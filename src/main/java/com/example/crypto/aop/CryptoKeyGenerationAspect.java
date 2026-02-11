
package com.example.crypto.aop;

import com.example.crypto.annotation.CryptoKeyGeneration;
import com.example.crypto.annotation.CryptoKeyGeneration.Encoding;
import com.example.crypto.annotation.CryptoKeyGeneration.OutputType;
import com.example.crypto.audit.AuditEvent;
import com.example.crypto.audit.AuditEventRepository;
import com.example.crypto.config.CryptoKeyGenProperties;
import com.example.crypto.exception.AccessDeniedException;
import com.example.crypto.exception.CryptoKeyGenException;
import com.example.crypto.exception.RateLimitExceededException;
import com.example.crypto.model.KeyMaterial;
import com.example.crypto.rate.RateLimiter;
import com.example.crypto.security.RoleChecker;
import com.example.crypto.util.Base64Url;
import com.example.crypto.util.MdcUtil;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

@Aspect
@Component
public class CryptoKeyGenerationAspect {
    private static final Logger log = LoggerFactory.getLogger(CryptoKeyGenerationAspect.class);

    private final CryptoKeyGenProperties props;
    private final AuditEventRepository auditRepo;
    private final RoleChecker roleChecker = new RoleChecker();
    private final RateLimiter rateLimiter = new RateLimiter();
    private final MeterRegistry meterRegistry;

    @Autowired
    public CryptoKeyGenerationAspect(CryptoKeyGenProperties props, AuditEventRepository auditRepo, MeterRegistry meterRegistry) {
        this.props = props;
        this.auditRepo = auditRepo;
        this.meterRegistry = meterRegistry;
    }

    @Around("@annotation(com.example.crypto.annotation.CryptoKeyGeneration)")
    public Object around(ProceedingJoinPoint pjp) throws Throwable {
        MethodSignature sig = (MethodSignature) pjp.getSignature();
        CryptoKeyGeneration ann = AnnotationUtils.findAnnotation(sig.getMethod(), CryptoKeyGeneration.class);
        Objects.requireNonNull(ann, "@CryptoKeyGeneration not found");

        HttpServletRequest request = currentRequest();
        String corr = MdcUtil.ensureCorrelationId(request != null ? request.getHeader(props.getCorrelationHeader()) : null);
        String principal = roleChecker.currentPrincipal();

        // Security & rate limiting
        if (ann.rolesAllowed().length > 0 && !roleChecker.hasAnyRole(ann.rolesAllowed())) {
            throw new AccessDeniedException("Access denied for principal " + principal);
        }
        String rateKey = principal + ":" + ann.purpose() + ":" + ann.algorithm();
        if (!rateLimiter.tryAcquire(rateKey, ann.rateLimitPerMinute())) {
            throw new RateLimitExceededException("Rate limit exceeded for " + principal);
        }

        String outcome = "SUCCESS";
        Timer.Sample sample = Timer.start(meterRegistry);
        try {
            KeyMaterial km = generate(ann);
            meterRegistry.counter("crypto.keygen.count", "purpose", ann.purpose(), "alg", ann.algorithm(), "outcome", outcome).increment();
            return km;
        } catch (Throwable t) {
            outcome = "FAILURE";
            meterRegistry.counter("crypto.keygen.count", "purpose", ann.purpose(), "alg", ann.algorithm(), "outcome", outcome).increment();
            log.error("Key generation failed: purpose={} alg={} corr={}", ann.purpose(), ann.algorithm(), corr, t);
            throw t;
        } finally {
            sample.stop(meterRegistry.timer("crypto.keygen.timer", "purpose", ann.purpose(), "alg", ann.algorithm(), "outcome", outcome));
            try {
                auditRepo.save(new AuditEvent(principal, ann.purpose(), ann.algorithm(), ann.output().name(), ann.encoding().name(), outcome));
            } catch (Exception e) {
                log.warn("Audit persistence failed", e);
            }
            MdcUtil.clear();
        }
    }

    private KeyMaterial generate(CryptoKeyGeneration ann) throws Exception {
        boolean fips = props.isFipsMode() && ann.fipsRequired();
        SecureRandom rng = ann.strongRng() ? SecureRandom.getInstanceStrong() : new SecureRandom();
        String alg = ann.algorithm();

        switch (ann.output()) {
            case SECRET:
                return generateSecret(alg, ann.keySize(), ann.encoding(), fips, rng);
            case BYTES:
                return generateBytes(ann.keySize(), ann.encoding(), rng);
            case KEYPAIR:
                return generateKeyPair(alg, ann.keySize(), ann.curve(), ann.encoding(), fips, rng, ann.exportPrivate());
            default:
                throw new CryptoKeyGenException("Unsupported output type");
        }
    }

    private KeyMaterial generateSecret(String alg, int keySize, Encoding enc, boolean fips, SecureRandom rng) throws Exception {
        if (alg.equalsIgnoreCase("AES")) {
            if (keySize < props.getMinAesKeySize()) {
                throw new CryptoKeyGenException("AES keySize below minimum");
            }
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(keySize, rng);
            SecretKey key = kg.generateKey();
            return encodeSecret("oct", alg, key.getEncoded(), keySize, enc);
        }
        if (alg.startsWith("HmacSHA")) {
            if (fips && !(alg.equals("HmacSHA256") || alg.equals("HmacSHA384") || alg.equals("HmacSHA512"))) {
                throw new CryptoKeyGenException("Non-FIPS HMAC algorithm: " + alg);
            }
            KeyGenerator kg = KeyGenerator.getInstance(alg);
            kg.init(Math.max(256, keySize), rng);
            SecretKey key = kg.generateKey();
            return encodeSecret("oct", alg, key.getEncoded(), keySize, enc);
        }
        throw new CryptoKeyGenException("Unsupported SECRET algorithm: " + alg);
    }

    private KeyMaterial generateBytes(int sizeBits, Encoding enc, SecureRandom rng) {
        int sizeBytes = Math.max(1, sizeBits / 8);
        byte[] bytes = new byte[sizeBytes];
        rng.nextBytes(bytes);
        KeyMaterial km = new KeyMaterial();
        km.setKid(UUID.randomUUID().toString());
        km.setAlgorithm("RANDOM");
        km.setKty("oct");
        km.setLength(sizeBits);
        km.setEncoding(enc.name());
        km.setSecret(encodeRaw(bytes, enc));
        return km;
    }

    private KeyMaterial generateKeyPair(String alg, int keySize, String curve, Encoding enc, boolean fips, SecureRandom rng, boolean exportPrivate) throws Exception {
        if (alg.equalsIgnoreCase("RSA")) {
            if (keySize < props.getMinRsaKeySize()) {
                throw new CryptoKeyGenException("RSA keySize below minimum");
            }
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize, rng);
            KeyPair kp = kpg.generateKeyPair();
            return encodeKeyPairRSA(kp, keySize, enc, exportPrivate);
        }
        if (alg.equalsIgnoreCase("EC")) {
            String crv = (curve == null || curve.isBlank()) ? "secp256r1" : curve; // P-256
            if (fips) {
                if (!(crv.equals("secp256r1") || crv.equals("secp384r1") || crv.equals("secp521r1"))) {
                    throw new CryptoKeyGenException("Non-FIPS curve: " + crv);
                }
            }
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec(crv), rng);
            KeyPair kp = kpg.generateKeyPair();
            return encodeKeyPairEC(kp, crv, enc, exportPrivate);
        }
        if (alg.equalsIgnoreCase("Ed25519")) {
            if (fips) {
                throw new CryptoKeyGenException("Ed25519 not allowed in FIPS mode");
            }
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            kpg.initialize(255, rng);
            KeyPair kp = kpg.generateKeyPair();
            return encodeKeyPairEd25519(kp, enc, exportPrivate);
        }
        throw new CryptoKeyGenException("Unsupported KEYPAIR algorithm: " + alg);
    }

    private KeyMaterial encodeSecret(String kty, String alg, byte[] key, int keySize, Encoding enc) {
        KeyMaterial km = new KeyMaterial();
        km.setKid(UUID.randomUUID().toString());
        km.setAlgorithm(alg);
        km.setKty(kty);
        km.setLength(keySize);
        km.setEncoding(enc.name());
        switch (enc) {
            case RAW_HEX -> km.setSecret(hex(key));
            case RAW_BASE64 -> km.setSecret(Base64.getEncoder().encodeToString(key));
            case JWK -> km.setSecret("{"kty":"oct","k":"" + Base64Url.encode(key) + ""}");
            case PEM -> km.setSecret(pem("SECRET KEY", key));
        }
        return km;
    }

    private KeyMaterial encodeKeyPairRSA(KeyPair kp, int keySize, Encoding enc, boolean exportPrivate) throws Exception {
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        RSAPrivateCrtKey priv = (RSAPrivateCrtKey) kp.getPrivate();
        KeyMaterial km = new KeyMaterial();
        km.setKid(UUID.randomUUID().toString());
        km.setAlgorithm("RSA");
        km.setKty("RSA");
        km.setLength(keySize);
        km.setEncoding(enc.name());
        switch (enc) {
            case PEM -> {
                km.setPublicKey(pem("PUBLIC KEY", pub.getEncoded()));
                if (exportPrivate) km.setPrivateKey(pem("PRIVATE KEY", priv.getEncoded()));
            }
            case JWK -> {
                Map<String, Object> jwk = new LinkedHashMap<>();
                jwk.put("kty", "RSA");
                jwk.put("n", Base64Url.encode(unsigned(pub.getModulus())));
                jwk.put("e", Base64Url.encode(unsigned(pub.getPublicExponent())));
                if (exportPrivate) {
                    jwk.put("d", Base64Url.encode(unsigned(priv.getPrivateExponent())));
                    jwk.put("p", Base64Url.encode(unsigned(priv.getPrimeP())));
                    jwk.put("q", Base64Url.encode(unsigned(priv.getPrimeQ())));
                    jwk.put("dp", Base64Url.encode(unsigned(priv.getPrimeExponentP())));
                    jwk.put("dq", Base64Url.encode(unsigned(priv.getPrimeExponentQ())));
                    jwk.put("qi", Base64Url.encode(unsigned(priv.getCrtCoefficient())));
                }
                km.setPublicKey(toJson(jwk));
            }
            default -> {
                km.setPublicKey(encodeRaw(pub.getEncoded(), enc));
                if (exportPrivate) km.setPrivateKey(encodeRaw(priv.getEncoded(), enc));
            }
        }
        return km;
    }

    private KeyMaterial encodeKeyPairEC(KeyPair kp, String crv, Encoding enc, boolean exportPrivate) throws Exception {
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
        KeyMaterial km = new KeyMaterial();
        km.setKid(UUID.randomUUID().toString());
        km.setAlgorithm("EC");
        km.setKty("EC");
        km.setLength(pub.getParams().getCurve().getField().getFieldSize());
        km.setEncoding(enc.name());
        switch (enc) {
            case PEM -> {
                km.setPublicKey(pem("PUBLIC KEY", pub.getEncoded()));
                if (exportPrivate) km.setPrivateKey(pem("PRIVATE KEY", priv.getEncoded()));
            }
            case JWK -> {
                // EC JWK (uncompressed point)
                byte[] x = unsigned(pub.getW().getAffineX());
                byte[] y = unsigned(pub.getW().getAffineY());
                Map<String, Object> jwk = new LinkedHashMap<>();
                jwk.put("kty", "EC");
                jwk.put("crv", mapCurveToJwk(crv));
                jwk.put("x", Base64Url.encode(x));
                jwk.put("y", Base64Url.encode(y));
                if (exportPrivate) jwk.put("d", Base64Url.encode(unsigned(priv.getS())));
                km.setPublicKey(toJson(jwk));
            }
            default -> {
                km.setPublicKey(encodeRaw(pub.getEncoded(), enc));
                if (exportPrivate) km.setPrivateKey(encodeRaw(priv.getEncoded(), enc));
            }
        }
        return km;
    }

    private KeyMaterial encodeKeyPairEd25519(KeyPair kp, Encoding enc, boolean exportPrivate) {
        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();
        KeyMaterial km = new KeyMaterial();
        km.setKid(UUID.randomUUID().toString());
        km.setAlgorithm("Ed25519");
        km.setKty("OKP");
        km.setLength(255);
        km.setEncoding(enc.name());
        switch (enc) {
            case PEM -> {
                km.setPublicKey(pem("PUBLIC KEY", pub.getEncoded()));
                if (exportPrivate) km.setPrivateKey(pem("PRIVATE KEY", priv.getEncoded()));
            }
            case JWK -> {
                Map<String, Object> jwk = new LinkedHashMap<>();
                jwk.put("kty", "OKP");
                jwk.put("crv", "Ed25519");
                jwk.put("x", Base64Url.encode(pub.getEncoded())); // simplification
                if (exportPrivate) jwk.put("d", Base64Url.encode(priv.getEncoded()));
                km.setPublicKey(toJson(jwk));
            }
            default -> {
                km.setPublicKey(encodeRaw(pub.getEncoded(), enc));
                if (exportPrivate) km.setPrivateKey(encodeRaw(priv.getEncoded(), enc));
            }
        }
        return km;
    }

    private String encodeRaw(byte[] bytes, Encoding enc) {
        return switch (enc) {
            case RAW_HEX -> hex(bytes);
            case RAW_BASE64 -> Base64.getEncoder().encodeToString(bytes);
            case PEM -> pem("KEY", bytes);
            case JWK -> "{"k":"" + Base64Url.encode(bytes) + ""}";
        };
    }

    private static String pem(String type, byte[] data) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'
'}).encodeToString(data);
        return "-----BEGIN " + type + "-----
" + b64 + "
-----END " + type + "-----
";
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static byte[] unsigned(BigInteger bi) {
        byte[] arr = bi.toByteArray();
        if (arr.length > 1 && arr[0] == 0) {
            return Arrays.copyOfRange(arr, 1, arr.length);
        }
        return arr;
    }

    private static String toJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(e.getKey()).append('"').append(':');
            Object v = e.getValue();
            if (v instanceof String) {
                sb.append('"').append(v).append('"');
            } else {
                sb.append(String.valueOf(v));
            }
        }
        sb.append('}');
        return sb.toString();
    }

    private static String mapCurveToJwk(String name) {
        return switch (name) {
            case "secp256r1", "P-256" -> "P-256";
            case "secp384r1", "P-384" -> "P-384";
            case "secp521r1", "P-521" -> "P-521";
            default -> name;
        };
    }

    private HttpServletRequest currentRequest() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            return attrs != null ? attrs.getRequest() : null;
        } catch (Exception e) {
            return null;
        }
    }
}

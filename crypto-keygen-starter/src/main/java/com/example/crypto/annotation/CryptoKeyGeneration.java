
package com.example.crypto.annotation;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CryptoKeyGeneration {
    enum OutputType { SECRET, KEYPAIR, BYTES }
    enum Encoding { RAW_BASE64, RAW_HEX, PEM, JWK }

    String purpose();                   // e.g., DATA_ENCRYPTION, SIGNING, TOKEN
    String algorithm();                 // AES, HmacSHA256, RSA, EC, Ed25519
    int keySize() default 256;          // bits (not used for EC)
    String curve() default "";          // secp256r1|secp384r1|secp521r1

    OutputType output() default OutputType.SECRET;
    Encoding encoding() default Encoding.JWK;

    boolean fipsRequired() default true;
    boolean strongRng() default true;   // SecureRandom.getInstanceStrong()
    boolean exportPrivate() default false;

    String[] rolesAllowed() default {"ROLE_ADMIN"};
    int rateLimitPerMinute() default 30; // per principal
}

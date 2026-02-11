
# Crypto Secure Key Generation Annotation (Spring Boot)

A high-quality, robust, production-ready **custom annotation** for cryptographically secure random **key generation** in Spring Boot 3 (Java 17). The `@CryptoKeyGeneration` annotation centralizes **strong randomness (DRBG), FIPS-aware algorithm controls, allowed key sizes, export policies, auditing, metrics, and rate limiting** behind a clean AOP layer.

> ⚠️ Demo uses H2 and in-memory limits. Replace with your enterprise stores & policies for production.

## Features
- **Single annotation:** `@CryptoKeyGeneration` with attributes for algorithm, key size/curve, encoding (PEM/JWK/HEX/Base64), export policy, FIPS-only, and roles.
- **Secure RNG:** Uses `SecureRandom.getInstanceStrong()` by default; configurable.
- **Algorithms supported:** AES (SECRET), HmacSHA256/384/512 (SECRET), RSA (KEYPAIR), EC P-256/P-384/P-521 (KEYPAIR). Ed25519 optional (non-FIPS).
- **FIPS-aware controls:** Rejects non-approved algorithms when `fipsRequired=true`.
- **Output formats:** RAW (Base64/Hex), **PEM**, or **JWK** (oct/RSA/EC) with Base64URL encoding.
- **Access control & rate limiting:** Role checks and per-principal operation rate limits.
- **Auditing & metrics:** Persists audit records (masked), Micrometer timers/counters.
- **Correlation ID:** Propagated via MDC (`X-Correlation-Id`).

## Quickstart
```bash
mvn spring-boot:run
```

### Try AES key (256-bit)
```bash
curl -u user:password -X POST   "http://localhost:8080/api/keys/aes?size=256&encoding=JWK"
```

### Try RSA keypair (3072-bit)
```bash
curl -u admin:password -X POST   "http://localhost:8080/api/keys/rsa?size=3072&encoding=PEM"
```

## Configuration
`application.yml` exposes `crypto.keygen.*` toggles (FIPS mode, min sizes).

## Production Notes
- Back audit repository with your RDBMS.
- Enforce enterprise key policies via `CryptoKeyGenProperties`.
- Replace in-memory rate limiter with Redis or API gateway quota.
- Consider storing private keys in HSM/KMS; return only wrapped/handles.

## License
MIT

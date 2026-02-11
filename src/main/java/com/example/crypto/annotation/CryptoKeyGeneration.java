
package com.example.crypto.annotation;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CryptoKeyGeneration {
    enum OutputType { SECRET, KEYPAIR, BYTES }
    enum Encoding { RAW_BASE64, RAW_HEX, PEM, JWK }

    // Purpose label for audit/metrics (e.g., DATA_ENCRYPTION, SIGNING, TOKEN)
    String purpose();

    // Algorithm name (e.g., AES, HmacSHA256, RSA, EC, Ed25519)
    String algorithm();

    // Key size in bits (RSA/AES/HMAC). For EC set curve instead.
    int keySize() default 256;

    // Named curve for EC (e.g., secp256r1, secp384r1, secp521r1)
    String curve() default "";

    // Output material type
    OutputType output() default OutputType.SECRET;

    // Output encoding format
    Encoding encoding() default Encoding.JWK;

    // Require only FIPS-approved algorithms
    boolean fipsRequired() default true;

    // Use SecureRandom.getInstanceStrong()
    boolean strongRng() default true;

    // Whether private material may be returned to caller
    boolean exportPrivate() default false;

    // Roles allowed to invoke
    String[] rolesAllowed() default {"ROLE_ADMIN"};

    // Rate limit per minute per principal
    int rateLimitPerMinute() default 30;
}

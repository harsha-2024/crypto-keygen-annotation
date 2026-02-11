
package com.example.crypto.hsm;

import java.util.Map;

public interface KeyProtector {
    /** Wrap or store private key material and return a handle or wrapped blob */
    ProtectedKey protect(byte[] pkcs8PrivateKey, Map<String,Object> context);
}

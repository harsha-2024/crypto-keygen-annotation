
package com.example.crypto.hsm;

import java.util.Base64;
import java.util.Map;

/** Default fallback that base64-encodes PKCS#8 for demo only (NOT for production). */
public class NoopProtector implements KeyProtector {
    @Override
    public ProtectedKey protect(byte[] pkcs8PrivateKey, Map<String, Object> context) {
        return new ProtectedKey("INLINE", Base64.getEncoder().encodeToString(pkcs8PrivateKey));
    }
}

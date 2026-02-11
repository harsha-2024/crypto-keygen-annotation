
package com.example.crypto.hsm;

public class ProtectedKey {
    private final String type; // e.g., KMS_WRAPPED, KEY_VAULT, INLINE
    private final String value; // handle or wrapped blob (Base64)
    public ProtectedKey(String type, String value) { this.type = type; this.value = value; }
    public String getType() { return type; }
    public String getValue() { return value; }
}

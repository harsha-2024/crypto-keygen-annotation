
package com.example.crypto.policy;

import com.example.crypto.annotation.CryptoKeyGeneration;

public interface PolicyEngine {
    void validate(CryptoKeyGeneration ann);
}

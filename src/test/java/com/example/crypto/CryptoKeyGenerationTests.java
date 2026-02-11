
package com.example.crypto;

import com.example.crypto.demo.KeyService;
import com.example.crypto.model.KeyMaterial;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class CryptoKeyGenerationTests {

    @Autowired
    KeyService service;

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    void aes256_ok_for_user() {
        KeyMaterial km = service.generateAes256();
        assertEquals("AES", km.getAlgorithm());
        assertNotNull(km.getSecret());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void rsa3072_ok_for_admin() {
        KeyMaterial km = service.generateRsa3072();
        assertEquals("RSA", km.getAlgorithm());
        assertNotNull(km.getPublicKey());
        assertNotNull(km.getPrivateKey());
    }
}

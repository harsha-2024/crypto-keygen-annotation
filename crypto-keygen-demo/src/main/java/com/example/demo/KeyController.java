
package com.example.demo;

import com.example.crypto.model.KeyMaterial;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/keys")
@Tag(name = "Key Generation", description = "Crypto-secure key generation APIs")
public class KeyController {
    private final KeyService service;
    public KeyController(KeyService service) { this.service = service; }

    @PostMapping("/aes")
    @Operation(summary = "Generate AES key (256-bit)")
    public KeyMaterial aes() { return service.generateAes256(); }

    @PostMapping("/rsa")
    @Operation(summary = "Generate RSA keypair (3072-bit)")
    public KeyMaterial rsa() { return service.generateRsa3072(); }

    @PostMapping("/ec")
    @Operation(summary = "Generate EC keypair (P-256)")
    public KeyMaterial ec() { return service.generateEcP256(); }
}

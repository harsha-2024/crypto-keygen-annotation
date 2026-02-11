
package com.example.crypto.demo;

import com.example.crypto.model.KeyMaterial;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/keys")
public class KeyController {
    private final KeyService service;
    public KeyController(KeyService service) { this.service = service; }

    @PostMapping("/aes")
    public KeyMaterial aes(@RequestParam(defaultValue = "256") int size, @RequestParam(defaultValue = "JWK") String encoding) {
        // for demo: route to predefined method; size/encoding arguments shown but not used
        return service.generateAes256();
    }

    @PostMapping("/rsa")
    public KeyMaterial rsa(@RequestParam(defaultValue = "3072") int size, @RequestParam(defaultValue = "PEM") String encoding) {
        return service.generateRsa3072();
    }

    @PostMapping("/ec")
    public KeyMaterial ec() {
        return service.generateEcP256();
    }
}

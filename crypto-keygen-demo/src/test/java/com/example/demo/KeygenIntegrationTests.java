
package com.example.demo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class KeygenIntegrationTests {

    @Container
    static GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("spring.data.redis.host", () -> redis.getHost());
        r.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
    }

    @Autowired
    TestRestTemplate rest;

    @Test
    void aes_ok_then_rate_limited() {
        // first 3 calls OK
        for (int i=0;i<3;i++) {
            ResponseEntity<Map> res = rest.withBasicAuth("user","password").postForEntity("/api/keys/aes", null, Map.class);
            assertEquals(HttpStatus.OK, res.getStatusCode());
        }
        // set low limit via header simulation (not exposed) -> here we just call many times
        ResponseEntity<Map> res = null;
        for (int i=0;i<40;i++) {
            res = rest.withBasicAuth("user","password").postForEntity("/api/keys/aes", null, Map.class);
            if (res.getStatusCode().value() == 429) break;
        }
        assertNotNull(res);
        assertEquals(429, res.getStatusCode().value());
    }
}


package com.example.demo;

import com.example.crypto.exception.RateLimitExceededException;
import com.example.crypto.exception.AccessDeniedException;
import com.example.crypto.exception.CryptoKeyGenException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.Map;

@ControllerAdvice
public class RestExceptionHandler {
    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<?> rateLimit(RateLimitExceededException ex) {
        return ResponseEntity.status(429).body(Map.of("error","rate_limited","message", ex.getMessage()));
    }
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> denied(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error","access_denied","message", ex.getMessage()));
    }
    @ExceptionHandler(CryptoKeyGenException.class)
    public ResponseEntity<?> bad(CryptoKeyGenException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error","policy_violation","message", ex.getMessage()));
    }
}

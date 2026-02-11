
package com.example.crypto.exception;

public class RateLimitExceededException extends CryptoKeyGenException {
    public RateLimitExceededException(String message) { super(message); }
}


package com.example.crypto.exception;

public class CryptoKeyGenException extends RuntimeException {
    public CryptoKeyGenException(String message) { super(message); }
    public CryptoKeyGenException(String message, Throwable cause) { super(message, cause); }
}

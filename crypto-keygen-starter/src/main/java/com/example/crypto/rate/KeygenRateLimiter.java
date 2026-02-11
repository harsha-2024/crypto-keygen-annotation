
package com.example.crypto.rate;

public interface KeygenRateLimiter {
    boolean tryAcquire(String principalOpKey, int limitPerMinute);
}

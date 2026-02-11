
package com.example.crypto.rate;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryRateLimiter implements KeygenRateLimiter {
    private static class Window { int count; long windowStart; }
    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    @Override
    public boolean tryAcquire(String key, int limitPerMinute) {
        long now = Instant.now().getEpochSecond();
        long current = now / 60;
        Window w = windows.computeIfAbsent(key, k -> new Window());
        synchronized (w) {
            if (w.windowStart != current) { w.windowStart = current; w.count = 0; }
            if (w.count >= limitPerMinute) return false;
            w.count++; return true;
        }
    }
}

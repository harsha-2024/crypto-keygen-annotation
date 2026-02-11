
package com.example.crypto.rate;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.util.Collections;

public class RedisRateLimiter implements KeygenRateLimiter {
    private static final String LUA = "" +
            "local key = KEYS[1]
" +
            "local limit = tonumber(ARGV[1])
" +
            "local ttl = 60
" +
            "local count = redis.call('INCR', key)
" +
            "if count == 1 then redis.call('EXPIRE', key, ttl) end
" +
            "if count > limit then return 0 else return 1 end";

    private final StringRedisTemplate redis;
    private final DefaultRedisScript<Long> script;

    public RedisRateLimiter(StringRedisTemplate redis) {
        this.redis = redis;
        this.script = new DefaultRedisScript<>(LUA, Long.class);
    }

    @Override
    public boolean tryAcquire(String principalOpKey, int limitPerMinute) {
        Long res = redis.execute(script, Collections.singletonList("rl:" + principalOpKey), String.valueOf(limitPerMinute));
        return res != null && res == 1L;
    }
}


package com.example.crypto.autoconfig;

import com.example.crypto.aop.CryptoKeyGenerationAspect;
import com.example.crypto.config.CryptoKeyGenProperties;
import com.example.crypto.hsm.KeyProtector;
import com.example.crypto.hsm.NoopProtector;
import com.example.crypto.hsm.aws.AwsKmsKeyProtector;
import com.example.crypto.hsm.azure.AzureKeyVaultProtector;
import com.example.crypto.policy.DefaultPolicyEngine;
import com.example.crypto.policy.PolicyEngine;
import com.example.crypto.rate.InMemoryRateLimiter;
import com.example.crypto.rate.KeygenRateLimiter;
import com.example.crypto.rate.RedisRateLimiter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;
import software.amazon.awssdk.services.kms.KmsClient;

@AutoConfiguration
@EnableConfigurationProperties(CryptoKeyGenProperties.class)
public class CryptoKeyGenAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PolicyEngine policyEngine(CryptoKeyGenProperties props) {
        return new DefaultPolicyEngine(props);
    }

    @Bean
    @ConditionalOnMissingBean(KeygenRateLimiter.class)
    @ConditionalOnProperty(prefix = "crypto.keygen", name = "prefer-redis-rate-limiter", havingValue = "true", matchIfMissing = true)
    @ConditionalOnClass(StringRedisTemplate.class)
    public KeygenRateLimiter redisRateLimiter(StringRedisTemplate template) {
        return new RedisRateLimiter(template);
    }

    @Bean
    @ConditionalOnMissingBean(KeygenRateLimiter.class)
    public KeygenRateLimiter inMemoryRateLimiter() { return new InMemoryRateLimiter(); }

    @Bean
    @ConditionalOnMissingBean(KeyProtector.class)
    @ConditionalOnClass(KmsClient.class)
    @ConditionalOnProperty(prefix = "crypto.keygen.kms", name = "key-id")
    public KeyProtector awsKmsProtector(KmsClient kms, CryptoKeyGenProperties props, org.springframework.core.env.Environment env) {
        String keyId = env.getProperty("crypto.keygen.kms.key-id");
        return new AwsKmsKeyProtector(kms, keyId);
    }

    @Bean
    @ConditionalOnMissingBean(KeyProtector.class)
    @ConditionalOnClass(com.azure.security.keyvault.keys.cryptography.CryptographyClient.class)
    @ConditionalOnProperty(prefix = "crypto.keygen.keyvault", name = "key-id")
    public KeyProtector azureKeyVaultProtector(org.springframework.core.env.Environment env) {
        String keyId = env.getProperty("crypto.keygen.keyvault.key-id");
        return new AzureKeyVaultProtector(keyId);
    }

    @Bean
    @ConditionalOnMissingBean(KeyProtector.class)
    public KeyProtector noopProtector() { return new NoopProtector(); }

    @Bean
    public CryptoKeyGenerationAspect cryptoKeyGenerationAspect(CryptoKeyGenProperties props, MeterRegistry meterRegistry, KeygenRateLimiter limiter, PolicyEngine policy, KeyProtector protector) {
        return new CryptoKeyGenerationAspect(props, meterRegistry, limiter, policy, protector);
    }
}

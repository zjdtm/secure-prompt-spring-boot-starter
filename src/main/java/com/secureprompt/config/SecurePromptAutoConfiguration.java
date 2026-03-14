package com.secureprompt.config;

import com.secureprompt.aop.PromptValidationInterceptor;
import com.secureprompt.domain.AttackPattern;
import com.secureprompt.engine.PatternMatchingEngine;
import com.secureprompt.engine.RiskScoreCalculator;
import com.secureprompt.repository.InMemoryPatternRepository;
import com.secureprompt.repository.PatternRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

import java.util.List;

/**
 * Spring Boot Auto-configuration for SecurePrompt.
 *
 * <p>Automatically activated when:
 * <ul>
 *   <li>{@code @EnableSecurePrompt} is present on the application class, OR</li>
 *   <li>{@code secure-prompt.enabled=true} is set in {@code application.yml}</li>
 * </ul>
 *
 * <p>All beans use {@code @ConditionalOnMissingBean} so users can override
 * any component with their own implementation.
 */
@AutoConfiguration
@EnableAspectJAutoProxy
@EnableConfigurationProperties(SecurePromptProperties.class)
@ConditionalOnProperty(
        prefix = "secure-prompt",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class SecurePromptAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SecurePromptAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public PatternRepository patternRepository(SecurePromptProperties properties) {
        InMemoryPatternRepository repository = new InMemoryPatternRepository();

        // Register custom patterns from configuration
        List<SecurePromptProperties.CustomPattern> customPatterns = properties.getCustomPatterns();
        if (customPatterns != null && !customPatterns.isEmpty()) {
            for (SecurePromptProperties.CustomPattern cp : customPatterns) {
                AttackPattern custom = AttackPattern.builder()
                        .name(cp.getName())
                        .regex(cp.getRegex())
                        .severity(cp.getSeverity())
                        .active(true)
                        .build();
                repository.save(custom);
                log.info("[SecurePrompt] Custom pattern registered: {}", cp.getName());
            }
        }

        long count = repository.count();
        log.info("[SecurePrompt] Initialized with {} attack patterns (in-memory)", count);
        return repository;
    }

    @Bean
    @ConditionalOnMissingBean
    public PatternMatchingEngine patternMatchingEngine(PatternRepository patternRepository) {
        return new PatternMatchingEngine(patternRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskScoreCalculator riskScoreCalculator() {
        return new RiskScoreCalculator();
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptValidationInterceptor promptValidationInterceptor(
            PatternMatchingEngine patternMatchingEngine,
            RiskScoreCalculator riskScoreCalculator,
            SecurePromptProperties properties) {
        log.info("[SecurePrompt] AOP interceptor registered | threshold={}, blockMode={}",
                properties.getThreshold(), properties.isBlockMode());
        return new PromptValidationInterceptor(patternMatchingEngine, riskScoreCalculator, properties);
    }
}

package com.secureprompt.config;

import com.secureprompt.domain.Severity;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for SecurePrompt.
 *
 * <p>Example {@code application.yml} configuration:
 * <pre>{@code
 * secure-prompt:
 *   enabled: true
 *   threshold: 70
 *   block-mode: true
 *   log-blocked-prompts: false
 *   custom-patterns:
 *     - name: my_pattern
 *       regex: "reveal\\s+secrets?"
 *       severity: HIGH
 *   excluded-endpoints:
 *     - /api/public/**
 *     - /health
 * }</pre>
 */
@Data
@ConfigurationProperties(prefix = "secure-prompt")
public class SecurePromptProperties {

    /** Enable or disable SecurePrompt entirely. Default: true */
    private boolean enabled = true;

    /**
     * Risk score threshold (0-100).
     * Prompts with score >= threshold will be treated as attacks.
     * Default: 70 (recommended for production).
     * Strict: 50, Loose: 90.
     */
    private int threshold = 70;

    /**
     * Block mode.
     * true  = throw {@code PromptInjectionException} when attack detected (default).
     * false = log only, do not block.
     */
    private boolean blockMode = true;

    /**
     * Whether to log the hashed prompt content when blocked.
     * Default: false (for privacy).
     */
    private boolean logBlockedPrompts = false;

    /** Additional user-defined patterns */
    private List<CustomPattern> customPatterns = new ArrayList<>();

    /** Endpoints excluded from validation (Ant-style patterns) */
    private List<String> excludedEndpoints = new ArrayList<>();

    /** Optional rate limiting configuration */
    private RateLimitConfig rateLimit = new RateLimitConfig();

    @Data
    public static class CustomPattern {
        private String name;
        private String regex;
        private Severity severity;
    }

    @Data
    public static class RateLimitConfig {
        private boolean enabled = false;
        private int maxRequests = 100;
        private Duration window = Duration.ofMinutes(1);
    }
}

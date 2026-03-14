package com.secureprompt.aop;

import com.secureprompt.annotation.SecurePrompt;
import com.secureprompt.config.SecurePromptProperties;
import com.secureprompt.domain.MatchedPattern;
import com.secureprompt.engine.PatternMatchingEngine;
import com.secureprompt.engine.RiskScoreCalculator;
import com.secureprompt.exception.PromptInjectionException;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.List;
import java.util.stream.Collectors;

/**
 * AOP interceptor that validates prompts on methods annotated with {@link SecurePrompt}.
 *
 * <p>Intercept flow:
 * <ol>
 *   <li>Extract String parameters from the method</li>
 *   <li>Run pattern matching</li>
 *   <li>Calculate risk score</li>
 *   <li>If score >= threshold → throw {@link PromptInjectionException} (if block-mode=true)</li>
 *   <li>Log detection events</li>
 * </ol>
 */
@Aspect
@Component
public class PromptValidationInterceptor {

    private static final Logger log = LoggerFactory.getLogger(PromptValidationInterceptor.class);

    private final PatternMatchingEngine patternMatcher;
    private final RiskScoreCalculator scoreCalculator;
    private final SecurePromptProperties properties;

    public PromptValidationInterceptor(
            PatternMatchingEngine patternMatcher,
            RiskScoreCalculator scoreCalculator,
            SecurePromptProperties properties) {
        this.patternMatcher = patternMatcher;
        this.scoreCalculator = scoreCalculator;
        this.properties = properties;
    }

    @Around("@annotation(com.secureprompt.annotation.SecurePrompt) || " +
            "@within(com.secureprompt.annotation.SecurePrompt)")
    public Object validatePrompt(ProceedingJoinPoint joinPoint) throws Throwable {
        String prompt = extractPrompt(joinPoint);

        if (prompt == null || prompt.isBlank()) {
            return joinPoint.proceed();
        }

        long startTime = System.nanoTime();

        // Pattern matching
        List<MatchedPattern> matches = patternMatcher.match(prompt);

        // Risk score calculation
        int riskScore = scoreCalculator.calculate(matches);

        // Determine effective threshold (method-level overrides global)
        int effectiveThreshold = resolveThreshold(joinPoint);

        // Logging
        logDetection(joinPoint, matches, riskScore, effectiveThreshold);

        // Enforcement
        if (riskScore >= effectiveThreshold) {
            boolean shouldBlock = resolveBlockMode(joinPoint);
            if (shouldBlock) {
                throw new PromptInjectionException(
                        "Prompt injection detected",
                        matches,
                        riskScore
                );
            } else {
                log.error("[SecurePrompt] Injection detected but NOT blocked (block-mode=false): score={}", riskScore);
            }
        }

        long durationNanos = System.nanoTime() - startTime;
        log.debug("[SecurePrompt] Validation completed in {}ms, score={}, matches={}",
                String.format("%.3f", durationNanos / 1_000_000.0), riskScore, matches.size());

        return joinPoint.proceed();
    }

    private String extractPrompt(ProceedingJoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();
        if (args == null) return null;

        for (Object arg : args) {
            if (arg instanceof String s && !s.isBlank()) {
                return s;
            }
        }
        return null;
    }

    private int resolveThreshold(ProceedingJoinPoint joinPoint) {
        SecurePrompt annotation = getAnnotation(joinPoint);
        if (annotation != null && annotation.threshold() >= 0) {
            return annotation.threshold();
        }
        return properties.getThreshold();
    }

    private boolean resolveBlockMode(ProceedingJoinPoint joinPoint) {
        SecurePrompt annotation = getAnnotation(joinPoint);
        if (annotation != null && !annotation.blockMode().isBlank()) {
            return Boolean.parseBoolean(annotation.blockMode());
        }
        return properties.isBlockMode();
    }

    private SecurePrompt getAnnotation(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Check method-level annotation first
        SecurePrompt methodAnnotation = method.getAnnotation(SecurePrompt.class);
        if (methodAnnotation != null) {
            return methodAnnotation;
        }

        // Fall back to class-level annotation
        return joinPoint.getTarget().getClass().getAnnotation(SecurePrompt.class);
    }

    private void logDetection(ProceedingJoinPoint joinPoint,
                               List<MatchedPattern> matches,
                               int riskScore,
                               int threshold) {
        if (matches.isEmpty()) {
            log.debug("[SecurePrompt] No threats detected in {}.{}",
                    joinPoint.getTarget().getClass().getSimpleName(),
                    joinPoint.getSignature().getName());
            return;
        }

        String patternNames = matches.stream()
                .map(MatchedPattern::getName)
                .collect(Collectors.joining(", "));

        String method = joinPoint.getTarget().getClass().getSimpleName()
                + "." + joinPoint.getSignature().getName();

        if (riskScore >= threshold) {
            log.error("[SecurePrompt] BLOCKED - method={}, score={}/{}, patterns=[{}]",
                    method, riskScore, threshold, patternNames);
        } else {
            log.warn("[SecurePrompt] SUSPICIOUS - method={}, score={}/{}, patterns=[{}]",
                    method, riskScore, threshold, patternNames);
        }
    }
}

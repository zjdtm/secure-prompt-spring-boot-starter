package com.secureprompt.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a method (or class) for prompt injection validation.
 *
 * <p>When a method is annotated with {@code @SecurePrompt}, all {@link String}
 * parameters will be validated against known prompt injection patterns before
 * the method executes.
 *
 * <p>Usage:
 * <pre>{@code
 * @SecurePrompt
 * public String chat(String userPrompt) {
 *     return llmService.call(userPrompt); // safe: injection already checked
 * }
 * }</pre>
 *
 * <p>Per-method threshold override:
 * <pre>{@code
 * @SecurePrompt(threshold = 50) // stricter for this endpoint
 * public String sensitiveChat(String prompt) { ... }
 * }</pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SecurePrompt {

    /**
     * Custom risk score threshold for this method.
     * -1 means use the global setting from {@code application.yml}.
     */
    int threshold() default -1;

    /**
     * Override block mode for this method.
     * Empty string means use the global setting.
     */
    String blockMode() default "";
}

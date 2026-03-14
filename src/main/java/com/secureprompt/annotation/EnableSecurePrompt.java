package com.secureprompt.annotation;

import com.secureprompt.config.SecurePromptAutoConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Enables SecurePrompt auto-configuration in a Spring Boot application.
 *
 * <p>Add this annotation to your main application class:
 * <pre>{@code
 * @SpringBootApplication
 * @EnableSecurePrompt
 * public class MyApplication {
 *     public static void main(String[] args) {
 *         SpringApplication.run(MyApplication.class, args);
 *     }
 * }
 * }</pre>
 *
 * <p>Once enabled, all methods annotated with {@link SecurePrompt} will be
 * automatically intercepted and validated against known prompt injection patterns.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(SecurePromptAutoConfiguration.class)
public @interface EnableSecurePrompt {

    /**
     * Whether to intercept ALL methods globally (not just those with @SecurePrompt).
     * Default: false.
     */
    boolean global() default false;
}

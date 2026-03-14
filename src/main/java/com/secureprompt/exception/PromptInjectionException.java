package com.secureprompt.exception;

import com.secureprompt.domain.MatchedPattern;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Exception thrown when a prompt injection attack is detected and the block mode is enabled.
 *
 * <p>This is a {@link RuntimeException} that can be caught by a
 * {@code @ControllerAdvice} global exception handler to return HTTP 403 Forbidden.
 *
 * <p>Usage example:
 * <pre>{@code
 * @ExceptionHandler(PromptInjectionException.class)
 * public ResponseEntity<ErrorResponse> handle(PromptInjectionException ex) {
 *     return ResponseEntity.status(HttpStatus.FORBIDDEN)
 *         .body(new ErrorResponse("Prompt injection detected", ex.getRiskScore()));
 * }
 * }</pre>
 */
public class PromptInjectionException extends RuntimeException {

    private final List<MatchedPattern> matchedPatterns;
    private final int riskScore;
    private final LocalDateTime detectedAt;

    public PromptInjectionException(
            String message,
            List<MatchedPattern> matchedPatterns,
            int riskScore) {
        super(message);
        this.matchedPatterns = matchedPatterns;
        this.riskScore = riskScore;
        this.detectedAt = LocalDateTime.now();
    }

    public List<MatchedPattern> getMatchedPatterns() {
        return matchedPatterns;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public LocalDateTime getDetectedAt() {
        return detectedAt;
    }
}

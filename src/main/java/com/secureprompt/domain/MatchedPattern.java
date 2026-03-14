package com.secureprompt.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Represents a pattern that was matched in the user's prompt.
 * Used to calculate risk score and generate logs.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MatchedPattern {

    /** Name of the matched attack pattern */
    private String name;

    /** Severity level of the matched pattern */
    private Severity severity;

    /**
     * Confidence score of the match (0.0 - 1.0).
     * 1.0 = exact match, 0.5 = weak match
     */
    private double confidence;

    /** The actual text that was matched */
    private String matchedText;

    /**
     * Calculates the weighted risk score for this pattern.
     * Formula: baseSeverityScore * confidence
     */
    public int getWeightedScore() {
        int baseSeverity = switch (severity) {
            case CRITICAL -> 100;
            case HIGH -> 70;
            case MEDIUM -> 40;
            case LOW -> 20;
        };
        return (int) (baseSeverity * confidence);
    }
}

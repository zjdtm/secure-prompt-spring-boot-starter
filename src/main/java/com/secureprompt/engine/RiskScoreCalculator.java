package com.secureprompt.engine;

import com.secureprompt.domain.MatchedPattern;
import com.secureprompt.domain.Severity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Calculates the total risk score from a list of matched patterns.
 *
 * <p>Formula: {@code score = min(100, sum(severityScore * confidence))}
 *
 * <p>Severity weights:
 * <ul>
 *   <li>CRITICAL: 100</li>
 *   <li>HIGH: 70</li>
 *   <li>MEDIUM: 40</li>
 *   <li>LOW: 20</li>
 * </ul>
 */
@Component
public class RiskScoreCalculator {

    private static final Map<Severity, Integer> SEVERITY_SCORES = Map.of(
            Severity.CRITICAL, 100,
            Severity.HIGH, 70,
            Severity.MEDIUM, 40,
            Severity.LOW, 20
    );

    /**
     * Calculates the total risk score for a set of matched patterns.
     *
     * @param matches List of matched patterns
     * @return Risk score in range [0, 100]
     */
    public int calculate(List<MatchedPattern> matches) {
        if (matches == null || matches.isEmpty()) {
            return 0;
        }

        double totalScore = matches.stream()
                .mapToDouble(this::calculatePatternScore)
                .sum();

        return (int) Math.min(100, totalScore);
    }

    /**
     * Returns the severity level that corresponds to a given numeric score.
     *
     * @param score Risk score (0-100)
     * @return Corresponding severity level
     */
    public Severity getSeverityLevel(int score) {
        if (score >= 90) return Severity.CRITICAL;
        if (score >= 70) return Severity.HIGH;
        if (score >= 40) return Severity.MEDIUM;
        return Severity.LOW;
    }

    private double calculatePatternScore(MatchedPattern match) {
        int baseSeverity = SEVERITY_SCORES.getOrDefault(match.getSeverity(), 20);
        return baseSeverity * match.getConfidence();
    }
}

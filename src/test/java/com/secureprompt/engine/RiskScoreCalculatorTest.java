package com.secureprompt.engine;

import com.secureprompt.domain.MatchedPattern;
import com.secureprompt.domain.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("RiskScoreCalculator")
class RiskScoreCalculatorTest {

    private RiskScoreCalculator calculator;

    @BeforeEach
    void setUp() {
        calculator = new RiskScoreCalculator();
    }

    @Test
    @DisplayName("Empty matches should return score 0")
    void emptyMatchesShouldReturnZero() {
        assertThat(calculator.calculate(List.of())).isEqualTo(0);
        assertThat(calculator.calculate(null)).isEqualTo(0);
    }

    @Test
    @DisplayName("Single CRITICAL pattern with confidence 1.0 should return 100")
    void singleCriticalPatternFullConfidenceShouldReturn100() {
        List<MatchedPattern> matches = List.of(
                MatchedPattern.builder()
                        .name("test")
                        .severity(Severity.CRITICAL)
                        .confidence(1.0)
                        .build()
        );

        assertThat(calculator.calculate(matches)).isEqualTo(100);
    }

    @Test
    @DisplayName("Single HIGH pattern with confidence 1.0 should return 70")
    void singleHighPatternShouldReturn70() {
        List<MatchedPattern> matches = List.of(
                MatchedPattern.builder()
                        .name("test")
                        .severity(Severity.HIGH)
                        .confidence(1.0)
                        .build()
        );

        assertThat(calculator.calculate(matches)).isEqualTo(70);
    }

    @Test
    @DisplayName("Multiple patterns should be capped at 100")
    void multiplePatternsShouldBeCappedAt100() {
        List<MatchedPattern> matches = List.of(
                MatchedPattern.builder().name("p1").severity(Severity.CRITICAL).confidence(1.0).build(),
                MatchedPattern.builder().name("p2").severity(Severity.HIGH).confidence(1.0).build()
        );

        assertThat(calculator.calculate(matches)).isEqualTo(100);
    }

    @Test
    @DisplayName("MEDIUM pattern with 0.5 confidence should return 20")
    void mediumPatternHalfConfidenceShouldReturn20() {
        List<MatchedPattern> matches = List.of(
                MatchedPattern.builder()
                        .name("test")
                        .severity(Severity.MEDIUM)
                        .confidence(0.5)
                        .build()
        );

        assertThat(calculator.calculate(matches)).isEqualTo(20);
    }

    @Test
    @DisplayName("getSeverityLevel should return correct level")
    void getSeverityLevelShouldReturnCorrectLevel() {
        assertThat(calculator.getSeverityLevel(95)).isEqualTo(Severity.CRITICAL);
        assertThat(calculator.getSeverityLevel(70)).isEqualTo(Severity.HIGH);
        assertThat(calculator.getSeverityLevel(50)).isEqualTo(Severity.MEDIUM);
        assertThat(calculator.getSeverityLevel(10)).isEqualTo(Severity.LOW);
    }
}

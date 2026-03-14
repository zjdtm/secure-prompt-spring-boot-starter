package com.secureprompt.domain;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Result of a single pattern matching operation.
 */
@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class MatchResult {

    private final boolean matched;
    private final double confidence;
    private final String matchedText;

    public static MatchResult matched(double confidence, String matchedText) {
        return new MatchResult(true, confidence, matchedText);
    }

    public static MatchResult notMatched() {
        return new MatchResult(false, 0.0, null);
    }
}

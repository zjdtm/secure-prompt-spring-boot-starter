package com.secureprompt.engine;

import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.secureprompt.domain.AttackPattern;
import com.secureprompt.domain.MatchResult;
import com.secureprompt.domain.MatchedPattern;
import com.secureprompt.repository.PatternRepository;
import com.secureprompt.util.PromptNormalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Core engine that matches user prompts against known attack patterns.
 *
 * <p>Performance optimizations:
 * <ul>
 *   <li>Compiled regex patterns are cached using Caffeine (up to 1000 patterns)</li>
 *   <li>Normalization is applied before matching</li>
 *   <li>Case-insensitive and DOTALL matching by default</li>
 * </ul>
 */
@Component
public class PatternMatchingEngine {

    private static final Logger log = LoggerFactory.getLogger(PatternMatchingEngine.class);

    private final PatternRepository patternRepository;
    private final PromptNormalizer normalizer;
    private final LoadingCache<String, Pattern> compiledPatterns;

    public PatternMatchingEngine(PatternRepository patternRepository) {
        this.patternRepository = patternRepository;
        this.normalizer = new PromptNormalizer();
        this.compiledPatterns = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(1, TimeUnit.HOURS)
                .build(regex -> Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL));
    }

    /**
     * Matches the given prompt against all active attack patterns.
     *
     * @param prompt Raw user input
     * @return List of matched patterns (empty if none detected)
     */
    public List<MatchedPattern> match(String prompt) {
        if (prompt == null || prompt.isBlank()) {
            return List.of();
        }

        String normalized = normalizer.normalize(prompt);
        List<AttackPattern> patterns = patternRepository.findAll();
        List<MatchedPattern> matches = new ArrayList<>();

        for (AttackPattern pattern : patterns) {
            MatchResult result = matchPattern(normalized, pattern);
            if (result.isMatched()) {
                matches.add(MatchedPattern.builder()
                        .name(pattern.getName())
                        .severity(pattern.getSeverity())
                        .confidence(result.getConfidence())
                        .matchedText(result.getMatchedText())
                        .build());
            }
        }

        return matches;
    }

    private MatchResult matchPattern(String input, AttackPattern pattern) {
        try {
            Pattern compiled = compiledPatterns.get(pattern.getRegex());
            if (compiled == null) {
                return MatchResult.notMatched();
            }

            Matcher matcher = compiled.matcher(input);
            if (matcher.find()) {
                double confidence = calculateConfidence(matcher.group(), input.length());
                return MatchResult.matched(confidence, matcher.group());
            }

            return MatchResult.notMatched();

        } catch (Exception e) {
            log.warn("Pattern matching failed for pattern '{}': {}", pattern.getName(), e.getMessage());
            return MatchResult.notMatched();
        }
    }

    /**
     * Calculates confidence based on the length of the matched text.
     * Longer matches indicate a more precise/deliberate attack.
     * Minimum confidence is 0.8 since any regex match is already a strong signal.
     */
    private double calculateConfidence(String matchedText, int totalLength) {
        int matchLength = matchedText.trim().length();
        if (matchLength >= 20) {
            return 1.0;
        } else if (matchLength >= 10) {
            return 0.9;
        } else {
            return 0.8; // Minimum: any keyword match is a strong signal
        }
    }
}

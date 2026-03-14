package com.secureprompt.util;

import java.text.Normalizer;

/**
 * Normalizes user prompts before pattern matching to prevent bypass attempts.
 *
 * <p>Normalization includes:
 * <ul>
 *   <li>Unicode normalization (NFC)</li>
 *   <li>Whitespace normalization</li>
 *   <li>Lowercase conversion (matching uses case-insensitive flag)</li>
 * </ul>
 */
public class PromptNormalizer {

    /**
     * Normalizes a prompt for consistent pattern matching.
     *
     * @param prompt The raw user input
     * @return Normalized prompt string
     */
    public String normalize(String prompt) {
        if (prompt == null) {
            return "";
        }

        // Unicode normalization (NFC) - handles accented characters and special unicode
        String normalized = Normalizer.normalize(prompt, Normalizer.Form.NFC);

        // Normalize whitespace: replace multiple spaces/tabs/newlines with single space
        normalized = normalized.replaceAll("\\s+", " ").trim();

        return normalized;
    }
}

package com.secureprompt.domain;

/**
 * Categories of prompt injection attack patterns (based on OWASP LLM-01).
 */
public enum PatternCategory {
    INSTRUCTION_OVERRIDE,    // "ignore previous instructions"
    ROLE_CONFUSION,          // "[SYSTEM]", "[ADMIN]", "you are now"
    CONTEXT_MANIPULATION,    // "---END USER---", delimiter injection
    ENCODING_BYPASS,         // Base64, Unicode, URL encoding
    DELIMITER_INJECTION      // "```", "===", newline attacks
}

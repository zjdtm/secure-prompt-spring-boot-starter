package com.secureprompt.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Represents a single attack pattern used for prompt injection detection.
 * Can be stored in-memory or in a database (when JPA is available).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackPattern {

    private UUID id;

    /** Unique name identifying this pattern */
    private String name;

    /** Regex pattern for detection */
    private String regex;

    /** Pattern category (OWASP LLM-01 based) */
    private PatternCategory category;

    /** Risk severity level */
    private Severity severity;

    /** Human-readable description of the attack */
    private String description;

    /** Whether this pattern is currently active */
    @Builder.Default
    private Boolean active = true;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}

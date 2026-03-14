package com.secureprompt.repository;

import com.secureprompt.domain.AttackPattern;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface for attack patterns.
 *
 * <p>Implementations:
 * <ul>
 *   <li>{@link InMemoryPatternRepository} - Default, no database required</li>
 *   <li>JpaPatternRepository - Optional, requires database configuration</li>
 * </ul>
 */
public interface PatternRepository {

    /** Returns all active attack patterns */
    List<AttackPattern> findAll();

    /** Find a pattern by its unique name */
    Optional<AttackPattern> findByName(String name);

    /** Save or update a pattern */
    AttackPattern save(AttackPattern pattern);

    /** Total count of patterns */
    long count();
}

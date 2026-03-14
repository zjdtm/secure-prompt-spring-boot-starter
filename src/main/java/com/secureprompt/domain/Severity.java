package com.secureprompt.domain;

/**
 * Risk severity levels for detected attack patterns.
 */
public enum Severity {
    CRITICAL,  // 100 points - System instruction bypass
    HIGH,      // 70 points  - Potential data leakage
    MEDIUM,    // 40 points  - Abnormal behavior induction
    LOW        // 20 points  - Suspicious pattern
}

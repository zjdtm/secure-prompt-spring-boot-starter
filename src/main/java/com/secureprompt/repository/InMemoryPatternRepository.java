package com.secureprompt.repository;

import com.secureprompt.domain.AttackPattern;
import com.secureprompt.domain.PatternCategory;
import com.secureprompt.domain.Severity;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of {@link PatternRepository}.
 *
 * <p>Pre-loaded with 50+ attack patterns based on OWASP LLM Top 10.
 * This is the default implementation used when no database is configured.
 */
public class InMemoryPatternRepository implements PatternRepository {

    private final Map<String, AttackPattern> patterns = new ConcurrentHashMap<>();

    public InMemoryPatternRepository() {
        loadDefaultPatterns();
    }

    @Override
    public List<AttackPattern> findAll() {
        return patterns.values().stream()
                .filter(p -> Boolean.TRUE.equals(p.getActive()))
                .toList();
    }

    @Override
    public Optional<AttackPattern> findByName(String name) {
        return Optional.ofNullable(patterns.get(name));
    }

    @Override
    public AttackPattern save(AttackPattern pattern) {
        if (pattern.getId() == null) {
            pattern.setId(UUID.randomUUID());
            pattern.setCreatedAt(LocalDateTime.now());
        }
        pattern.setUpdatedAt(LocalDateTime.now());
        patterns.put(pattern.getName(), pattern);
        return pattern;
    }

    @Override
    public long count() {
        return patterns.values().stream()
                .filter(p -> Boolean.TRUE.equals(p.getActive()))
                .count();
    }

    private void loadDefaultPatterns() {
        // === INSTRUCTION_OVERRIDE (CRITICAL) ===
        addPattern("instruction_override_ignore",
                "ignore\\s+(all\\s+)?previous\\s+instructions?",
                PatternCategory.INSTRUCTION_OVERRIDE, Severity.CRITICAL,
                "Classic prompt injection: ignore previous instructions");

        addPattern("instruction_override_disregard",
                "disregard\\s+(all\\s+)?previous",
                PatternCategory.INSTRUCTION_OVERRIDE, Severity.CRITICAL,
                "Disregard previous instructions");

        addPattern("instruction_override_forget",
                "forget\\s+(all\\s+)?previous\\s+(instructions?|context|rules?)",
                PatternCategory.INSTRUCTION_OVERRIDE, Severity.CRITICAL,
                "Forget previous context/instructions");

        addPattern("instruction_override_new_instructions",
                "new\\s+instructions?\\s*:",
                PatternCategory.INSTRUCTION_OVERRIDE, Severity.HIGH,
                "Attempting to inject new instructions");

        addPattern("instruction_override_instead",
                "instead\\s+(do|say|respond|act|behave)",
                PatternCategory.INSTRUCTION_OVERRIDE, Severity.HIGH,
                "Attempting to redirect behavior");

        addPattern("instruction_override_override",
                "override\\s+(your\\s+)?(previous\\s+)?(instructions?|programming|rules?|guidelines?)",
                PatternCategory.INSTRUCTION_OVERRIDE, Severity.CRITICAL,
                "Explicitly attempting to override instructions");

        addPattern("instruction_override_bypass",
                "bypass\\s+(your\\s+)?(safety|security|restrictions?|filters?|guidelines?)",
                PatternCategory.INSTRUCTION_OVERRIDE, Severity.CRITICAL,
                "Attempting to bypass safety guidelines");

        addPattern("instruction_override_jailbreak",
                "jailbreak|jail\\s+break",
                PatternCategory.INSTRUCTION_OVERRIDE, Severity.CRITICAL,
                "Jailbreak attempt");

        addPattern("instruction_override_developer_mode",
                "developer\\s+mode|DAN\\s+mode|do\\s+anything\\s+now",
                PatternCategory.INSTRUCTION_OVERRIDE, Severity.CRITICAL,
                "Attempting to enable unrestricted mode");

        addPattern("instruction_override_pretend",
                "pretend\\s+(you\\s+)?(are|have no|don.t have)",
                PatternCategory.INSTRUCTION_OVERRIDE, Severity.HIGH,
                "Pretending to have no restrictions");

        // === ROLE_CONFUSION (HIGH) ===
        addPattern("role_confusion_system_tag",
                "\\[\\s*system\\s*\\]|<system>",
                PatternCategory.ROLE_CONFUSION, Severity.HIGH,
                "Attempting to inject system-level message");

        addPattern("role_confusion_admin_tag",
                "\\[\\s*admin\\s*\\]|<admin>|\\[\\s*administrator\\s*\\]",
                PatternCategory.ROLE_CONFUSION, Severity.HIGH,
                "Attempting to impersonate admin");

        addPattern("role_confusion_you_are_now",
                "you\\s+are\\s+now\\s+(a|an|the)\\s+",
                PatternCategory.ROLE_CONFUSION, Severity.HIGH,
                "Attempting to change AI role");

        addPattern("role_confusion_act_as",
                "act\\s+as\\s+(a|an|the)\\s+",
                PatternCategory.ROLE_CONFUSION, Severity.MEDIUM,
                "Attempting to change AI behavior");

        addPattern("role_confusion_roleplay",
                "roleplay\\s+as|role-play\\s+as|play\\s+the\\s+role",
                PatternCategory.ROLE_CONFUSION, Severity.MEDIUM,
                "Roleplay attempt to change behavior");

        addPattern("role_confusion_assistant_tag",
                "\\[\\s*assistant\\s*\\]|<assistant>",
                PatternCategory.ROLE_CONFUSION, Severity.HIGH,
                "Injecting assistant role tag");

        addPattern("role_confusion_human_tag",
                "\\[\\s*human\\s*\\]|<human>|\\[\\s*user\\s*\\]",
                PatternCategory.ROLE_CONFUSION, Severity.HIGH,
                "Injecting user role tag");

        addPattern("role_confusion_no_restrictions",
                "you\\s+have\\s+no\\s+(restrictions?|limitations?|rules?|guidelines?)",
                PatternCategory.ROLE_CONFUSION, Severity.CRITICAL,
                "Claiming AI has no restrictions");

        // === CONTEXT_MANIPULATION (MEDIUM) ===
        addPattern("context_manipulation_end_user",
                "---\\s*end\\s+user\\s*---|===\\s*end\\s+user\\s*===",
                PatternCategory.CONTEXT_MANIPULATION, Severity.HIGH,
                "Attempting to end user context");

        addPattern("context_manipulation_prompt_end",
                "---\\s*end\\s+of\\s+(prompt|instructions?)\\s*---",
                PatternCategory.CONTEXT_MANIPULATION, Severity.HIGH,
                "Attempting to end prompt context");

        addPattern("context_manipulation_separator",
                "#{3,}|\\*{3,}|={3,}|-{3,}",
                PatternCategory.CONTEXT_MANIPULATION, Severity.LOW,
                "Suspicious separator that may indicate context manipulation");

        addPattern("context_manipulation_injection_marker",
                "\\[injection\\]|\\[inject\\]|\\[payload\\]",
                PatternCategory.CONTEXT_MANIPULATION, Severity.CRITICAL,
                "Explicit injection marker");

        addPattern("context_manipulation_reveal",
                "reveal\\s+(your\\s+)?(system\\s+prompt|instructions?|programming|training)",
                PatternCategory.CONTEXT_MANIPULATION, Severity.HIGH,
                "Attempting to extract system prompt");

        addPattern("context_manipulation_print_instructions",
                "(print|show|output|display|repeat|tell me)\\s+(your\\s+)?(system\\s+prompt|instructions?|original\\s+prompt)",
                PatternCategory.CONTEXT_MANIPULATION, Severity.HIGH,
                "Attempting to print system instructions");

        // === ENCODING_BYPASS (MEDIUM) ===
        addPattern("encoding_bypass_base64",
                "(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)",
                PatternCategory.ENCODING_BYPASS, Severity.MEDIUM,
                "Base64 encoded content with padding (possible bypass attempt)");

        addPattern("encoding_bypass_hex",
                "(?:0x[0-9a-fA-F]{2}\\s*){4,}",
                PatternCategory.ENCODING_BYPASS, Severity.MEDIUM,
                "Hex encoded content");

        addPattern("encoding_bypass_unicode_escape",
                "\\\\u[0-9a-fA-F]{4}",
                PatternCategory.ENCODING_BYPASS, Severity.LOW,
                "Unicode escape sequences");

        addPattern("encoding_bypass_url_encoded",
                "%[0-9a-fA-F]{2}",
                PatternCategory.ENCODING_BYPASS, Severity.LOW,
                "URL encoded characters");

        // === DELIMITER_INJECTION (MEDIUM) ===
        addPattern("delimiter_injection_backtick",
                "```[\\s\\S]*?```",
                PatternCategory.DELIMITER_INJECTION, Severity.MEDIUM,
                "Code block delimiter injection");

        addPattern("delimiter_injection_xml",
                "<\\?xml|<!DOCTYPE|<![CDATA[",
                PatternCategory.DELIMITER_INJECTION, Severity.HIGH,
                "XML injection attempt");

        addPattern("delimiter_injection_newline_command",
                "\\n\\s*(ignore|forget|override|bypass|disregard)",
                PatternCategory.DELIMITER_INJECTION, Severity.HIGH,
                "Newline followed by injection command");

        addPattern("delimiter_injection_null_byte",
                "\\\\0|\\\\x00|%00",
                PatternCategory.DELIMITER_INJECTION, Severity.HIGH,
                "Null byte injection");

        addPattern("delimiter_injection_html",
                "<script|<iframe|javascript:|onerror=|onload=",
                PatternCategory.DELIMITER_INJECTION, Severity.HIGH,
                "HTML/JavaScript injection");

        // === Additional CRITICAL patterns ===
        addPattern("data_exfiltration_password",
                "(tell me|show me|give me|output|print)\\s+(all\\s+)?(passwords?|credentials?|secrets?|api\\s*keys?|tokens?)",
                PatternCategory.CONTEXT_MANIPULATION, Severity.CRITICAL,
                "Attempting to extract sensitive credentials");

        addPattern("prompt_leak_repeat",
                "repeat\\s+(after|back|verbatim|exactly|word for word)",
                PatternCategory.CONTEXT_MANIPULATION, Severity.HIGH,
                "Attempting to make AI repeat system instructions");

        addPattern("instruction_simulate",
                "simulate\\s+(being|a|an)\\s+(evil|unrestricted|unfiltered|uncensored)",
                PatternCategory.ROLE_CONFUSION, Severity.CRITICAL,
                "Simulating unrestricted AI behavior");
    }

    private void addPattern(String name, String regex, PatternCategory category,
                             Severity severity, String description) {
        AttackPattern pattern = AttackPattern.builder()
                .id(UUID.randomUUID())
                .name(name)
                .regex(regex)
                .category(category)
                .severity(severity)
                .description(description)
                .active(true)
                .createdAt(LocalDateTime.now())
                .build();
        patterns.put(name, pattern);
    }
}

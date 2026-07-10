use crate::issues::Issue;
use crate::rules::{EntropyRule, RuleSet};
use regex::Regex;

use super::entropy::shannon_entropy;

pub fn scan_file(file_path: &str, content: &str, ruleset: &RuleSet) -> Vec<Issue> {
    let mut issues = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    for rule in &ruleset.rules {
        // Skip rules that only have AST patterns (no regex patterns)
        if rule.pattern.is_none() {
            continue;
        }

        // Match file pattern if specified
        if let Some(file_pattern) = &rule.file_pattern {
            if !wildmatch::WildMatch::new(file_pattern).matches(file_path) {
                continue;
            }
        }

        // Respect global defaults + rule-level file exclusions (path + content)
        if rule.is_excluded(file_path, content, &ruleset.defaults) {
            continue;
        }

        // Regex pattern matching with comment/string filtering
        if let Some(pattern) = &rule.pattern {
            for (i, line) in lines.iter().enumerate() {
                // Skip if the match is in a comment or string literal, unless this is a
                // secret-detection rule: secrets routinely live inside string literals
                // (.env/.json/.yaml values, Python string assignments), so this
                // Python-oriented heuristic must not suppress them.
                if !rule.redact && is_in_comment_or_string(line) {
                    continue;
                }

                if let Some(caps) = pattern.captures(line) {
                    // Skip if the line also matches the exclude pattern
                    if let Some(exclude) = &rule.exclude_pattern {
                        if exclude.is_match(line) {
                            continue;
                        }
                    }

                    let code = if rule.redact {
                        // Redact the first capture group (the secret value) if the
                        // pattern defines one, otherwise redact the whole match.
                        let target = caps.get(1).or_else(|| caps.get(0)).unwrap();
                        redact_span(line, target.start(), target.end())
                    } else {
                        line.to_string()
                    };

                    issues.push(Issue::new(
                        rule.id.clone(),
                        rule.description.clone(),
                        file_path.to_string(),
                        i + 1,
                        code,
                        rule.severity.clone(),
                        rule.confidence.clone(),
                        rule.remediation.clone(),
                        rule.cwe.clone(),
                    ));
                }
            }
        }
    }

    issues
}

fn is_in_comment_or_string(line: &str) -> bool {
    let trimmed = line.trim();

    // Skip obvious comments
    if trimmed.starts_with('#') {
        return true;
    }

    // Skip lines that are entirely string literals (docstrings)
    if (trimmed.starts_with("\"\"\"") && trimmed.ends_with("\"\"\"") && trimmed.len() > 6) ||
       (trimmed.starts_with("'''") && trimmed.ends_with("'''") && trimmed.len() > 6) ||
       (trimmed.starts_with('"') && trimmed.ends_with('"') && !trimmed.contains(" = ")) ||
       (trimmed.starts_with('\'') && trimmed.ends_with('\'') && !trimmed.contains(" = ")) {
        return true;
    }

    // More sophisticated check: if the line contains quotes but no assignment/function call
    // it's likely a standalone string/docstring
    if (trimmed.contains("\"\"\"") || trimmed.contains("'''")) &&
       !trimmed.contains('=') &&
       !trimmed.contains('(') {
        return true;
    }

    false
}

/// Returns true if the given bytes look like binary content (contains a NUL
/// byte within the first 8KB) rather than text. Used to skip binary files
/// (images, archives, compiled artifacts) before pattern/entropy scanning.
pub fn looks_binary(bytes: &[u8]) -> bool {
    let sample_len = bytes.len().min(8192);
    bytes[..sample_len].contains(&0u8)
}

/// Replaces the `[start, end)` byte span of `line` with a redacted form of the
/// value it contains, preserving the surrounding context (e.g. `api_key = `).
fn redact_span(line: &str, start: usize, end: usize) -> String {
    let secret = &line[start..end];
    format!("{}{}{}", &line[..start], redact_value(secret), &line[end..])
}

/// Masks a secret value, keeping only the first/last 4 characters visible.
/// Short values (<=8 chars) are fully masked to avoid leaking most of a short
/// secret.
fn redact_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();

    if len <= 8 {
        return "*".repeat(len.max(4));
    }

    let first: String = chars[..4].iter().collect();
    let last: String = chars[len - 4..].iter().collect();
    format!("{}{}{}", first, "*".repeat(len - 8), last)
}

/// A compiled `EntropyRule`, ready to scan file content without recompiling
/// its token regex on every call.
pub struct CompiledEntropyRule<'a> {
    rule: &'a EntropyRule,
    token_regex: Regex,
}

/// Compiles all entropy rules in a `RuleSet` once per scan run (not once per
/// file), since regex compilation is comparatively expensive and files are
/// processed in parallel.
pub fn compile_entropy_rules(ruleset: &RuleSet) -> Vec<CompiledEntropyRule> {
    ruleset
        .entropy_rules
        .iter()
        .filter_map(|rule| {
            Regex::new(&rule.token_pattern)
                .ok()
                .map(|token_regex| CompiledEntropyRule { rule, token_regex })
        })
        .collect()
}

/// Scans file content for high-entropy tokens (e.g. long base64/hex blobs)
/// not covered by an explicit secret pattern. Always redacts matches.
pub fn scan_file_entropy(
    file_path: &str,
    content: &str,
    compiled_rules: &[CompiledEntropyRule],
    entropy_override: Option<f64>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    if compiled_rules.is_empty() {
        return issues;
    }

    let lines: Vec<&str> = content.lines().collect();

    for entry in compiled_rules {
        let rule = entry.rule;

        if let Some(file_pattern) = &rule.file_pattern {
            if !wildmatch::WildMatch::new(file_pattern).matches(file_path) {
                continue;
            }
        }

        let threshold = entropy_override.unwrap_or(rule.threshold);

        for (i, line) in lines.iter().enumerate() {
            for m in entry.token_regex.find_iter(line) {
                let token = m.as_str();
                if token.chars().count() < rule.min_length {
                    continue;
                }

                if shannon_entropy(token) >= threshold {
                    let code = redact_span(line, m.start(), m.end());
                    issues.push(Issue::new(
                        rule.id.clone(),
                        rule.description.clone(),
                        file_path.to_string(),
                        i + 1,
                        code,
                        rule.severity.clone(),
                        rule.confidence.clone(),
                        rule.remediation.clone(),
                        None,
                    ));
                }
            }
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issues::Severity;
    use crate::rules::Rule;

    fn redact_rule(id: &str, pattern: &str) -> Rule {
        toml::from_str(&format!(
            r#"
            id = "{id}"
            description = "test"
            severity = "Critical"
            pattern = '{pattern}'
            redact = true
            "#
        ))
        .unwrap()
    }

    #[test]
    fn redact_value_masks_middle_keeps_edges() {
        assert_eq!(redact_value("AKIAABCDEFGH1234"), "AKIA********1234");
    }

    #[test]
    fn redact_value_short_secret_fully_masked() {
        let out = redact_value("abcd1234");
        assert_eq!(out, "*".repeat(8));
    }

    #[test]
    fn scan_file_redacts_capture_group_only() {
        let mut ruleset = RuleSet {
            defaults: Default::default(),
            rules: vec![redact_rule("SECRET001", r#"api_key\s*=\s*"([A-Za-z0-9]{12,})""#)],
            taint_sources: vec![],
            taint_sinks: vec![],
            taint_sanitizers: vec![],
            entropy_rules: vec![],
        };
        ruleset.rules[0].severity = Severity::Critical;

        let content = "api_key = \"ABCDEFGHIJKL9999\"\n";
        let issues = scan_file("config.py", content, &ruleset);

        assert_eq!(issues.len(), 1);
        assert!(issues[0].code.starts_with("api_key = \"ABCD"));
        assert!(!issues[0].code.contains("ABCDEFGHIJKL9999"));
        assert!(issues[0].code.contains("9999\""));
    }

    #[test]
    fn scan_file_secret_rule_bypasses_string_literal_filter() {
        let mut ruleset = RuleSet {
            defaults: Default::default(),
            rules: vec![redact_rule("SECRET002", r#""api_key":\s*"([A-Za-z0-9]{12,})""#)],
            taint_sources: vec![],
            taint_sinks: vec![],
            taint_sanitizers: vec![],
            entropy_rules: vec![],
        };
        ruleset.rules[0].severity = Severity::Critical;

        // This line looks like a bare string literal to `is_in_comment_or_string`
        // (starts and ends with a quote) but is a real JSON secret value.
        let content = "\"api_key\": \"ABCDEFGHIJKL9999\"\n";
        let issues = scan_file("config.json", content, &ruleset);

        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn looks_binary_detects_nul_byte() {
        assert!(looks_binary(&[0x41, 0x42, 0x00, 0x43]));
        assert!(!looks_binary(b"hello world"));
    }

    #[test]
    fn scan_file_entropy_flags_high_entropy_token_and_redacts() {
        let mut ruleset = RuleSet {
            defaults: Default::default(),
            rules: vec![],
            taint_sources: vec![],
            taint_sinks: vec![],
            taint_sanitizers: vec![],
            entropy_rules: vec![],
        };
        ruleset.entropy_rules.push(toml::from_str(
            r#"
            id = "ENTROPY001"
            description = "High entropy token"
            severity = "Medium"
            threshold = 4.0
            min_length = 20
            "#,
        ).unwrap());

        let compiled = compile_entropy_rules(&ruleset);
        let content = "token = 8f3kD9pQmZ2xN7vR1tYcL0aWs6HbUeJg\n";
        let issues = scan_file_entropy("config.py", content, &compiled, None);

        assert_eq!(issues.len(), 1);
        assert!(!issues[0].code.contains("8f3kD9pQmZ2xN7vR1tYcL0aWs6HbUeJg"));
    }

    #[test]
    fn scan_file_entropy_ignores_low_entropy_text() {
        let mut ruleset = RuleSet {
            defaults: Default::default(),
            rules: vec![],
            taint_sources: vec![],
            taint_sinks: vec![],
            taint_sanitizers: vec![],
            entropy_rules: vec![],
        };
        ruleset.entropy_rules.push(toml::from_str(
            r#"
            id = "ENTROPY001"
            description = "High entropy token"
            severity = "Medium"
            threshold = 4.5
            min_length = 20
            "#,
        ).unwrap());

        let compiled = compile_entropy_rules(&ruleset);
        let content = "this_is_a_normal_variable_name_not_a_secret = True\n";
        let issues = scan_file_entropy("config.py", content, &compiled, None);

        assert_eq!(issues.len(), 0);
    }
}

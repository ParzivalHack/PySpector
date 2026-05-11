use crate::issues::Issue;
use crate::rules::RuleSet;

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

        // Regex pattern matching with comment/string filtering
        if let Some(pattern) = &rule.pattern {
            for (i, line) in lines.iter().enumerate() {
                // Skip if the match is in a comment or string literal
                if is_in_comment_or_string(line) {
                    continue;
                }

                if pattern.is_match(line) {
                    issues.push(Issue::new(
                        rule.id.clone(),
                        rule.description.clone(),
                        file_path.to_string(),
                        i + 1,
                        line.to_string(),
                        rule.severity.clone(),
                        rule.confidence.clone(),
                        rule.remediation.clone(),
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
    if (trimmed.starts_with("\"\"\"") && trimmed.ends_with("\"\"\"") && trimmed.len() > 6)
        || (trimmed.starts_with("'''") && trimmed.ends_with("'''") && trimmed.len() > 6)
        || (trimmed.starts_with('"') && trimmed.ends_with('"') && !trimmed.contains(" = "))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\'') && !trimmed.contains(" = "))
    {
        return true;
    }

    // More sophisticated check: if the line contains quotes but no assignment/function call
    // it's likely a standalone string/docstring
    if (trimmed.contains("\"\"\"") || trimmed.contains("'''"))
        && !trimmed.contains('=')
        && !trimmed.contains('(')
    {
        return true;
    }

    false
}

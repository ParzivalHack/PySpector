use crate::issues::Issue;
use crate::rules::RuleSet;

pub fn scan_file(file_path: &str, content: &str, ruleset: &RuleSet) -> Vec<Issue> {
    let mut issues = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    // is_in_comment_or_string() depends only on the line's own text, not on
    // which rule is being checked. Computing it once per line here (instead of
    // once per rule per line) turns an O(rules × lines) redundant recomputation
    // into O(lines) for every file — regex rules run against every scanned file.
    let code_line_mask: Vec<bool> = lines.iter().map(|line| !is_in_comment_or_string(line)).collect();

    for rule in &ruleset.rules {
        // Skip rules that only have AST patterns (no regex patterns)
        if rule.pattern.is_none() {
            continue;
        }

        // Match file pattern if specified (precompiled once in RuleSet::finalize())
        if let Some(compiled_pattern) = &rule.compiled_file_pattern {
            if !compiled_pattern.matches(file_path) {
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
                // Skip if the match is in a comment or string literal
                if !code_line_mask[i] {
                    continue;
                }

                if pattern.is_match(line) {
                    // Skip if the line also matches the exclude pattern
                    if let Some(exclude) = &rule.exclude_pattern {
                        if exclude.is_match(line) {
                            continue;
                        }
                    }
                    issues.push(Issue::new(
                        rule.id.clone(),
                        rule.description.clone(),
                        file_path.to_string(),
                        i + 1,
                        line.to_string(),
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
use crate::ast_parser::AstNode;
use crate::issues::Issue;
use crate::rules::{RuleSet, Rule};

// Main entry point for AST scanning
pub fn scan_ast(ast: &AstNode, file_path: &str, content: &str, ruleset: &RuleSet) -> Vec<Issue> {
    let mut issues = Vec::new();
    let ast_rules: Vec<&Rule> = ruleset.rules.iter()
        .filter(|r| r.ast_match.is_some())
        .collect();
    
    if ast_rules.is_empty() { return issues; }

    walk_ast(ast, file_path, content, &ast_rules, &mut issues);
    issues
}

// Recursively walks the AST, checking each node against the rules
fn walk_ast(node: &AstNode, file_path: &str, content: &str, rules: &[&Rule], issues: &mut Vec<Issue>) {
    for rule in rules.iter() {
        if let Some(match_pattern) = &rule.ast_match {
            if check_node_match(node, match_pattern) {
                let line_content = content.lines().nth(node.lineno.saturating_sub(1) as usize).unwrap_or("").to_string();
                issues.push(Issue::new(
                    rule.id.clone(),
                    rule.description.clone(),
                    file_path.to_string(),
                    node.lineno as usize,
                    line_content,
                    rule.severity.clone(),
                    rule.confidence.clone(),
                    rule.remediation.clone(),
                ));
            }
        }
    }

    // Recurse into children
    for child_list in node.children.values() {
        for child_node in child_list {
            walk_ast(child_node, file_path, content, rules, issues);
        }
    }
}

fn check_node_match(node: &AstNode, match_pattern: &str) -> bool {
    let (node_type_match, props_str) = if let Some(open_paren) = match_pattern.find('(') {
        (
            &match_pattern[..open_paren],
            Some(&match_pattern[open_paren + 1..match_pattern.rfind(')').unwrap_or(match_pattern.len())])
        )
    } else {
        (match_pattern, None)
    };

    if node.node_type != node_type_match { return false; }

    if let Some(props) = props_str {
        for prop in props.split(',') {
            if let Some((path, expected_value)) = prop.trim().split_once('=') {
                if !node_has_property(node, &path.split('.').collect::<Vec<_>>(), expected_value) {
                    return false;
                }
            }
        }
    }
    
    true
}

fn node_has_property(node: &AstNode, path: &[&str], expected_value: &str) -> bool {
    if path.is_empty() { return false; }

    let current_part = path[0];
    let remaining_path = &path[1..];

    if remaining_path.is_empty() {
        if let Some(field_value) = node.fields.get(current_part).and_then(|v| v.as_ref()) {
            return match field_value {
                serde_json::Value::String(s) => s == expected_value,
                serde_json::Value::Bool(b) => b.to_string().to_lowercase() == expected_value.to_lowercase(),
                serde_json::Value::Number(n) => n.to_string() == expected_value,
                _ => false
            };
        }
    }

    if let Some(child_list) = node.children.get(current_part) {
        if !remaining_path.is_empty() && remaining_path[0] == "*" {
            let path_after_wildcard = &remaining_path[1..];
            for child in child_list {
                if node_has_property(child, path_after_wildcard, expected_value) {
                    return true;
                }
            }
        } else if !remaining_path.is_empty() {
            if let Some(child) = child_list.first() {
                return node_has_property(child, remaining_path, expected_value);
            }
        }
    }
    
    false
}
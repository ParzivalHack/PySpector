use serde::Deserialize;
use crate::issues::Severity;
use regex::Regex;

/// Global defaults inherited by every rule unless the rule overrides them.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct Defaults {
    /// File-path glob patterns excluded from ALL rules (e.g. "*tests*", "*/fixtures/*").
    /// Rules may add their own exclude_file_pattern on top of these.
    #[serde(default)]
    pub exclude_file_patterns: Vec<String>,
    /// Rule IDs that are completely disabled (produce too much noise for this codebase).
    /// Disabling here is equivalent to deleting the rule but without touching the rule
    /// definitions — making it easy to re-enable or override per project.
    #[serde(default)]
    pub disabled_rule_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    #[serde(default = "default_confidence")]
    pub confidence: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(with = "serde_regex", default)]
    pub pattern: Option<Regex>,
    #[serde(with = "serde_regex", default)]
    pub exclude_pattern: Option<Regex>,
    #[serde(default)]
    pub ast_match: Option<String>,
    #[serde(default)]
    pub file_pattern: Option<String>,
    /// Rule-level glob to exclude specific files (stacks on top of [defaults]).
    #[serde(default)]
    pub exclude_file_pattern: Option<String>,
}

impl Rule {
    /// Returns true if `file_path` is excluded by this rule's own exclude_file_pattern
    /// OR by the global defaults.
    pub fn is_file_excluded(&self, file_path: &str, defaults: &Defaults) -> bool {
        // Check global default exclusions first
        for pattern in &defaults.exclude_file_patterns {
            if wildmatch::WildMatch::new(pattern).matches(file_path) {
                return true;
            }
        }
        // Then rule-level exclusion
        if let Some(efp) = &self.exclude_file_pattern {
            if wildmatch::WildMatch::new(efp).matches(file_path) {
                return true;
            }
        }
        false
    }
}

fn default_confidence() -> String { "Medium".to_string() }

#[derive(Debug, Deserialize)]
pub struct TaintSourceRule {
    pub id: String,
    pub description: String,
    pub function_call: String,
    pub taint_target: String,
}

#[derive(Debug, Deserialize)]
pub struct TaintSinkRule {
    pub id: String,
    pub vulnerability_id: String,
    pub description: String,
    pub function_call: String,
    pub vulnerable_parameter_index: usize,
}

#[derive(Debug, Deserialize)]
pub struct TaintSanitizerRule {
    pub id: String,
    pub description: String,
    pub function_call: String,
}

#[derive(Debug, Deserialize)]
pub struct RuleSet {
    /// Global defaults inherited by every rule.
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
    #[serde(default, rename = "taint_source")]
    pub taint_sources: Vec<TaintSourceRule>,
    #[serde(default, rename = "taint_sink")]
    pub taint_sinks: Vec<TaintSinkRule>,
    #[serde(default, rename = "taint_sanitizer")]
    pub taint_sanitizers: Vec<TaintSanitizerRule>,
}
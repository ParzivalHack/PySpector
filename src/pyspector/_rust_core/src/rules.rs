use crate::issues::Severity;
use regex::Regex;
use serde::Deserialize;

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
    #[serde(default)]
    pub ast_match: Option<String>,
    #[serde(default)]
    pub file_pattern: Option<String>,
}

fn default_confidence() -> String {
    "Medium".to_string()
}

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
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
    #[serde(default, rename = "taint_source")]
    pub taint_sources: Vec<TaintSourceRule>,
    #[serde(default, rename = "taint_sink")]
    pub taint_sinks: Vec<TaintSinkRule>,
    #[serde(default, rename = "taint_sanitizer")]
    pub taint_sanitizers: Vec<TaintSanitizerRule>,
}

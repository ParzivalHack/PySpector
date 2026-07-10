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
    /// Regex checked against the FULL FILE CONTENT. If the file content matches,
    /// this rule is suppressed for that file regardless of line-level matches.
    /// Use to avoid library-specific FPs: e.g. suppress yaml.load() findings in
    /// files that import ruamel.yaml (which is safe by default).
    /// Example: file_content_exclude = "from ruamel\\.yaml|import ruamel"
    #[serde(with = "serde_regex", default)]
    pub file_content_exclude: Option<regex::Regex>,
    /// CWE identifier (e.g. "CWE-78" for command injection). Used for
    /// cross-rule dedup: findings at the same (file, line) sharing the same
    /// CWE collapse to the highest-severity one. Rules without a CWE set
    /// keep the legacy per-rule dedup behaviour. Also surfaced in JSON/SARIF
    /// output for downstream tooling.
    #[serde(default)]
    pub cwe: Option<String>,
    /// When true, this rule matches secret material: the matched value (or its
    /// first capture group, if any) is redacted before the match is stored on
    /// an `Issue`, and the Python-literal comment/string heuristic in
    /// `config_analysis::is_in_comment_or_string` is bypassed, since secrets
    /// routinely live inside string literals (.env/.json/.yaml values).
    #[serde(default)]
    pub redact: bool,
}

impl Rule {
    /// Returns true if the file should be excluded based on path patterns OR
    /// file content (file_content_exclude checked against the full file text).
    pub fn is_file_excluded(&self, file_path: &str, defaults: &Defaults) -> bool {
        self.is_excluded(file_path, "", defaults)
    }

    /// Full exclusion check: path patterns + optional file content regex.
    /// Pass file content when available for the most accurate result.
    pub fn is_excluded(&self, file_path: &str, content: &str, defaults: &Defaults) -> bool {
        // Check global default exclusions first
        for pattern in &defaults.exclude_file_patterns {
            if wildmatch::WildMatch::new(pattern).matches(file_path) {
                return true;
            }
        }
        // Then rule-level file path exclusion (supports comma-separated patterns)
        if let Some(efp) = &self.exclude_file_pattern {
            for pattern in efp.split(',') {
                if wildmatch::WildMatch::new(pattern.trim()).matches(file_path) {
                    return true;
                }
            }
        }
        // Finally, file content exclusion — suppress rule if the file imports
        // a library or uses a pattern that makes the rule inapplicable.
        if !content.is_empty() {
            if let Some(fce) = &self.file_content_exclude {
                if fce.is_match(content) {
                    return true;
                }
            }
        }
        false
    }
}

fn default_confidence() -> String { "Medium".to_string() }

fn default_token_pattern() -> String { r"[A-Za-z0-9+/_=-]{20,}".to_string() }

fn default_min_length() -> usize { 20 }

#[derive(Debug, Deserialize, Clone)]
pub struct EntropyRule {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    #[serde(default = "default_confidence")]
    pub confidence: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub file_pattern: Option<String>,
    #[serde(default = "default_token_pattern")]
    pub token_pattern: String,
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    pub threshold: f64,
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
    /// Index of the positional argument that must be tainted to trigger this sink.
    /// Ignored when vulnerable_receiver = true.
    #[serde(default)]
    pub vulnerable_parameter_index: usize,
    /// When true, the method *receiver* (the object before the dot) must be
    /// tainted rather than a positional argument.
    /// e.g. tainted_template.format(...)  →  receiver "tainted_template" is the risk.
    #[serde(default)]
    pub vulnerable_receiver: bool,
    /// When true, this sink is a method call (called as obj.method()), so matching
    /// uses ends_with(".function_call"). When false (default), it is a direct builtin
    /// call (e.g. set(), open()) matched with exact equality to prevent "cache.set"
    /// matching the "set" builtin sink.
    #[serde(default)]
    pub is_method: bool,
    /// Which taint origins trigger this sink (default = "all" attacker-controlled).
    /// "injectable_only" — only fires for HttpRequest/External, NOT ShellSanitized.
    ///   Use for shell injection sinks (PY102): shlex.quote() is a valid mitigation.
    /// "all" (default) — fires for HttpRequest, External, AND ShellSanitized.
    ///   Use for path/SQL/URL sinks where shlex.quote doesn't help.
    #[serde(default = "default_triggers_on")]
    pub triggers_on: String,
    /// When set, only this named keyword argument triggers the sink.
    /// e.g. vulnerable_keyword = "password" fires only on create(..., password=tainted).
    /// When absent, any tainted positional or keyword arg may trigger.
    #[serde(default)]
    pub vulnerable_keyword: Option<String>,
}

fn default_triggers_on() -> String { "all".to_string() }

#[derive(Debug, Deserialize)]
pub struct TaintSanitizerRule {
    pub id: String,
    pub description: String,
    pub function_call: String,
    /// When set, the sanitizer does NOT clear taint but transforms its origin.
    /// e.g. transforms_to = "ShellSanitized" means shlex.quote() turns
    /// HttpRequest taint into ShellSanitized taint — still risky for path
    /// traversal / f-strings, but safe for shell injection (PY102).
    #[serde(default)]
    pub transforms_to: Option<String>,
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
    #[serde(default, rename = "entropy_rule")]
    pub entropy_rules: Vec<EntropyRule>,
}

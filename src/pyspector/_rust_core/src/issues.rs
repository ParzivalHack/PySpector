use pyo3::prelude::*;
use serde::Deserialize;
use sha1::{Sha1, Digest};

#[pyclass]
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct Issue {
    #[pyo3(get)]
    pub rule_id: String,
    #[pyo3(get)]
    pub description: String,
    #[pyo3(get)]
    pub file_path: String,
    #[pyo3(get)]
    pub line_number: usize,
    #[pyo3(get)]
    pub code: String,
    #[pyo3(get)]
    pub severity: Severity,
    #[pyo3(get)]
    pub confidence: String,
    #[pyo3(get)]
    pub remediation: String,
    /// CWE identifier inherited from the rule (e.g. "CWE-502"). Used for
    /// cross-rule dedup and downstream SARIF/JSON output.
    #[pyo3(get)]
    pub cwe: Option<String>,
}

// This new block exposes methods to Python
#[pymethods]
impl Issue {
    #[new] // This is the constructor exposed to Python
    #[pyo3(signature = (rule_id, description, file_path, line_number, code, severity, confidence, remediation, cwe=None))]
    pub fn new(
        rule_id: String,
        description: String,
        file_path: String,
        line_number: usize,
        code: String,
        severity: Severity,
        confidence: String,
        remediation: String,
        cwe: Option<String>,
    ) -> Self {
        Self {
            rule_id,
            description,
            file_path,
            line_number,
            code: code.trim().to_string(),
            severity,
            confidence,
            remediation,
            cwe,
        }
    }

    /// Creates a unique, stable fingerprint for an issue.
    pub fn get_fingerprint(&self) -> String {
        let unique_string = format!(
            "{}|{}|{}|{}",
            self.rule_id, self.file_path, self.line_number, self.code.trim()
        );

        let mut hasher = Sha1::new();
        hasher.update(unique_string.as_bytes());
        let result = hasher.finalize();
        
        format!("{:x}", result)
    }
}
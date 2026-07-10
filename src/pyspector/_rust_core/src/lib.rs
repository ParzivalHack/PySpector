use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use rayon::prelude::*;
use std::collections::HashSet;

mod ast_parser;
mod graph;
pub mod issues;
pub mod rules;
pub mod analysis;
mod supply_chain;

use issues::{Issue, Severity};
use rules::RuleSet;
use analysis::{run_analysis, AnalysisContext, config_analysis};
use ast_parser::PythonFile;

#[pyfunction]
#[pyo3(name = "run_scan")]
fn run_scan_py<'py>(
    py: Python<'py>,
    path: String,
    rules_toml_str: String,
    config: &Bound<'py, PyDict>,
    python_files_data: &Bound<'py, PyList>,
) -> PyResult<Bound<'py, PyList>> {

    let exclusions: Vec<String> = config.get_item("exclude")?.map_or(Ok(Vec::new()), |v| v.extract())?;
    let entropy_threshold: Option<f64> = config.get_item("entropy_threshold")?.map_or(Ok(None), |v| v.extract())?;

    let mut ruleset: RuleSet = toml::from_str(&rules_toml_str).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Failed to parse rules: {}", e))
    })?;
    // Precompile glob exclusion patterns once instead of on every (file, rule) check.
    ruleset.finalize();

    // Extracting from Python objects requires the GIL, so this loop must stay
    // sequential — but it only copies three strings per file, it doesn't parse
    // anything. The actual parsing (serde_json::from_str over each file's AST,
    // which can be a sizeable JSON tree) is pure CPU work with no GIL
    // dependency, so it's deferred and done in parallel below, after detach().
    let mut raw_files: Vec<(String, String, String)> = Vec::new();
    for item in python_files_data.iter() {
        let file_dict: Bound<'py, PyDict> = item.extract()?;
        let file_path: String = file_dict.get_item("file_path")?.unwrap().extract()?;
        let content: String = file_dict.get_item("content")?.unwrap().extract()?;
        let ast_json: String = file_dict.get_item("ast_json")?.unwrap().extract()?;

        raw_files.push((file_path, content, ast_json));
    }

    let context = AnalysisContext {
        root_path: path,
        exclusions,
        ruleset,
        py_files: &py_files,
        entropy_threshold,
    };

    // PyO3 renamed `allow_threads` to `detach`
    let issues = py.detach(|| {
        // Parse every file's AST JSON in parallel across all cores instead of
        // one-at-a-time — previously this ran sequentially before any
        // Rayon-parallelized analysis even started.
        let py_files: Vec<PythonFile> = raw_files
            .into_par_iter()
            .map(|(file_path, content, ast_json)| PythonFile::new(file_path, content, ast_json))
            .collect();

        let context = AnalysisContext {
            root_path: path,
            exclusions,
            ruleset,
            py_files: &py_files,
        };

        run_analysis(context)
    });

    let py_issues = PyList::empty(py);
    for issue in issues {
        py_issues.append(Py::new(py, issue)?)?;
    }

    Ok(py_issues)
}

#[pyfunction]
#[pyo3(name = "scan_blobs")]
fn scan_blobs_py<'py>(
    py: Python<'py>,
    blobs: &Bound<'py, PyList>,
    rules_toml_str: String,
    config: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyList>> {
    let entropy_threshold: Option<f64> =
        config.get_item("entropy_threshold")?.map_or(Ok(None), |v| v.extract())?;

    let ruleset: RuleSet = toml::from_str(&rules_toml_str).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Failed to parse rules: {}", e))
    })?;

    struct Blob {
        label: String,
        content: String,
    }

    let mut items: Vec<Blob> = Vec::new();
    for item in blobs.iter() {
        let dict: Bound<'py, PyDict> = item.extract()?;
        let path: String = dict.get_item("path")?.unwrap().extract()?;
        let content: String = dict.get_item("content")?.unwrap().extract()?;
        let commit: String = dict.get_item("commit")?.unwrap().extract()?;
        items.push(Blob {
            label: format!("{}:{}", commit, path),
            content,
        });
    }

    let compiled_entropy_rules = config_analysis::compile_entropy_rules(&ruleset);

    // PyO3 renamed `allow_threads` to `detach`
    let issues: Vec<Issue> = py.detach(|| {
        let mut all: Vec<Issue> = items
            .par_iter()
            .flat_map(|blob| {
                let mut findings =
                    config_analysis::scan_file(&blob.label, &blob.content, &ruleset);
                findings.extend(config_analysis::scan_file_entropy(
                    &blob.label,
                    &blob.content,
                    &compiled_entropy_rules,
                    entropy_threshold,
                ));
                findings
            })
            .collect();

        let mut seen = HashSet::new();
        all.retain(|issue| seen.insert(issue.get_fingerprint()));
        all
    });

    let py_issues = PyList::empty(py);
    for issue in issues {
        py_issues.append(Py::new(py, issue)?)?;
    }

    Ok(py_issues)
}

#[pyfunction]
#[pyo3(name = "scan_supply_chain")]
fn scan_supply_chain_py<'py>(
    py: Python<'py>,
    project_path: String,
) -> PyResult<Bound<'py, PyList>> {
    // PyO3 renamed `allow_threads` to `detach`
    let vulnerabilities = py.detach(|| {
        supply_chain::scan_dependencies(&project_path)
    });

    let py_list = PyList::empty(py);
    for vuln in vulnerabilities {
        let dict = PyDict::new(py);
        dict.set_item("dependency", vuln.dependency)?;
        dict.set_item("version", vuln.version)?;
        dict.set_item("vulnerability_id", vuln.vulnerability_id)?;
        dict.set_item("severity", vuln.severity)?;
        dict.set_item("summary", vuln.summary)?;
        dict.set_item("file", vuln.file)?;
        dict.set_item("fixed_version", vuln.fixed_version)?;
        py_list.append(dict)?;
    }

    Ok(py_list)
}

#[pymodule]
fn _rust_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Issue>()?;
    m.add_class::<Severity>()?;

    m.add_function(wrap_pyfunction!(run_scan_py, m)?)?;
    m.add_function(wrap_pyfunction!(scan_blobs_py, m)?)?;
    m.add_function(wrap_pyfunction!(scan_supply_chain_py, m)?)?;

    Ok(())
}

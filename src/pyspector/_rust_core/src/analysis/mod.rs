use crate::ast_parser::PythonFile;
use crate::graph::call_graph_builder;
use crate::issues::{Issue, Severity};
use crate::rules::RuleSet;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// Numeric ordering of severities so we can pick the "worse" of two findings
/// that fire at the same code location. Critical > High > Medium > Low.
fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}

mod ast_analysis;
mod config_analysis;
mod taint_analysis;

pub struct AnalysisContext<'a> {
    pub root_path: String,
    pub exclusions: Vec<String>,
    pub ruleset: RuleSet,
    pub py_files: &'a [PythonFile],
}

pub fn run_analysis(mut context: AnalysisContext) -> Vec<Issue> {
    // Apply disabled_rule_ids from [defaults] before scanning
    if !context.ruleset.defaults.disabled_rule_ids.is_empty() {
        let disabled: std::collections::HashSet<&str> = context.ruleset.defaults
            .disabled_rule_ids.iter().map(|s| s.as_str()).collect();
        let before = context.ruleset.rules.len();
        context.ruleset.rules.retain(|r| !disabled.contains(r.id.as_str()));
        let removed = before - context.ruleset.rules.len();
        if removed > 0 {
            println!("[*] Disabled {} rules via [defaults].disabled_rule_ids", removed);
        }
    }
    println!("[*] Starting analysis with {} rules", context.ruleset.rules.len());
    
    let root_path = Path::new(&context.root_path);
    let mut files_to_scan: Vec<String> = Vec::new();
    
    // Add common test fixture patterns to exclusions
    let mut enhanced_exclusions = context.exclusions.clone();
    enhanced_exclusions.extend(vec![
        "*/tests/fixtures/*".to_string(),
        "*/test/fixtures/*".to_string(),
        "*_test.py".to_string(),
        "*/test_*.py".to_string(),
    ]);
    // Precompile each exclusion pattern once — is_excluded() is called once per
    // file in the walk below and once per file again in the AST pass, so
    // re-parsing every glob pattern with WildMatch::new() on every call (and
    // twice per call, at that) adds up on large codebases.
    let compiled_exclusions = compile_exclusions(&enhanced_exclusions);

    for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        // Collect all files (not just .py) for regex scanning
        if path.is_file() && !is_excluded(path, &compiled_exclusions) {
            if let Some(s) = path.to_str() {
                files_to_scan.push(s.to_string());
            }
        }
    }
    
    println!("[+] Found {} files to scan ({} non-Python)", files_to_scan.len(),
             files_to_scan.iter().filter(|f| !f.ends_with(".py")).count());

    // Scan all files with regex patterns
    let t_config = std::time::Instant::now();
    let mut issues: Vec<Issue> = files_to_scan
        .par_iter()
        .flat_map(|file_path| {
            if let Ok(content) = fs::read_to_string(file_path) {
                config_analysis::scan_file(file_path, &content, &context.ruleset)
            } else {
                Vec::new()
            }
        })
        .collect();
    println!("[*] Pattern/config scan: {:.2}s → {} issues", t_config.elapsed().as_secs_f64(), issues.len());

    // Process Python files with AST analysis
    let t_ast = std::time::Instant::now();
    let python_issues: Vec<Issue> = context.py_files
        .par_iter()
        .flat_map(|py_file| {
            let mut findings = Vec::new();
            if is_excluded(Path::new(&py_file.file_path), &compiled_exclusions) {
                return findings;
            }
            if let Some(ast) = &py_file.ast {
                let ast_findings = ast_analysis::scan_ast(ast, &py_file.file_path, &py_file.content, &context.ruleset);
                findings.extend(ast_findings);
            }
            findings
        })
        .collect();
    println!("[*] AST analysis: {:.2}s → {} issues", t_ast.elapsed().as_secs_f64(), python_issues.len());
    issues.extend(python_issues);

    // Build the call graph and run taint analysis
    let t_callgraph = std::time::Instant::now();
    let call_graph = call_graph_builder::build_call_graph(context.py_files);
    println!("[*] Call graph build: {:.2}s", t_callgraph.elapsed().as_secs_f64());
    let taint_issues = taint_analysis::analyze_program_for_taint(&call_graph, &context.ruleset);
    println!("[+] Found {} issues from taint analysis", taint_issues.len());
    issues.extend(taint_issues);
    
    let mut seen = HashSet::new();
    issues.retain(|issue| seen.insert(issue.get_fingerprint()));

    // Cross-rule dedup by CWE: at the same (file, line), rules sharing a CWE
    // describe one vulnerability — keep the highest severity. Distinct CWEs
    // stay distinct so `os.system(eval(x))` reports both CWE-78 and CWE-94.
    let mut by_cwe_loc: HashMap<(String, usize, String), Issue> = HashMap::new();
    let mut uncategorized: Vec<Issue> = Vec::new();
    for issue in issues {
        match &issue.cwe {
            Some(cwe) => {
                let key = (issue.file_path.clone(), issue.line_number, cwe.clone());
                match by_cwe_loc.get(&key) {
                    Some(existing) => {
                        let new_rank = severity_rank(&issue.severity);
                        let old_rank = severity_rank(&existing.severity);
                        if new_rank > old_rank
                            || (new_rank == old_rank && issue.rule_id < existing.rule_id)
                        {
                            by_cwe_loc.insert(key, issue);
                        }
                    }
                    None => { by_cwe_loc.insert(key, issue); }
                }
            }
            None => uncategorized.push(issue),
        }
    }
    let merged = by_cwe_loc.len();
    let mut issues: Vec<Issue> = by_cwe_loc.into_values().collect();
    issues.extend(uncategorized);

    let untagged = issues.len() - merged;
    if untagged > 0 {
        println!(
            "[*] Total issues after deduplication: {} (CWE-tagged: {}, untagged: {})",
            issues.len(), merged, untagged
        );
    } else {
        println!("[*] Total issues after deduplication: {}", issues.len());
    }
    issues
}

/// Either a precompiled glob pattern or a plain substring, decided once at
/// compile time (see `compile_exclusions`) instead of re-inspecting the raw
/// string and reparsing the glob on every file checked.
enum ExclusionPattern {
    Glob(wildmatch::WildMatch),
    Substring(String),
}

fn compile_exclusions(exclusions: &[String]) -> Vec<ExclusionPattern> {
    exclusions.iter().map(|ex| {
        if ex.contains('*') {
            ExclusionPattern::Glob(wildmatch::WildMatch::new(ex))
        } else {
            ExclusionPattern::Substring(ex.clone())
        }
    }).collect()
}

fn is_excluded(path: &Path, exclusions: &[ExclusionPattern]) -> bool {
    let path_str = path.to_str().unwrap_or_default();
    let path_filename = path.file_name().and_then(|s| s.to_str()).unwrap_or_default();

    exclusions.iter().any(|ex| match ex {
        ExclusionPattern::Glob(pattern) => {
            pattern.matches(path_str) || pattern.matches(path_filename)
        }
        ExclusionPattern::Substring(s) => {
            path_str.contains(s.as_str()) || path_filename.contains(s.as_str())
        }
    })
}

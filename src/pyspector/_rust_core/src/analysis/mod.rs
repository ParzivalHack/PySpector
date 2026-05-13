use crate::ast_parser::PythonFile;
use crate::graph::call_graph_builder;
use crate::issues::Issue;
use crate::rules::RuleSet;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

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
    
    for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        // Collect all files (not just .py) for regex scanning
        if path.is_file() && !is_excluded(path, &enhanced_exclusions) {
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
            if is_excluded(Path::new(&py_file.file_path), &enhanced_exclusions) {
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
    
    // Remove duplicates
    let mut seen = HashSet::new();
    issues.retain(|issue| seen.insert(issue.get_fingerprint()));

    println!("[*] Total issues after deduplication: {}", issues.len());
    issues
}

fn is_excluded(path: &Path, exclusions: &[String]) -> bool {
    let path_str = path.to_str().unwrap_or_default();
    let path_filename = path.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    
    exclusions.iter().any(|ex| {
        // Handle glob patterns
        if ex.contains('*') {
            wildmatch::WildMatch::new(ex).matches(path_str) || 
            wildmatch::WildMatch::new(ex).matches(path_filename)
        } else {
            // Handle simple substring matching
            path_str.contains(ex) || path_filename.contains(ex)
        }
    })
}

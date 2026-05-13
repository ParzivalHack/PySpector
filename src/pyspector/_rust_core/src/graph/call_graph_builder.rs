use crate::ast_parser::{AstNode, PythonFile};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Default)]
pub struct CallGraph<'a> {
    /// Maps function ID (file::function_name) to its AST node
    pub functions: HashMap<String, &'a AstNode>,
    /// Maps function ID to set of functions it calls
    pub graph: HashMap<String, HashSet<String>>,
    /// Maps file path to file content for line extraction
    pub file_contents: HashMap<String, String>,
}

/// Returns true if a file path should be excluded from taint analysis.
/// Excluded: test files, documentation code, and example code.
///
/// These files are excluded because:
/// - Test files: test functions never receive real attacker-controlled data,
///   so they only add functions without adding security-relevant taint paths.
/// - Docs/examples: tutorial and example code uses hardcoded credentials,
///   simplified patterns, and intentional anti-patterns for illustration.
///   Including them as taint entry points produces false positives in the
///   library code being demonstrated.
fn is_test_file(file_path: &str) -> bool {
    let lower = file_path.to_lowercase();
    // Test infrastructure
    if lower.contains("/test") || lower.contains("\\test")
        || lower.starts_with("test")
        || lower.contains("/tests/") || lower.contains("\\tests\\")
        || lower.ends_with("_test.py")
        || lower.contains("/conftest") || lower.contains("\\conftest")
        || lower.contains("/fixture") || lower.contains("\\fixture")
        || (lower.contains("/mock") && lower.ends_with(".py"))
    {
        return true;
    }
    // Documentation, example code, and project maintenance scripts.
    // Entry points in these directories are for documentation or project tooling,
    // not production user-facing code. Including them as taint entry points produces
    // false positives in library code being demonstrated or maintained.
    lower.contains("/docs/") || lower.contains("\\docs\\")
        || lower.contains("/docs_src/") || lower.contains("\\docs_src\\")
        || lower.contains("/examples/") || lower.contains("\\examples\\")
        || lower.contains("/example/") || lower.contains("\\example\\")
        || lower.contains("/tutorial/") || lower.contains("\\tutorial\\")
        || lower.contains("/tutorials/") || lower.contains("\\tutorials\\")
        || lower.contains("/samples/") || lower.contains("\\samples\\")
        || lower.contains("/demo/") || lower.contains("\\demo\\")
        // Project maintenance scripts: documentation generation, release management,
        // linting/formatting, CI helpers. These are operator-run tools, not
        // user-facing entry points.
        || lower.contains("/scripts/") || lower.contains("\\scripts\\")
        || lower.starts_with("scripts/") || lower.starts_with("scripts\\")
        // Machine-generated data files — contain language docs/data as string literals.
        // They are not executable entry points; including them pollutes the call graph.
        || lower.contains("/pydoc_data/") || lower.contains("\\pydoc_data\\")
}

// Builds a call graph from all parsed Python files.
pub fn build_call_graph(py_files: &[PythonFile]) -> CallGraph {
    let production_files: Vec<&PythonFile> = py_files
        .iter()
        .filter(|f| !is_test_file(&f.file_path))
        .collect();

    println!("[*] Building call graph from {}/{} files (test files excluded from taint analysis)",
             production_files.len(), py_files.len());

    let mut call_graph = CallGraph::default();
    let mut all_funcs = HashMap::new();

    // First pass: find all function definitions.
    // Removed per-file and per-function println — 18k+ print syscalls dominated runtime.
    for file in &production_files {
        if let Some(ast) = &file.ast {
            let mut funcs_in_file = Vec::new();
            find_functions(ast, &mut funcs_in_file);

            for func_node in funcs_in_file {
                if let Some(func_name) = get_name_from_node(func_node) {
                    let func_id = format!("{}::{}", file.file_path, func_name);
                    all_funcs.insert(func_id, func_node);
                }
            }
        }
        call_graph.file_contents.insert(file.file_path.clone(), file.content.clone());
    }

    call_graph.functions = all_funcs;
    println!("[+] Found {} total functions", call_graph.functions.len());

    // Build a name index: bare_function_name → [func_id, ...] for O(1) call resolution.
    // Without this index, Pass 2 is O(functions × call_sites × functions) — O(n²).
    // With the index it's O(functions × call_sites) — O(n).
    let mut name_index: HashMap<String, Vec<String>> = HashMap::new();
    for func_id in call_graph.functions.keys() {
        // Extract bare name after "::" (may include class prefix like "ClassName.method")
        if let Some(bare) = func_id.rsplit("::").next() {
            name_index.entry(bare.to_string()).or_default().push(func_id.clone());
            // Also index just the method suffix for "ClassName.method" → "method"
            if let Some(method) = bare.rsplit('.').next() {
                if method != bare {
                    name_index.entry(method.to_string()).or_default().push(func_id.clone());
                }
            }
        }
    }

    // Second pass: resolve call sites using the O(1) index.
    for (func_id, func_node) in &call_graph.functions {
        let mut calls = HashSet::new();
        let mut call_sites = Vec::new();
        find_call_sites(func_node, &mut call_sites);

        for call_node in call_sites {
            let callee_name = get_full_call_name(call_node);
            if callee_name.is_empty() { continue; }

            // Direct lookup: exact callee name
            if let Some(targets) = name_index.get(&callee_name) {
                calls.extend(targets.iter().cloned());
            }
            // Method suffix lookup: "obj.method" → "method"
            if let Some(method) = callee_name.rsplit('.').next() {
                if method != callee_name {
                    if let Some(targets) = name_index.get(method) {
                        calls.extend(targets.iter().cloned());
                    }
                }
            }
        }
        call_graph.graph.insert(func_id.clone(), calls);
    }

    call_graph
}

// --- Helper functions ---

fn find_functions<'a>(node: &'a AstNode, functions: &mut Vec<&'a AstNode>) {
    if node.node_type == "FunctionDef" || node.node_type == "AsyncFunctionDef" {
        functions.push(node);
    }
    for child_list in node.children.values() {
        for child in child_list {
            find_functions(child, functions);
        }
    }
}

fn find_call_sites<'a>(node: &'a AstNode, sites: &mut Vec<&'a AstNode>) {
    if node.node_type == "Call" {
        sites.push(node);
    }
    for child_list in node.children.values() {
        for child in child_list {
            find_call_sites(child, sites);
        }
    }
}

fn get_name_from_node(node: &AstNode) -> Option<String> {
    // For FunctionDef/AsyncFunctionDef nodes, the function name is in 'name' field
    // For Name nodes, the identifier is in 'id' field
    node.fields.get("name")
        .or_else(|| node.fields.get("id"))
        .and_then(|v| v.as_ref())
        .and_then(|v| v.as_str().map(String::from))
}

fn get_full_call_name(call_node: &AstNode) -> String {
    if let Some(func) = call_node.children.get("func").and_then(|v| v.get(0)) {
        if func.node_type == "Name" {
            return get_name_from_node(func).unwrap_or_default();
        } else if func.node_type == "Attribute" {
            let mut parts = Vec::new();
            let mut current = func;
            while current.node_type == "Attribute" {
                if let Some(attr) = current.fields.get("attr").and_then(|v| v.as_ref()).and_then(|v| v.as_str()) {
                    parts.push(attr.to_string());
                }
                if let Some(next_node) = current.children.get("value").and_then(|v| v.get(0)) {
                    current = next_node;
                } else { break; }
            }
            if let Some(base) = get_name_from_node(current) {
                parts.push(base);
            }
            parts.reverse();
            return parts.join(".");
        }
    }
    String::new()
}
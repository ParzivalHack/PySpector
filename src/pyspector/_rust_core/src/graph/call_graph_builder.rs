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

// Builds a call graph from all parsed Python files.
pub fn build_call_graph(py_files: &[PythonFile]) -> CallGraph {
    println!("[*] Building call graph from {} files", py_files.len());
    
    let mut call_graph = CallGraph::default();
    let mut all_funcs = HashMap::new();

    // First pass: find all function definitions and store their content.
    for file in py_files {
        println!("[*] Processing file: {}", file.file_path);
        
        if let Some(ast) = &file.ast {
            let mut funcs_in_file = Vec::new();
            find_functions(ast, &mut funcs_in_file);
            
            for func_node in funcs_in_file {
                if let Some(func_name) = get_name_from_node(func_node) {
                    let func_id = format!("{}::{}", file.file_path, func_name);
                    println!("[*] Found function: {}", func_id);
                    all_funcs.insert(func_id, func_node);
                }
            }
        }
        call_graph.file_contents.insert(file.file_path.clone(), file.content.clone());
    }
    
    call_graph.functions = all_funcs;
    println!("[+] Found {} total functions", call_graph.functions.len());

    // Second pass: find all call sites in each function.
    for (func_id, func_node) in &call_graph.functions {
        let mut calls = HashSet::new();
        let mut call_sites = Vec::new();
        find_call_sites(func_node, &mut call_sites);
        
        for call_node in call_sites {
            let callee_name = get_full_call_name(call_node);
            for (potential_target_id, _) in &call_graph.functions {
                if potential_target_id.ends_with(&format!("::{}", callee_name)) {
                    calls.insert(potential_target_id.clone());
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
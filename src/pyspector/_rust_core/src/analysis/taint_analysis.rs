use crate::ast_parser::AstNode;
use crate::graph::call_graph_builder::CallGraph;
use crate::graph::cfg_builder::build_cfg;
use crate::graph::representation::{BasicBlock, BlockId, ControlFlowGraph};
use crate::issues::Issue;
use crate::rules::RuleSet;
use std::collections::{HashMap, HashSet, VecDeque};

/// Origin of a taint
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintOrigin {
    External,      // From a known source (e.g. input(), request.get())
    Param(usize),  // From a function parameter (index)
}

/// Per-block taint state: maps variable names to their taint origins
/// If a variable is not in the map, it is not tainted.
type TaintState = HashMap<String, HashSet<TaintOrigin>>;

/// Summary of a function's taint behavior
#[derive(Debug, Clone, Default, PartialEq)]
struct FunctionSummary {
    /// True if the function returns a tainted value from an external source
    returns_external_taint: bool,
    /// Set of parameter indices that flow to the return value
    param_flows_to_return: HashSet<usize>,
}

/// Global context for inter-procedural analysis
struct GlobalTaintContext {
    /// Summaries for all functions in the program
    summaries: HashMap<String, FunctionSummary>,
}

/// Context for the intra-procedural fixed-point worklist algorithm
struct TaintContext {
    /// Entry taint state for each block
    entry_states: HashMap<BlockId, TaintState>,
    /// Exit taint state for each block
    exit_states: HashMap<BlockId, TaintState>,
}

impl TaintContext {
    fn new() -> Self {
        Self {
            entry_states: HashMap::new(),
            exit_states: HashMap::new(),
        }
    }
}

// Main entry point for inter-procedural taint analysis
pub fn analyze_program_for_taint(call_graph: &CallGraph, ruleset: &RuleSet) -> Vec<Issue> {
    println!("[*] Starting inter-procedural taint analysis with {} functions", call_graph.functions.len());
    
    let mut global_ctx = GlobalTaintContext {
        summaries: HashMap::new(),
    };
    
    // Initialize summaries for all functions
    for func_id in call_graph.functions.keys() {
        global_ctx.summaries.insert(func_id.clone(), FunctionSummary::default());
    }
    
    let mut all_issues = Vec::new();
    let mut iterations = 0;
    const MAX_GLOBAL_ITERATIONS: usize = 10; 
    
    loop {
        iterations += 1;
        println!("[*] Global fixed-point iteration {}", iterations);
        let mut summaries_changed = false;
        let mut current_pass_issues = Vec::new();
        
        // Analyze each function
        for (func_id, func_node) in &call_graph.functions {
            let cfg = build_cfg(func_node);
            
            let file_path = func_id.split("::").next().unwrap_or("");
            let default_content = String::new();
            let content = call_graph.file_contents.get(file_path).unwrap_or(&default_content);
            
            let (new_summary, issues) = analyze_function_taint(
                &cfg, 
                func_node,
                ruleset, 
                file_path, 
                content,
                &global_ctx
            );
            
            if let Some(old_summary) = global_ctx.summaries.get(func_id) {
                if &new_summary != old_summary {
                    println!("[*] Summary changed for {}", func_id);
                    global_ctx.summaries.insert(func_id.clone(), new_summary);
                    summaries_changed = true;
                }
            }
            
            // Collect issues from the latest pass
            // We clear the list at the start of each global iteration so we don't duplicate
            // But we accumulate across functions in the same pass
            current_pass_issues.extend(issues);
        }
        
        if !summaries_changed || iterations >= MAX_GLOBAL_ITERATIONS {
            if summaries_changed {
                println!("[!] Warning: Max global iterations reached without convergence");
            } else {
                println!("[+] Global convergence reached after {} iterations", iterations);
            }
            all_issues = current_pass_issues;
            break;
        }
    }

    // Deduplicate issues
    let mut unique_issues = Vec::new();
    let mut seen_fingerprints = HashSet::new();
    for issue in all_issues {
        let fp = issue.get_fingerprint();
        if !seen_fingerprints.contains(&fp) {
            seen_fingerprints.insert(fp);
            unique_issues.push(issue);
        }
    }

    println!("[+] Found {} unique taint issues", unique_issues.len());
    unique_issues
}

fn analyze_function_taint(
    cfg: &ControlFlowGraph,
    func_node: &AstNode,
    ruleset: &RuleSet,
    file_path: &str,
    content: &str,
    global_ctx: &GlobalTaintContext,
) -> (FunctionSummary, Vec<Issue>) {
    let mut ctx = TaintContext::new();
    
    // Extract parameters and initialize taint state
    let params = extract_function_params(func_node);
    let mut initial_state = TaintState::new();
    
    for (idx, param_name) in params.iter().enumerate() {
        let mut origins = HashSet::new();
        origins.insert(TaintOrigin::Param(idx));
        initial_state.insert(param_name.clone(), origins);
    }
    
    // Initialize blocks
    for block_id in cfg.blocks.keys() {
        ctx.entry_states.insert(*block_id, TaintState::new());
        ctx.exit_states.insert(*block_id, TaintState::new());
    }
    
    // Set entry block state
    ctx.entry_states.insert(cfg.entry, initial_state);
    
    // Worklist algorithm
    let mut worklist: VecDeque<BlockId> = VecDeque::new();
    worklist.push_back(cfg.entry);
    let mut in_worklist: HashSet<BlockId> = HashSet::new();
    in_worklist.insert(cfg.entry);
    
    let mut iterations = 0;
    while let Some(block_id) = worklist.pop_front() {
        in_worklist.remove(&block_id);
        iterations += 1;
        if iterations > 1000 { break; }
        
        let block = match cfg.blocks.get(&block_id) {
            Some(b) => b,
            None => continue,
        };
        
        // Compute entry state
        let mut entry_state = if block_id == cfg.entry {
            ctx.entry_states.get(&cfg.entry).cloned().unwrap_or_default()
        } else {
            TaintState::new()
        };
        
        if block_id != cfg.entry {
             entry_state = compute_entry_state(block, &ctx.exit_states);
        } else {
            // Merge back-edges for entry block
            let back_edge_state = compute_entry_state(block, &ctx.exit_states);
            merge_states(&mut entry_state, &back_edge_state);
        }
        
        ctx.entry_states.insert(block_id, entry_state.clone());
        
        // Transfer function
        let (exit_state, _) = transfer_function(
            block,
            entry_state,
            ruleset,
            file_path,
            content,
            global_ctx
        );
        
        // Check change
        let prev_exit = ctx.exit_states.get(&block_id).cloned().unwrap_or_default();
        if exit_state != prev_exit {
            ctx.exit_states.insert(block_id, exit_state);
            for succ_id in block.successors.keys() {
                if !in_worklist.contains(succ_id) {
                    worklist.push_back(*succ_id);
                    in_worklist.insert(*succ_id);
                }
            }
        }
    }
    
    // Collect issues and compute summary from final state
    let mut issues = Vec::new();
    let mut summary = FunctionSummary::default();
    
    for block in cfg.blocks.values() {
        // Re-run transfer to get issues
        let entry_state = ctx.entry_states.get(&block.id).cloned().unwrap_or_default();
        let (exit_state, block_issues) = transfer_function(
            block, 
            entry_state, 
            ruleset, 
            file_path, 
            content, 
            global_ctx
        );
        issues.extend(block_issues);
        
        // Check Return statements for summary
        for stmt in &block.statements {
            if stmt.node_type == "Return" {
                if let Some(value) = stmt.children.get("value").and_then(|v| v.get(0)) {
                    // Check if return value is a direct source call
                    if value.node_type == "Call" {
                         let call_name = get_full_call_name(value);
                         if ruleset.taint_sources.iter().any(|s| call_name.contains(&s.function_call)) {
                             summary.returns_external_taint = true;
                         }
                    }
                    
                    // Check taint of returned variables
                    let names = extract_all_names(value);
                    for name in names {
                        if let Some(origins) = exit_state.get(&name) {
                            for origin in origins {
                                match origin {
                                    TaintOrigin::External => summary.returns_external_taint = true,
                                    TaintOrigin::Param(idx) => { summary.param_flows_to_return.insert(*idx); }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    (summary, issues)
}

fn compute_entry_state(
    block: &BasicBlock,
    exit_states: &HashMap<BlockId, TaintState>,
) -> TaintState {
    let mut entry_state = TaintState::new();
    
    for pred_id in &block.predecessors {
        if let Some(pred_exit) = exit_states.get(pred_id) {
            merge_states(&mut entry_state, pred_exit);
        }
    }
    
    entry_state
}

fn merge_states(target: &mut TaintState, source: &TaintState) {
    for (var, origins) in source {
        target.entry(var.clone())
            .or_insert_with(HashSet::new)
            .extend(origins.iter().cloned());
    }
}

fn transfer_function(
    block: &BasicBlock,
    mut state: TaintState,
    ruleset: &RuleSet,
    file_path: &str,
    content: &str,
    global_ctx: &GlobalTaintContext,
) -> (TaintState, Vec<Issue>) {
    let mut issues = Vec::new();
    
    for stmt in &block.statements {
        match stmt.node_type.as_str() {
            "Assign" => {
                if let Some(value_node) = stmt.children.get("value").and_then(|v| v.get(0)) {
                    let targets: Vec<String> = stmt.children.get("targets")
                        .map(|targets| {
                            targets.iter()
                                .filter_map(|t| get_name_from_node(t))
                                .collect()
                        })
                        .unwrap_or_default();
                    
                    if value_node.node_type == "Call" {
                        let call_name = get_full_call_name(value_node);
                        
                        // 1. Check for Taint Source
                        let is_source = ruleset.taint_sources.iter().any(|source| {
                            call_name.contains(&source.function_call) || 
                            source.function_call.contains(&call_name)
                        });
                        
                        if is_source {
                            for target in &targets {
                                let mut origins = HashSet::new();
                                origins.insert(TaintOrigin::External);
                                state.insert(target.clone(), origins);
                            }
                        } else {
                            // 2. Check for Sanitizer
                            let is_sanitizer = ruleset.taint_sanitizers.iter().any(|san| {
                                call_name.contains(&san.function_call) ||
                                san.function_call.contains(&call_name)
                            });
                            
                            if is_sanitizer {
                                for target in &targets {
                                    state.remove(target);
                                }
                            } else {
                                // 3. Check for Inter-procedural Taint (Summaries)
                                
                                let mut new_origins = HashSet::new();
                                
                                // Find matching summary
                                let summary = global_ctx.summaries.iter()
                                    .find(|(k, _)| k.ends_with(&format!("::{}", call_name)))
                                    .map(|(_, v)| v);
                                
                                if let Some(summary) = summary {
                                    if summary.returns_external_taint {
                                        new_origins.insert(TaintOrigin::External);
                                    }
                                    
                                    // Check flow from arguments
                                    if let Some(args) = value_node.children.get("args") {
                                        for &param_idx in &summary.param_flows_to_return {
                                            if let Some(arg) = args.get(param_idx) {
                                                let arg_names = extract_all_names(arg);
                                                for name in arg_names {
                                                    if let Some(origins) = state.get(&name) {
                                                        new_origins.extend(origins.iter().cloned());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    // Fallback: Conservative propagation if unknown function
                                    if check_args_tainted(value_node, &state) {
                                        // We propagate the origins from args
                                        if let Some(args) = value_node.children.get("args") {
                                            for arg in args {
                                                let names = extract_all_names(arg);
                                                for name in names {
                                                    if let Some(origins) = state.get(&name) {
                                                        new_origins.extend(origins.iter().cloned());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                if !new_origins.is_empty() {
                                    for target in &targets {
                                        state.insert(target.clone(), new_origins.clone());
                                    }
                                }
                            }
                        }
                    } else {
                        // Transitive propagation (Assignment)
                        let mut new_origins = HashSet::new();
                        let src_names = extract_all_names(value_node);
                        for name in src_names {
                            if let Some(origins) = state.get(&name) {
                                new_origins.extend(origins.iter().cloned());
                            }
                        }
                        
                        if !new_origins.is_empty() {
                            for target in &targets {
                                state.insert(target.clone(), new_origins.clone());
                            }
                        }
                    }
                }
            }
            "Expr" => {
                if let Some(value) = stmt.children.get("value").and_then(|v| v.get(0)) {
                    if value.node_type == "Call" {
                        check_sink_and_report(value, &state, ruleset, file_path, content, &mut issues);
                        
                        // Sanitizer as standalone statement
                    }
                }
            }
            _ => {
                let mut call_sites = Vec::new();
                find_call_sites(stmt, &mut call_sites);
                for call_node in call_sites {
                    check_sink_and_report(call_node, &state, ruleset, file_path, content, &mut issues);
                }
            }
        }
    }
    
    (state, issues)
}

fn check_sink_and_report(
    call_node: &AstNode,
    state: &TaintState,
    ruleset: &RuleSet,
    file_path: &str,
    content: &str,
    issues: &mut Vec<Issue>,
) {
    let call_name = get_full_call_name(call_node);
    
    for sink in &ruleset.taint_sinks {
        if call_name.contains(&sink.function_call) || sink.function_call.contains(&call_name) {
            if let Some(args) = call_node.children.get("args") {
                if args.len() > sink.vulnerable_parameter_index {
                    let arg = &args[sink.vulnerable_parameter_index];
                    let arg_names = extract_all_names(arg);
                    
                    for name in arg_names {
                        if let Some(_origins) = state.get(&name) {
                            // We found a tainted variable flowing to a sink
                            
                            println!("[!] VULNERABILITY: Tainted variable '{}' flows to sink '{}'", name, call_name);
                            report_issue(ruleset, &sink.vulnerability_id, file_path, call_node, content, issues);
                            break; // Report once per sink call
                        }
                    }
                }
            }
        }
    }
}

fn check_args_tainted(call_node: &AstNode, state: &TaintState) -> bool {
    if let Some(args) = call_node.children.get("args") {
        for arg in args {
            let names = extract_all_names(arg);
            if names.iter().any(|name| state.contains_key(name)) {
                return true;
            }
        }
    }
    false
}

fn extract_function_params(func_node: &AstNode) -> Vec<String> {
    let mut params = Vec::new();
    if let Some(args_node) = func_node.children.get("args").and_then(|v| v.get(0)) {
        if let Some(args_list) = args_node.children.get("args") {
            for arg in args_list {
                if let Some(name) = arg.fields.get("arg").and_then(|v| v.as_ref()).and_then(|v| v.as_str()) {
                    params.push(name.to_string());
                }
            }
        }
    }
    params
}

fn extract_all_names(node: &AstNode) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(name) = get_name_from_node(node) {
        names.push(name);
    }
    for child_list in node.children.values() {
        for child in child_list {
            names.extend(extract_all_names(child));
        }
    }
    names
}

// --- Helper functions ---

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
    match node.node_type.as_str() {
        "Name" => node.fields.get("id").and_then(|v| v.as_ref()).and_then(|v| v.as_str().map(String::from)),
        "Attribute" => node.fields.get("attr").and_then(|v| v.as_ref()).and_then(|v| v.as_str().map(String::from)),
        _ => None
    }
}

fn get_full_call_name(call_node: &AstNode) -> String {
    if let Some(func) = call_node.children.get("func").and_then(|v| v.get(0)) {
        match func.node_type.as_str() {
            "Name" => return get_name_from_node(func).unwrap_or_default(),
            "Attribute" => {
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
            _ => {}
        }
    }
    String::new()
}

fn report_issue(ruleset: &RuleSet, vuln_id: &str, file_path: &str, stmt: &AstNode, content: &str, issues: &mut Vec<Issue>) {
    if let Some(vuln_rule) = ruleset.rules.iter().find(|r| r.id == vuln_id) {
        let line_content = content.lines().nth(stmt.lineno.saturating_sub(1) as usize).unwrap_or("").to_string();
        issues.push(Issue::new(
            vuln_rule.id.clone(),
            vuln_rule.description.clone(),
            file_path.to_string(),
            stmt.lineno as usize,
            line_content,
            vuln_rule.severity.clone(),
            vuln_rule.confidence.clone(),
            vuln_rule.remediation.clone(),
        ));
    }
}
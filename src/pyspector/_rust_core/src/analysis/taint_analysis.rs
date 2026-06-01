use crate::ast_parser::AstNode;
use crate::graph::call_graph_builder::CallGraph;
use crate::graph::cfg_builder::build_cfg;
use crate::graph::representation::{BasicBlock, BlockId, ControlFlowGraph};
use crate::issues::Issue;
use crate::rules::RuleSet;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};

/// Provenance of a value — universal Python semantics, no framework knowledge.
///
/// The provenance lattice (least trusted → most trusted):
///   HttpRequest → ShellSanitized → OperatorConfig → DeveloperDefined / SystemGenerated
///
/// HttpRequest and ShellSanitized are attacker-controlled (trigger most sinks).
/// ShellSanitized specifically does NOT trigger shell injection sinks (PY102/SHELL*).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintOrigin {
    /// Attacker-controlled: request.GET.get(), request.POST, cookies, body,
    /// HTTP API responses (.json(), iter_lines()), CLI arguments.
    HttpRequest,

    /// Attacker-controlled data that has been through shlex.quote().
    /// Safe for shell metacharacter injection (PY102) — shlex.quote prevents that.
    /// Still dangerous for: path traversal (PATH813), f-string injection (FSTRING867),
    /// file open (OPEN1149), URL injection (SSRF_001), SQL injection (PY101).
    ShellSanitized,

    /// Attacker-controlled data that has been through html.escape() or format_html().
    /// Safe for HTML XSS — still dangerous for SQL, shell, path, URLs.
    HtmlSanitized,

    /// Attacker-controlled data that has been through quote_name() or similar SQL sanitizers.
    /// Safe for SQL identifier injection — still dangerous for shell, path, HTML.
    SqlSanitized,

    /// Operator-controlled: os.environ.get(), config files loaded at startup.
    OperatorConfig,

    /// Developer-defined: string literals, class attributes, module constants.
    DeveloperDefined,

    /// System-generated: tempfile.*, uuid4(), os.urandom(), secrets.*.
    SystemGenerated,

    // Legacy — kept for backward compatibility
    External,
    Param(usize),
}

impl TaintOrigin {
    /// True if this origin is attacker-controlled and should trigger sink findings.
    ///
    /// HtmlSanitized and SqlSanitized are NOT attacker-controlled for general sinks:
    /// - html.escape/format_html/conditional_escape are complete XSS mitigations
    /// - quote_name is a complete SQL injection mitigation
    /// These sanitizers clear taint for all sinks — they were comprehensive mitigations.
    ///
    /// ShellSanitized IS still attacker-controlled for non-shell sinks:
    /// - shlex.quote prevents shell injection but NOT path traversal, f-string, SSRF, SQL
    /// - So ShellSanitized data still triggers PATH813, OPEN1149, FSTRING867, SSRF_001, PY101
    pub fn is_attacker_controlled(&self) -> bool {
        matches!(self,
            TaintOrigin::HttpRequest |
            TaintOrigin::External |
            TaintOrigin::ShellSanitized
        )
    }

    /// True only for HttpRequest/External — not ShellSanitized.
    /// Used by shell injection sinks (PY102, SHELL*): shlex.quote is a valid mitigation.
    pub fn is_shell_injectable(&self) -> bool {
        matches!(self, TaintOrigin::HttpRequest | TaintOrigin::External)
    }

    /// True if this origin should still trigger SQL sinks.
    /// ShellSanitized is still SQL-injectable (shlex.quote doesn't sanitize SQL).
    pub fn is_sql_injectable(&self) -> bool {
        matches!(self, TaintOrigin::HttpRequest | TaintOrigin::External | TaintOrigin::ShellSanitized)
    }

    /// Convert a sanitizer's transforms_to string to a TaintOrigin.
    pub fn from_transforms_to(s: &str) -> Option<Self> {
        match s {
            "ShellSanitized" => Some(TaintOrigin::ShellSanitized),
            "HtmlSanitized"  => Some(TaintOrigin::HtmlSanitized),
            "SqlSanitized"   => Some(TaintOrigin::SqlSanitized),
            _                => None,
        }
    }
}

/// Per-block taint state: maps variable names to their taint origins.
/// If a variable is not in the map, it is untainted (safe).
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

    /// Call-site taint: maps callee function name → per-parameter taint origins.
    call_site_taints: HashMap<String, Vec<HashSet<TaintOrigin>>>,

    /// Class attribute taint: maps (file_prefix, attr_name) → taint origins.
    class_attr_taints: HashMap<(String, String), HashSet<TaintOrigin>>,

    /// CFG cache: pre-built control flow graphs for all functions.
    /// build_cfg() is expensive (AST traversal + graph construction).
    /// Caching avoids rebuilding the same CFG in each iteration and the final pass.
    cfg_cache: HashMap<String, ControlFlowGraph>,
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
    let t0 = std::time::Instant::now();
    println!("[*] Starting inter-procedural taint analysis with {} functions", call_graph.functions.len());

    // Pre-build all CFGs once — reuse across convergence iterations and final pass.
    // Parallel build using Rayon: each function's CFG is independent.
    println!("[*] Pre-building CFGs for {} functions (parallel)...", call_graph.functions.len());
    let cfg_cache: HashMap<String, ControlFlowGraph> = call_graph.functions
        .par_iter()
        .map(|(func_id, func_node)| (func_id.clone(), build_cfg(func_node)))
        .collect();
    println!("[*] CFG pre-build: {:.2}s", t0.elapsed().as_secs_f64());

    let mut global_ctx = GlobalTaintContext {
        summaries: HashMap::new(),
        call_site_taints: HashMap::new(),
        class_attr_taints: HashMap::new(),
        cfg_cache,
    };

    // Initialize summaries for all functions
    for func_id in call_graph.functions.keys() {
        global_ctx.summaries.insert(func_id.clone(), FunctionSummary::default() as FunctionSummary);
    }
    
    let mut all_issues = Vec::new();
    let mut iterations = 0;
    const MAX_GLOBAL_ITERATIONS: usize = 10;

    // Pre-compute which files contain any taint source marker.
    // Functions in files with NO taint markers cannot have internal taint sources —
    // they may only receive taint from callers (handled by lazy call_site_taint filter).
    // This pre-filter eliminates ~80% of function analyses in typical codebases.
    const FILE_TAINT_MARKERS: &[&str] = &[
        // Django request access
        "request.GET", "request.POST", "request.FILES", "request.COOKIES",
        "request.META", "request.headers",
        // Flask / generic request
        "request.get(", "request.args", "request.form",
        "request.values", "request.json",
        // Environment / CLI
        "os.environ.get", "sys.argv",
        // HTTP streaming
        ".iter_lines", ".iter_text", ".iter_raw", ".iter_bytes",
        // Deserialization
        "marshal.loads", "json.load(", "json.loads(",
        ".json()",       // HTTP response .json() method
        "input(",        // CLI interactive input
    ];

    let taint_active_files: std::collections::HashSet<&str> = call_graph.file_contents
        .iter()
        .filter(|(_, content)| FILE_TAINT_MARKERS.iter().any(|m| content.contains(m)))
        .map(|(path, _)| path.as_str())
        .collect();

    println!("[*] Taint-active files: {}/{} ({:.0}% of total)",
             taint_active_files.len(),
             call_graph.file_contents.len(),
             100.0 * taint_active_files.len() as f64 / call_graph.file_contents.len().max(1) as f64);

    let t_convergence = std::time::Instant::now();
    loop {
        let t_iter = std::time::Instant::now();
        iterations += 1;
        let mut summaries_changed = false;
        let mut current_pass_issues: Vec<Issue> = Vec::new();

        // Analyze functions IN PARALLEL using Rayon.
        // Each function reads global_ctx (immutable snapshot of this iteration's state)
        // and returns (func_id, summary, call_sites, class_attrs).
        // Results are merged serially after all parallel analyses complete.
        let files_with_class_attr_taints: std::collections::HashSet<&str> = global_ctx.class_attr_taints
            .keys()
            .filter(|(_, _)| true)
            .map(|(file, _)| file.as_str())
            .collect();

        let iter_results: Vec<(String, FunctionSummary,
                                HashMap<String, Vec<HashSet<TaintOrigin>>>,
                                HashMap<(String, String), HashSet<TaintOrigin>>)> =
            call_graph.functions
                .par_iter()
                .filter(|(func_id, func_node)| {
                    if iterations == 1 { return true; }
                    let func_name = func_node.fields.get("name")
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
                        .unwrap_or("");
                    let file_path = func_id.split("::").next().unwrap_or("");
                    !extract_cli_tainted_params(func_node).is_empty()
                        || (global_ctx.call_site_taints.contains_key(func_name)
                            && global_ctx.call_site_taints[func_name].iter().any(|s| !s.is_empty()))
                        || files_with_class_attr_taints.contains(file_path)
                })
                .map(|(func_id, func_node)| {
                    let cfg_owned;
                    let cfg = match global_ctx.cfg_cache.get(func_id.as_str()) {
                        Some(c) => c,
                        None => { cfg_owned = build_cfg(func_node); &cfg_owned }
                    };
                    let file_path: &str = func_id.split("::").next().unwrap_or("");
                    let default_content = String::new();
                    let content = call_graph.file_contents.get(file_path)
                        .unwrap_or(&default_content);
                    let (summary, call_sites, class_attrs, _issues) =
                        analyze_function_taint(&cfg, func_node, ruleset, file_path, content, &global_ctx);
                    (func_id.clone(), summary, call_sites, class_attrs)
                })
                .collect();

        // Serial merge of parallel results into global_ctx
        for (func_id, new_summary, new_call_sites, new_class_attrs) in iter_results {
            for (callee, param_taints) in new_call_sites {
                let entry = global_ctx.call_site_taints
                    .entry(callee)
                    .or_insert_with(Vec::new);
                let mut changed = false;
                for (i, origins) in param_taints.iter().enumerate() {
                    if i >= entry.len() { entry.resize(i + 1, HashSet::new()); }
                    let before_len = entry[i].len();
                    entry[i].extend(origins.iter().cloned());
                    if entry[i].len() > before_len { changed = true; }
                }
                if changed { summaries_changed = true; }
            }
            for (key, origins) in new_class_attrs {
                let entry = global_ctx.class_attr_taints
                    .entry(key).or_insert_with(HashSet::new);
                let before_len = entry.len();
                entry.extend(origins.iter().cloned());
                if entry.len() > before_len { summaries_changed = true; }
            }
            if let Some(old_summary) = global_ctx.summaries.get(&func_id) {
                if &new_summary != old_summary {
                    println!("[*] Summary changed for {}", func_id);
                    global_ctx.summaries.insert(func_id.clone(), new_summary);
                    summaries_changed = true;
                }
            }
        }

        println!("[*] Iteration {} done in {:.2}s", iterations, t_iter.elapsed().as_secs_f64());
        if !summaries_changed || iterations >= MAX_GLOBAL_ITERATIONS {
            if summaries_changed {
                println!("[!] Warning: Max global iterations reached without convergence");
            } else {
                println!("[+] Global convergence reached after {} iterations in {:.2}s total",
                         iterations, t_convergence.elapsed().as_secs_f64());
            }
            break;
        }
    }

    // ── Final issue collection pass ──────────────────────────────────────────
    // After convergence: collect issues using the converged global_ctx.
    //
    // Optimization: for large codebases (>5k functions), apply a file-level
    // pre-filter to skip the ~80% of functions in files with no taint markers.
    // These functions cannot produce findings since they have no taint sources.
    // For small codebases, the filter overhead outweighs the savings — use
    // the simpler full par_iter which has lower overhead.
    const FILE_FILTER_THRESHOLD: usize = 5_000;
    let use_file_filter = call_graph.functions.len() > FILE_FILTER_THRESHOLD;

    let t_final_start = std::time::Instant::now();
    let parallel_issues: Vec<Vec<Issue>> = if use_file_filter {
        let final_func_ids: Vec<&String> = call_graph.functions
            .keys()
            .filter(|func_id| {
                let file_path = func_id.split("::").next().unwrap_or("");
                if taint_active_files.contains(file_path) { return true; }
                if let Some(func_node) = call_graph.functions.get(*func_id) {
                    if !extract_cli_tainted_params(func_node).is_empty() { return true; }
                    let func_name = func_node.fields.get("name")
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_str()).unwrap_or("");
                    if global_ctx.call_site_taints.contains_key(func_name)
                        && global_ctx.call_site_taints[func_name].iter().any(|s| !s.is_empty()) {
                        return true;
                    }
                }
                false
            })
            .collect();
        println!("[*] Final pass (parallel+filter): {}/{} functions ({}% filtered out)",
                 final_func_ids.len(), call_graph.functions.len(),
                 100 - 100 * final_func_ids.len() / call_graph.functions.len().max(1));
        final_func_ids
            .par_iter()
            .filter_map(|func_id| call_graph.functions.get(*func_id).map(|fn_node| {
                let cfg_owned;
                let cfg = match global_ctx.cfg_cache.get(*func_id) {
                    Some(c) => c,
                    None => { cfg_owned = build_cfg(fn_node); &cfg_owned }
                };
                let file_path: &str = func_id.split("::").next().unwrap_or("");
                let default_content = String::new();
                let content = call_graph.file_contents.get(file_path).unwrap_or(&default_content);
                let (_, _, _, issues) = analyze_function_taint(
                    &cfg, fn_node, ruleset, file_path, content, &global_ctx
                );
                issues
            }))
            .collect()
    } else {
        let t_final = t_final_start;
        println!("[*] Final pass (parallel): {} functions...", call_graph.functions.len());
        let result = call_graph.functions
            .par_iter()
            .map(|(func_id, func_node)| {
                let cfg_owned;
                let cfg = match global_ctx.cfg_cache.get(func_id.as_str()) {
                    Some(c) => c,
                    None => { cfg_owned = build_cfg(func_node); &cfg_owned }
                };
                let file_path: &str = func_id.split("::").next().unwrap_or("");
                let default_content = String::new();
                let content = call_graph.file_contents.get(file_path).unwrap_or(&default_content);
                let (_, _, _, issues) = analyze_function_taint(
                    &cfg, func_node, ruleset, file_path, content, &global_ctx
                );
                issues
            })
            .collect();
        println!("[*] Final pass done in {:.2}s", t_final.elapsed().as_secs_f64());
        result
    };
    for issues in parallel_issues {
        all_issues.extend(issues);
    }
    println!("[*] Total taint analysis: {:.2}s", t0.elapsed().as_secs_f64());

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

/// Return type: (summary, call_site_taints, class_attr_taints, issues)
/// - call_site_taints: Map<callee_name, Vec<taint_per_param>> — collected at each call site
/// - class_attr_taints: Map<(file, attr), origins> — from `self.attr = tainted` assignments
fn analyze_function_taint(
    cfg: &ControlFlowGraph,
    func_node: &AstNode,
    ruleset: &RuleSet,
    file_path: &str,
    content: &str,
    global_ctx: &GlobalTaintContext,
) -> (FunctionSummary, HashMap<String, Vec<HashSet<TaintOrigin>>>, HashMap<(String, String), HashSet<TaintOrigin>>, Vec<Issue>) {
    let mut ctx = TaintContext::new();
    
    // Extract parameters and initialize taint state
    let params = extract_function_params(func_node);
    let mut initial_state = TaintState::new();
    
    // Seed 1: decorator-detected entry-point parameters.
    let entry_params = extract_cli_tainted_params(func_node);
    // HTTP params (routes, API endpoints) → HttpRequest: attacker-controlled via network
    for param in &entry_params.http {
        let mut origins = HashSet::new();
        origins.insert(TaintOrigin::HttpRequest);
        initial_state.insert(param.clone(), origins);
    }
    // CLI params (commands, options) → OperatorConfig: trusted operator chose these.
    // Sinks like PATH813/SSRF/PY102 check is_attacker_controlled() which returns false
    // for OperatorConfig, so they won't fire. FILE_DESERIALIZERS will upgrade file
    // *contents* to HttpRequest, preserving supply-chain detection.
    for param in &entry_params.operator {
        let mut origins = HashSet::new();
        origins.insert(TaintOrigin::OperatorConfig);
        initial_state.insert(param.clone(), origins);
    }

    // Seed 2: inter-procedural call-site taint — if callers passed tainted args,
    // seed the matching parameters with their accumulated taint.
    //
    // Self-offset: for methods where params[0] is "self" or "cls", call-site args
    // are indexed without self (caller writes `obj.method(arg0)`, not `method(self, arg0)`).
    // Shift recorded arg indices by 1 to align with the method's param list.
    let func_name = func_node.fields.get("name")
        .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
        .unwrap_or("");
    let self_offset = params.first().map(|p| p == "self" || p == "cls").unwrap_or(false) as usize;
    if let Some(param_taints) = global_ctx.call_site_taints.get(func_name) {
        for (i, origins) in param_taints.iter().enumerate() {
            if !origins.is_empty() {
                let param_idx = i + self_offset;
                if let Some(param_name) = params.get(param_idx) {
                    let entry = initial_state.entry(param_name.clone()).or_insert_with(HashSet::new);
                    entry.extend(origins.iter().cloned());
                }
            }
        }
    }

    // Seed 3: class attribute taint — if any method of this class (same file)
    // assigned `self.attr = tainted` AND this function was seeded by call-site
    // taint (i.e. it's in the taint chain), propagate those attributes here.
    //
    // Seed class attribute taints — always seed for same-file methods.
    // Class attributes represent shared state within a class. Any method that could
    // access these attributes should see their taint, regardless of whether it has
    // initial_state. Scope guard was removed because cross-file FPs are caused by
    // inter-proc arg propagation, not class_attr_taints seeding.
    for ((attr_file, attr_name), origins) in &global_ctx.class_attr_taints {
        if attr_file == file_path && !origins.is_empty() {
            let key = format!("self.{}", attr_name);
            let entry = initial_state.entry(key).or_insert_with(HashSet::new);
            entry.extend(origins.iter().cloned());
            // Seed bare attr name for BinOp like `base / self.output_dir`
            let entry2 = initial_state.entry(attr_name.clone()).or_insert_with(HashSet::new);
            entry2.extend(origins.iter().cloned());
        }
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
    
    // Collect issues, summary, call-site taints, and class-attr taints
    let mut issues = Vec::new();
    let mut summary = FunctionSummary::default();
    // call_site_taints: callee_func_name → per-arg taint origins
    let mut call_site_taints: HashMap<String, Vec<HashSet<TaintOrigin>>> = HashMap::new();
    // class_attr_taints: (file, attr_name) → origins from `self.attr = tainted`
    let mut class_attr_taints: HashMap<(String, String), HashSet<TaintOrigin>> = HashMap::new();

    for block in cfg.blocks.values() {
        let entry_state = ctx.entry_states.get(&block.id).cloned().unwrap_or_default();
        let (exit_state, block_issues) = transfer_function(
            block,
            entry_state.clone(),
            ruleset,
            file_path,
            content,
            global_ctx
        );
        issues.extend(block_issues);

        // Scan all statements for:
        // 1. Function calls with tainted arguments → record call-site taint
        // 2. self.attr = tainted assignments → record class attr taint
        // 3. Return statements → update function summary
        // Use exit_state as running_state so we see all assignments in the block.
        // This is conservative (uses end-of-block state for all stmts) but avoids
        // false negatives from forward assignments in the same block.
        let running_state = exit_state.clone();
        for stmt in &block.statements {
            // Track self.attr = tainted assignments
            if stmt.node_type == "Assign" {
                // Check targets for `self.attr` pattern
                if let Some(targets) = stmt.children.get("targets") {
                    for target in targets {
                        if target.node_type == "Attribute" {
                            let attr_name = target.fields.get("attr")
                                .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
                                .unwrap_or("");
                            let is_self = target.children.get("value")
                                .and_then(|v| v.get(0))
                                .and_then(|v| v.fields.get("id"))
                                .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
                                .map(|s| s == "self")
                                .unwrap_or(false);
                            if is_self && !attr_name.is_empty() {
                                // Get the value being assigned and check if it's tainted
                                if let Some(val) = stmt.children.get("value").and_then(|v| v.get(0)) {
                                    let val_names = extract_all_names(val);
                                    let mut origins: HashSet<TaintOrigin> = HashSet::new();
                                    for name in &val_names {
                                        if let Some(o) = running_state.get(name) {
                                            origins.extend(o.iter().filter(|o| o.is_attacker_controlled()).cloned());
                                        }
                                    }
                                    if !origins.is_empty() {
                                        class_attr_taints
                                            .entry((file_path.to_string(), attr_name.to_string()))
                                            .or_insert_with(HashSet::new)
                                            .extend(origins.iter().cloned());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Track function calls with tainted arguments → call-site taint
            // Record under both the full name AND the bare method name so that
            // p.initialize(config) registers as call_site_taints["initialize"][0].
            let mut call_nodes: Vec<&AstNode> = Vec::new();
            find_call_sites(stmt, &mut call_nodes);
            for call_node in call_nodes {
                let call_name = get_full_call_name(call_node);
                if call_name.is_empty() { continue; }

                // The lookup key(s) to record taint under:
                // - For bare call `f(x)`: just "f"
                // - For method `obj.method(x)`: both "obj.method" and "method"
                let lookup_names: Vec<String> = if call_name.contains('.') {
                    let method_part = call_name.rsplit('.').next().unwrap_or("").to_string();
                    if method_part.is_empty() { vec![call_name.clone()] }
                    else { vec![call_name.clone(), method_part] }
                } else {
                    vec![call_name.clone()]
                };

                if let Some(args) = call_node.children.get("args") {
                    let mut param_taints: Vec<HashSet<TaintOrigin>> = Vec::new();
                    for arg in args {
                        let mut origins: HashSet<TaintOrigin> = HashSet::new();
                        for name in extract_all_names(arg) {
                            if let Some(o) = running_state.get(&name) {
                                origins.extend(o.iter().filter(|o| o.is_attacker_controlled()).cloned());
                            }
                        }
                        param_taints.push(origins);
                    }
                    if param_taints.iter().any(|o| !o.is_empty()) {
                        for key in &lookup_names {
                            let entry = call_site_taints
                                .entry(key.clone())
                                .or_insert_with(Vec::new);
                            let needed = param_taints.len();
                            if entry.len() < needed { entry.resize(needed, HashSet::new()); }
                            for (i, origins) in param_taints.iter().enumerate() {
                                entry[i].extend(origins.iter().cloned());
                            }
                        }
                    }
                }
            }

            // running_state = exit_state (already set above, no per-stmt update needed)
        }

        // Check Return statements for summary using exit_state
        // Also check for sinks inside return values (e.g. `return FunctionType(tainted_code, ...)`)
        for stmt in &block.statements {
            if stmt.node_type == "Return" {
                if let Some(value) = stmt.children.get("value").and_then(|v| v.get(0)) {
                    if value.node_type == "Call" {
                        // Check if return value is a sink with tainted argument
                        check_sink_and_report(value, &exit_state, ruleset, file_path, content, &mut issues);

                        let call_name = get_full_call_name(value);
                        let is_src = ruleset.taint_sources.iter().any(|s| {
                            if s.function_call.contains('.') {
                                call_name.contains(&s.function_call) ||
                                s.function_call.contains(&call_name)
                            } else {
                                call_name == s.function_call
                            }
                        });
                        if is_src { summary.returns_external_taint = true; }
                    }
                    let names = extract_all_names(value);
                    for name in names {
                        if let Some(origins) = exit_state.get(&name) {
                            for origin in origins {
                                match origin {
                                    TaintOrigin::External | TaintOrigin::HttpRequest =>
                                        summary.returns_external_taint = true,
                                    TaintOrigin::Param(idx) =>
                                        { summary.param_flows_to_return.insert(*idx); }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    (summary, call_site_taints, class_attr_taints, issues)
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

                    // --- Phase 2: Subscript taint sources ---
                    // Handles: attr = request.GET['key']  (Subscript node, not a Call)
                    if value_node.node_type == "Subscript" {
                        let container = get_subscript_container(value_node);
                        // HTTP request containers — attacker-controlled
                        const HTTP_CONTAINERS: &[&str] = &[
                            "request.GET", "request.POST", "request.FILES",
                            "request.COOKIES", "request.META", "request.headers",
                            "request.args", "request.form", "request.values",
                            "request.json",
                        ];
                        // Operator-supplied containers — trusted (CLI, env config)
                        // sys.argv is set by whoever invokes the program (the operator).
                        // os.environ is set by the deployment environment (the operator).
                        // Neither is attacker-controlled in the HTTP threat model.
                        const OPERATOR_CONTAINERS: &[&str] = &[
                            "sys.argv", "os.environ",
                        ];
                        if HTTP_CONTAINERS.iter().any(|tc| container.contains(tc)) {
                            let mut origins = HashSet::new();
                            origins.insert(TaintOrigin::External);
                            for target in &targets {
                                state.insert(target.clone(), origins.clone());
                            }
                        } else if OPERATOR_CONTAINERS.iter().any(|tc| container.contains(tc)) {
                            let mut origins = HashSet::new();
                            origins.insert(TaintOrigin::OperatorConfig);
                            for target in &targets {
                                state.insert(target.clone(), origins.clone());
                            }
                        } else {
                            let mut new_origins = HashSet::new();

                            // Propagate taint from the subscript base if already tainted
                            // e.g. data = tainted_dict['key'] → data is tainted
                            let base_names = get_subscript_base_names(value_node);
                            for name in &base_names {
                                if let Some(origins) = state.get(name.as_str()) {
                                    new_origins.extend(origins.iter().cloned());
                                }
                            }

                            // Also: if the subscript base is itself a taint source CALL,
                            // the subscript result is tainted.
                            // e.g. msg = r.json()["key"] → r.json() is a taint source → msg tainted
                            if let Some(base_value) = value_node.children.get("value").and_then(|v| v.get(0)) {
                                if base_value.node_type == "Call" {
                                    let base_call_name = get_full_call_name(base_value);
                                    let is_base_source = !base_call_name.is_empty() &&
                                        ruleset.taint_sources.iter().any(|source| {
                                            if source.function_call.contains('.') {
                                                base_call_name.contains(&source.function_call) ||
                                                source.function_call.contains(&base_call_name)
                                            } else {
                                                base_call_name == source.function_call
                                            }
                                        });
                                    if is_base_source {
                                        new_origins.insert(TaintOrigin::HttpRequest);
                                    }
                                }
                            }

                            if !new_origins.is_empty() {
                                for target in &targets {
                                    state.insert(target.clone(), new_origins.clone());
                                }
                            }
                        }
                    } else if value_node.node_type == "Call" {
                        let call_name = get_full_call_name(value_node);
                        
                        // 1. Check for Taint Source
                        let is_source = !call_name.is_empty() && ruleset.taint_sources.iter().any(|source| {
                            if source.function_call.contains('.') {
                                call_name.contains(&source.function_call) ||
                                source.function_call.contains(&call_name)
                            } else {
                                call_name == source.function_call
                            }
                        });
                        
                        // Check for SystemGenerated sources — tempfile/uuid/secrets
                        // These are never attacker-controlled regardless of framework
                        const SYSTEM_GENERATED_CALLS: &[&str] = &[
                            "tempfile.", "uuid.", "secrets.", "os.urandom",
                            "random.randbytes", "hashlib.new",
                        ];
                        let is_system_generated = !call_name.is_empty() &&
                            SYSTEM_GENERATED_CALLS.iter().any(|sg| call_name.starts_with(sg) || call_name == *sg);

                        // json.load(f) is an independent taint source: file contents can
                        // come from third parties (plugins, packages) even if the file PATH
                        // is operator-chosen. This allows CLI decorator params to be
                        // OperatorConfig (trusted) while still catching supply-chain attacks
                        // via loaded config files.
                        // json.loads (string parsing) is taint-PRESERVING instead — the
                        // string's own trust level determines the output trust level.
                        const FILE_DESERIALIZERS: &[&str] = &[
                            "json.load",    // reads from file handle — contents are external
                            "yaml.load",    // reads from file — check separate for SafeLoader
                            "toml.load",    // reads from file
                            "pickle.load",  // reads from file (also caught by PY301 pattern)
                        ];
                        let is_file_deserializer = !call_name.is_empty() &&
                            FILE_DESERIALIZERS.iter().any(|fd| call_name.contains(fd));

                        // Type conversion wrappers and deserializers that preserve taint:
                        // list(), tuple(), json.load(f), etc. — output has the same trust
                        // level as input. Propagate taint from first argument.
                        // INTENTIONALLY NARROW: only type conversions that preserve the
                        // data identity (list/tuple/set) AND JSON deserialization.
                        // Do NOT include sorted/reversed/enumerate/zip/map/filter —
                        // those push taint into DoS/join/sorted rules and produce
                        // massive false positives across large codebases.
                        const TAINT_PRESERVING_CALLS: &[&str] = &[
                            "list", "tuple", "set", "frozenset",
                            "json.loads",
                            // Regex operations propagate taint from input to match objects
                            "re.search", "re.match", "re.fullmatch",
                            "re.findall", "re.finditer",
                            "group", "groups", "groupdict",
                            // Path construction/normalization — taint from any component
                            // propagates to the result. os.path.join(base, user_path) and
                            // Path(user_path) both carry the taint forward to file-operation sinks.
                            "os.path.join", "os.path.normpath", "os.path.abspath",
                            // pathlib.Path constructor: Path(tainted_str) → tainted Path object
                            // → .read_text(), .write_text(), .open() etc. fire PATH813/OPEN1149
                            "Path", "PurePath", "PosixPath", "WindowsPath",
                            // URL parsing/construction: taint flows through URL manipulation.
                            // os.environ["CI_URL"] → urlsplit() → _replace() → urlunsplit() →
                            // git fetch <url>  triggers ENV_GIT_URL001 / PY102 / SSRF_001.
                            "urlsplit", "urlunsplit", "urlparse", "urlunparse",
                            "urljoin", "urlencode",
                            "urllib.parse.urlsplit", "urllib.parse.urlunsplit",
                            "urllib.parse.urlparse", "urllib.parse.urlunparse",
                            "urllib.parse.urljoin", "urllib.parse.urlencode",
                        ];
                        // Match both exact names (re.match) and method suffixes (m.group → .group)
                        let is_taint_preserving = !call_name.is_empty() &&
                            TAINT_PRESERVING_CALLS.iter().any(|tp| {
                                call_name == *tp ||
                                call_name.ends_with(&format!(".{}", tp))
                            });

                        if is_taint_preserving {
                            // Propagate taint from arguments to the result
                            if let Some(args) = value_node.children.get("args") {
                                let mut new_origins: HashSet<TaintOrigin> = HashSet::new();
                                for arg in args {
                                    for name in extract_all_names(arg) {
                                        if let Some(origins) = state.get(&name) {
                                            new_origins.extend(origins.iter().cloned());
                                        }
                                    }
                                }
                                if !new_origins.is_empty() {
                                    for target in &targets {
                                        state.insert(target.clone(), new_origins.clone());
                                    }
                                }
                            }
                        } else if is_system_generated {
                            for target in &targets {
                                let mut origins = HashSet::new();
                                origins.insert(TaintOrigin::SystemGenerated);
                                state.insert(target.clone(), origins);
                            }
                        } else if is_file_deserializer || is_source {
                            // Operator-config call sources: os.environ.get(), os.getenv()
                            // These read values set by the deployment operator, not by
                            // HTTP request senders.
                            const OPERATOR_CALL_SOURCES: &[&str] = &[
                                "os.environ.get", "os.getenv", "os.environ[",
                            ];
                            let is_operator_source = !call_name.is_empty() &&
                                OPERATOR_CALL_SOURCES.iter().any(|op| call_name.contains(op));

                            if is_operator_source {
                                for target in &targets {
                                    let mut origins = HashSet::new();
                                    origins.insert(TaintOrigin::OperatorConfig);
                                    state.insert(target.clone(), origins);
                                }
                            } else {
                                // is_file_deserializer: json.load(f), yaml.load(f), etc.
                                //   — always HttpRequest regardless of f's trust level,
                                //     because file contents can be third-party (supply chain)
                                // is_source: request.GET.get(), iter_lines(), .json(), etc.
                                for target in &targets {
                                    let mut origins = HashSet::new();
                                    origins.insert(TaintOrigin::HttpRequest);
                                    state.insert(target.clone(), origins);
                                }
                            }
                        } else {
                            // 2. Check for Sanitizer
                            // If transforms_to is set: transform taint origin instead of clearing.
                            // If no transforms_to: clear taint (data is fully sanitized).
                            let matching_sanitizer = ruleset.taint_sanitizers.iter().find(|san| {
                                call_name.contains(&san.function_call) ||
                                san.function_call.contains(&call_name)
                            });

                            if let Some(san) = matching_sanitizer {
                                if let Some(ref transforms_to) = san.transforms_to {
                                    // Partial sanitization: transform origin, preserve taintedness
                                    if let Some(new_origin) = TaintOrigin::from_transforms_to(transforms_to) {
                                        for target in &targets {
                                            let mut new_origins = HashSet::new();
                                            new_origins.insert(new_origin.clone());
                                            state.insert(target.clone(), new_origins);
                                        }
                                    } else {
                                        // Unknown transforms_to value — fall back to clearing
                                        for target in &targets { state.remove(target); }
                                    }
                                } else {
                                    // Full sanitization: clear taint completely
                                    for target in &targets { state.remove(target); }
                                }
                            } else {
                                // 2b. Known sink call: propagate taint to result if a
                                // vulnerable argument is tainted (e.g. b=bytes(tainted))
                                let sink_taint = {
                                    let mut found = HashSet::new();
                                    for sink in &ruleset.taint_sinks {
                                        let matches = if sink.function_call.contains('.') {
                                            // Forward-only: "urllib.request.urlopen".contains("open") would be a FP
                                            call_name.contains(&sink.function_call)
                                        } else if sink.is_method {
                                            let dc = call_name.chars().filter(|&c| c == '.').count();
                                            match dc {
                                                0 => call_name == sink.function_call,
                                                _ => {
                                                    const MP: &[&str] = &["posixpath.","ntpath.","genericpath.","pathlib.","os.","sys.","re.","json.","urllib.","http.","xml.","html.","csv.","io.","base64.","hashlib.","hmac.","struct.","itertools.","functools.","operator.","execute.","ops.","eager."];
                                                    call_name.ends_with(&format!(".{}", sink.function_call)) && !MP.iter().any(|pfx| call_name.starts_with(pfx))
                                                }
                                            }
                                        } else {
                                            call_name == sink.function_call
                                        };
                                        if !matches { continue; }
                                        // Check if the vulnerable argument is tainted
                                        let arg_tainted = if sink.vulnerable_receiver {
                                            if let Some(func) = value_node.children.get("func").and_then(|v| v.get(0)) {
                                                if func.node_type == "Attribute" {
                                                    if let Some(recv) = func.children.get("value").and_then(|v| v.get(0)) {
                                                        get_direct_taint_names(recv).iter().any(|n| is_attacker_tainted(&state, n))
                                                    } else { false }
                                                } else { false }
                                            } else { false }
                                        } else {
                                            if let Some(args) = value_node.children.get("args") {
                                                if args.len() > sink.vulnerable_parameter_index {
                                                    get_direct_taint_names(&args[sink.vulnerable_parameter_index]).iter().any(|n| is_attacker_tainted(&state, n))
                                                } else { false }
                                            } else { false }
                                        };
                                        if arg_tainted {
                                            found.insert(TaintOrigin::External);
                                            break;
                                        }
                                    }
                                    found
                                };
                                if !sink_taint.is_empty() {
                                    for target in &targets {
                                        state.insert(target.clone(), sink_taint.clone());
                                    }
                                }

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
                                    // Method receiver propagation ONLY:
                                    // tainted_obj.method() → result is tainted.
                                    // We do NOT propagate through positional args of unknown functions
                                    // (disabled: causes taint explosion through every utility call).
                                    if let Some(func) = value_node.children.get("func").and_then(|v| v.get(0)) {
                                        if func.node_type == "Attribute" {
                                            if let Some(receiver) = func.children.get("value").and_then(|v| v.get(0)) {
                                                let names = extract_all_names(receiver);
                                                for name in names {
                                                    if let Some(origins) = state.get(&name) {
                                                        new_origins.extend(origins.iter().cloned());
                                                    }
                                                }
                                            }
                                        // dead code below — kept for structure
                                        } else {
                                            let _ = (); // no positional arg propagation
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
                    } else if value_node.node_type == "Constant" || value_node.node_type == "JoinedStr" {
                        // Tier 3: Constant folding — string/numeric literals are DeveloperDefined.
                        // "text" or f"text with {constant}" → developer wrote it, never user input.
                        // This handles: INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"
                        // and all other module-level or class-level constant assignments.
                        let is_all_constant = value_node.node_type == "Constant" || {
                            // For f-strings: DeveloperDefined only if ALL FormattedValues are also constants/DeveloperDefined
                            value_node.children.get("values").map_or(true, |vals| {
                                vals.iter().all(|v| {
                                    v.node_type == "Constant" || (
                                        v.node_type == "FormattedValue" &&
                                        v.children.get("value").and_then(|vv| vv.get(0))
                                            .map_or(false, |expr| {
                                                // Check if the expr name is DeveloperDefined in state
                                                get_direct_taint_names(expr).iter().all(|n| {
                                                    state.get(n).map_or(true, |origins| {
                                                        origins.iter().all(|o| !o.is_attacker_controlled())
                                                    })
                                                })
                                            })
                                    )
                                })
                            })
                        };
                        if is_all_constant {
                            for target in &targets {
                                let mut origins = HashSet::new();
                                origins.insert(TaintOrigin::DeveloperDefined);
                                state.insert(target.clone(), origins);
                            }
                        }
                    } else {
                        // Transitive propagation (Assignment from Name/Attribute/etc.)
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

                    // BinOp taint propagation: x = tainted % "..." or "..." % tainted
                    // Handles Python string formatting: sql = "SELECT * FROM %s" % table
                    if value_node.node_type == "BinOp" {
                        let mut binop_origins = HashSet::new();
                        for side in ["left", "right"] {
                            if let Some(operand) = value_node.children.get(side).and_then(|v| v.get(0)) {
                                let names = get_direct_taint_names(operand);
                                for name in names {
                                    if let Some(origins) = state.get(&name) {
                                        binop_origins.extend(origins.iter().cloned());
                                    }
                                }
                            }
                        }
                        if !binop_origins.is_empty() {
                            for target in &targets {
                                state.insert(target.clone(), binop_origins.clone());
                            }
                        }
                    }

                    // BoolOp taint propagation: x = a or b, x = a and b
                    // If any operand is tainted, x is tainted.
                    // Handles: config = plugin_config or {}  →  config is tainted if plugin_config is
                    if value_node.node_type == "BoolOp" {
                        let mut bool_origins = HashSet::new();
                        if let Some(values) = value_node.children.get("values") {
                            for val in values {
                                for name in extract_all_names(val) {
                                    if let Some(origins) = state.get(&name) {
                                        bool_origins.extend(origins.iter().cloned());
                                    }
                                }
                            }
                        }
                        if !bool_origins.is_empty() {
                            for target in &targets {
                                state.insert(target.clone(), bool_origins.clone());
                            }
                        }
                    }

                    // Check ALL call nodes within the RHS for sinks.
                    // Using find_call_sites (not just the outermost call) catches nested
                    // sinks like: result = env.from_string(tainted).render()
                    // where from_string is the dangerous call, not render.
                    if value_node.node_type == "Call" {
                        let mut rhs_calls = Vec::new();
                        find_call_sites(value_node, &mut rhs_calls);
                        for call in rhs_calls {
                            check_sink_and_report(call, &state, ruleset, file_path, content, &mut issues);
                        }
                    }
                    // f-string: x = f"...{tainted}..."
                    // 1. Flag FSTRING867 if any slot contains tainted variable.
                    // 2. Propagate taint to x (the f-string result carries taint forward).
                    if value_node.node_type == "JoinedStr" {
                        check_fstring_taint(value_node, &state, ruleset, file_path, content, &mut issues);
                        // Propagate: if any FormattedValue is tainted, result is tainted
                        let mut origins = HashSet::new();
                        if let Some(values) = value_node.children.get("values") {
                            for val in values {
                                if val.node_type == "FormattedValue" {
                                    if let Some(expr) = val.children.get("value").and_then(|v| v.get(0)) {
                                        for name in extract_all_names(expr) {
                                            if let Some(o) = state.get(&name) {
                                                origins.extend(o.iter().cloned());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if !origins.is_empty() {
                            for target in &targets {
                                state.insert(target.clone(), origins.clone());
                            }
                        }
                    }
                }
            }
            // For-loop variable binding: `for x in tainted_collection` → x is tainted.
            // The CFG flattens for-loops so the For node appears as a statement
            // in the header block. Propagate taint from iter to target.
            "For" => {
                if let Some(iter) = stmt.children.get("iter").and_then(|v| v.get(0)) {
                    let iter_names = extract_all_names(iter);
                    let mut loop_origins: HashSet<TaintOrigin> = HashSet::new();
                    for name in &iter_names {
                        if let Some(origins) = state.get(name) {
                            loop_origins.extend(origins.iter().cloned());
                        }
                    }
                    if !loop_origins.is_empty() {
                        if let Some(target) = stmt.children.get("target").and_then(|v| v.get(0)) {
                            let target_names: Vec<String> = match target.node_type.as_str() {
                                "Name" => target.fields.get("id")
                                    .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
                                    .map(|s| vec![s.to_string()])
                                    .unwrap_or_default(),
                                "Tuple" => target.children.get("elts")
                                    .map(|elts| elts.iter()
                                        .filter_map(|e| e.fields.get("id")
                                            .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
                                            .map(|s| s.to_string()))
                                        .collect())
                                    .unwrap_or_default(),
                                _ => vec![],
                            };
                            for name in target_names {
                                state.insert(name, loop_origins.clone());
                            }
                        }
                    }
                }
                // Also check any sink calls in the for-loop header
                let mut call_sites = Vec::new();
                find_call_sites(stmt, &mut call_sites);
                for call_node in call_sites {
                    check_sink_and_report(call_node, &state, ruleset, file_path, content, &mut issues);
                }
            }
            "Expr" => {
                if let Some(value) = stmt.children.get("value").and_then(|v| v.get(0)) {
                    if value.node_type == "Call" {
                        check_sink_and_report(value, &state, ruleset, file_path, content, &mut issues);
                    }
                    if value.node_type == "JoinedStr" {
                        check_fstring_taint(value, &state, ruleset, file_path, content, &mut issues);
                    }
                }
            }
            // With statement: `with expr as var` → var inherits taint from expr.
            // Handles: with open(tainted_path) as f → f is tainted
            //          with tainted_ctx as val → val is tainted
            "With" => {
                if let Some(items) = stmt.children.get("items") {
                    for item in items {
                        // context_expr is the expression (e.g. open(path))
                        // optional_vars is the `as var` binding
                        let ctx_tainted: HashSet<TaintOrigin> = {
                            let mut origins = HashSet::new();
                            if let Some(ctx) = item.children.get("context_expr").and_then(|v| v.get(0)) {
                                // Check if context_expr is a call that is a sink (e.g. open())
                                // and whether its arguments are tainted → ctx gets taint
                                if ctx.node_type == "Call" {
                                    check_sink_and_report(ctx, &state, ruleset, file_path, content, &mut issues);
                                    // Propagate taint from call arguments to context var
                                    if let Some(args) = ctx.children.get("args") {
                                        for arg in args {
                                            for name in extract_all_names(arg) {
                                                if let Some(o) = state.get(&name) {
                                                    origins.extend(o.iter().cloned());
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    for name in extract_all_names(ctx) {
                                        if let Some(o) = state.get(&name) {
                                            origins.extend(o.iter().cloned());
                                        }
                                    }
                                }
                            }
                            origins
                        };
                        if !ctx_tainted.is_empty() {
                            if let Some(opt_vars) = item.children.get("optional_vars").and_then(|v| v.get(0)) {
                                if let Some(var_name) = opt_vars.fields.get("id")
                                    .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
                                {
                                    state.insert(var_name.to_string(), ctx_tainted);
                                }
                            }
                        }
                    }
                }
                // Also check sinks in the With body via the fallthrough
                let mut call_sites = Vec::new();
                find_call_sites(stmt, &mut call_sites);
                for call_node in call_sites {
                    check_sink_and_report(call_node, &state, ruleset, file_path, content, &mut issues);
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

/// Returns only the DIRECT variable name(s) of an AST node for taint checking.
/// Unlike `extract_all_names`, this does NOT recurse into attribute receivers.
/// - Name("attr")     → ["attr"]
/// - Attribute("self.STANDARD_UNIT") → ["STANDARD_UNIT"]  (not "self")
/// - Subscript(d["key"]) → ["d"]
/// Returns true if the state contains attacker-controlled taint for this name.
/// DeveloperDefined, SystemGenerated, OperatorConfig do NOT trigger sinks.
fn is_attacker_tainted(state: &TaintState, name: &str) -> bool {
    state.get(name).map_or(false, |origins| {
        origins.iter().any(|o| o.is_attacker_controlled())
    })
}

/// Check taint considering the sink's triggers_on policy.
///
/// "all" (default)        — fires for all attacker-controlled origins.
/// "shell_injectable"     — fires for all EXCEPT ShellSanitized.
///                          Use for PY102 — shlex.quote is valid shell mitigation.
/// "sql_injectable"       — fires for all EXCEPT SqlSanitized.
///                          Use for PY101 — quote_name is valid SQL mitigation.
/// "html_injectable"      — fires for all EXCEPT HtmlSanitized.
///                          Use for XSS sinks — html.escape/format_html are valid.
/// "injectable_only"      — fires ONLY for HttpRequest/External (no sanitized variants).
///                          Legacy / strict mode.
fn is_tainted_for_sink(state: &TaintState, name: &str, triggers_on: &str) -> bool {
    state.get(name).map_or(false, |origins| {
        origins.iter().any(|o| {
            match triggers_on {
                "shell_injectable" => o.is_shell_injectable(),   // HttpRequest|External only
                "sql_injectable"   => o.is_sql_injectable(),     // HttpRequest|External|ShellSanitized
                "html_injectable"  => o.is_attacker_controlled(), // all (HtmlSanitized is not attacker-controlled)
                "injectable_only"  => o.is_shell_injectable(),
                _                  => o.is_attacker_controlled(), // "all" default
            }
        })
    })
}

fn get_direct_taint_names(node: &AstNode) -> Vec<String> {
    match node.node_type.as_str() {
        "Name" => {
            if let Some(id) = node.fields.get("id").and_then(|v| v.as_ref()).and_then(|v| v.as_str()) {
                return vec![id.to_string()];
            }
        }
        "Attribute" => {
            // Only return the attribute name itself, NOT the receiver.
            // This prevents self.STANDARD_UNIT from matching because self is tainted.
            if let Some(attr) = node.fields.get("attr").and_then(|v| v.as_ref()).and_then(|v| v.as_str()) {
                return vec![attr.to_string()];
            }
        }
        "Subscript" => {
            // Return the container name for subscript access (e.g., dict["key"] → "dict")
            if let Some(value) = node.children.get("value").and_then(|v| v.get(0)) {
                return get_direct_taint_names(value);
            }
        }
        _ => {}
    }
    Vec::new()
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

    // Skip unresolvable calls (empty name matches everything via contains(""))
    if call_name.is_empty() {
        return;
    }

    for sink in &ruleset.taint_sinks {
        // Matching strategy:
        // - Dotted sink paths ("subprocess.run"): substring match
        // - Method sinks (is_method=true, e.g. "replace", "join", "format"):
        //     call_name must end with ".funcname" (avoids "set" matching builtin "set()")
        // - Builtin sinks (is_method=false, e.g. "set", "open", "getattr"):
        //     call_name must equal funcname exactly (prevents "cache.set" matching "set")
        let matches = if sink.function_call.contains('.') {
            // Forward-only: "urllib.request.urlopen".contains("open") is a FP
            call_name.contains(&sink.function_call)
        } else if sink.is_method {
            // Method sinks (replace, join, center, etc.):
            // - 0 dots: receiver was a literal/constant → exact match
            // - 1 dot: normal method call "s.method" → ends_with ".method"
            //   EXCEPT when receiver looks like a module (posixpath, ntpath, etc.)
            // - 2+ dots: module path → NOT a method, skip
            const MODULE_PREFIXES: &[&str] = &[
                "posixpath.", "ntpath.", "genericpath.", "pathlib.",
                "os.", "sys.", "re.", "json.", "urllib.", "http.",
                "xml.", "html.", "csv.", "io.", "base64.", "hashlib.",
                "hmac.", "struct.", "itertools.", "functools.", "operator.",
                // ML framework module prefixes that have .execute() but are NOT SQL sinks:
                //   execute.execute(b"Fill", ...) — eager op execution
                //   ops.execute(...)              — operation execution
                "execute.", "ops.", "eager.",
            ];
            let dot_count = call_name.chars().filter(|&c| c == '.').count();
            // For dot_count=0 (e.g. the receiver was a literal, so get_full_call_name
            // only returns the method name), require the func node to be an Attribute
            // to distinguish `'/'.join(parts)` (method on literal) from `execute(x)` (standalone).
            let func_is_attribute = call_node.children.get("func")
                .and_then(|v| v.get(0))
                .map(|f| f.node_type == "Attribute")
                .unwrap_or(false);
            match dot_count {
                0 => func_is_attribute && call_name == sink.function_call,
                _ => {
                    call_name.ends_with(&format!(".{}", sink.function_call)) &&
                    !MODULE_PREFIXES.iter().any(|pfx| call_name.starts_with(pfx))
                }
            }
        } else {
            call_name == sink.function_call
        };
        if !matches {
            continue;
        }

        let mut found_taint = false;

        let triggers_on = sink.triggers_on.as_str();

        if sink.vulnerable_receiver {
            // Check method receiver: tainted_obj.method(...) → receiver is tainted.
            // Use extract_all_names so inline expressions like Path(tainted).mkdir()
            // are correctly detected — Path(output) is a Call whose arg "output" is tainted.
            if let Some(func) = call_node.children.get("func").and_then(|v| v.get(0)) {
                if func.node_type == "Attribute" {
                    if let Some(receiver) = func.children.get("value").and_then(|v| v.get(0)) {
                        let names = extract_all_names(receiver);
                        for name in names {
                            if is_tainted_for_sink(state, &name, triggers_on) {
                                found_taint = true;
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            // Check positional argument at vulnerable_parameter_index.
            // When vulnerable_keyword is specified, skip Phase 1 entirely — the sink
            // is keyword-only (e.g. create(password=tainted), not create(tainted)).
            // Without this guard, Q.create(tainted_list) fires PLAIN_PWD001 because
            // args[0] is tainted even though no password= keyword is present.
            let skip_positional = sink.vulnerable_keyword.is_some();
            if !skip_positional {
            if let Some(args) = call_node.children.get("args") {
                if args.len() > sink.vulnerable_parameter_index {
                    let arg = &args[sink.vulnerable_parameter_index];
                    let arg_names = extract_all_names(arg);
                    for name in arg_names {
                        if is_tainted_for_sink(state, &name, triggers_on) {
                            found_taint = true;
                            break;
                        }
                    }
                    // Also check if the arg contains an inline taint source call
                    // e.g. httpx.stream("GET", r.json()["url"]) — r.json() is a source
                    if !found_taint {
                        let mut inline_calls: Vec<&AstNode> = Vec::new();
                        find_call_sites(arg, &mut inline_calls);
                        for inline_call in inline_calls {
                            let inline_name = get_full_call_name(inline_call);
                            let is_inline_source = ruleset.taint_sources.iter().any(|s| {
                                if s.function_call.contains('.') {
                                    inline_name.contains(&s.function_call) ||
                                    s.function_call.contains(&inline_name)
                                } else {
                                    inline_name == s.function_call
                                }
                            });
                            if is_inline_source {
                                found_taint = true;
                                break;
                            }
                        }
                    }
                }
            }
            } // end skip_positional guard
        }

        // Phase 3: keyword arguments for positional-arg sinks only.
        // If vulnerable_keyword is set, only that named kwarg triggers.
        // Otherwise, any tainted kwarg can trigger (for sinks that accept kwargs).
        if !found_taint && !sink.vulnerable_receiver {
            if let Some(keywords) = call_node.children.get("keywords") {
                for kw in keywords {
                    let kw_arg_name = kw.fields.get("arg")
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
                        .unwrap_or("");
                    // If vulnerable_keyword is specified, skip non-matching kwargs
                    if let Some(ref vk) = sink.vulnerable_keyword {
                        if kw_arg_name != vk.as_str() { continue; }
                    }
                    if let Some(kw_value) = kw.children.get("value").and_then(|v| v.get(0)) {
                        let kw_names = get_direct_taint_names(kw_value);
                        for name in kw_names {
                            if is_attacker_tainted(state, &name) {
                                found_taint = true;
                                break;
                            }
                        }
                    }
                    if found_taint { break; }
                }
            }
        }

        if found_taint {
            println!("[!] VULNERABILITY: Tainted variable flows to sink '{}'", call_name);
            report_issue(ruleset, &sink.vulnerability_id, file_path, call_node, content, issues);
        }
        // Note: found_taint is true only when is_attacker_controlled() returned true
        // (see get_direct_taint_names usage above — we check state.contains_key which
        //  only contains attacker-controlled taint after the provenance gate below)
    }
}

/// Check if an f-string (JoinedStr) contains a directly tainted variable and report FSTRING867.
///
/// Uses get_direct_taint_names (not extract_all_names) so only DIRECT variable references
/// inside the f-string slots trigger the rule. This prevents FPs where tainted data is
/// wrapped in a safe function call: `f"count: {len(data)}"` does NOT fire because `len()`
/// transforms the tainted data before interpolation (result is an integer, not injectable).
///
/// Cases that fire:
///   f"{user_input}"           — direct Name reference, tainted → fires
///   f"{obj.field}"            — Attribute, field is tainted → fires
///   f"{data[key]}"            — Subscript, data is tainted → fires
///
/// Cases that do NOT fire (correctly suppressed):
///   f"{len(tainted_list)}"    — len() wraps it, returns int, not injectable
///   f"{str(tainted)}"         — str() is a safe conversion
///   f"{repr(tainted)}"        — repr() wraps it safely
///   f"{x!r}"                  — !r conversion quotes the value (same as repr)
///   f"{x!a}"                  — !a conversion applies ascii(), quotes non-ASCII
fn check_fstring_taint(
    node: &AstNode,
    state: &TaintState,
    ruleset: &RuleSet,
    file_path: &str,
    content: &str,
    issues: &mut Vec<Issue>,
) {
    // JoinedStr.children["values"] contains Constant and FormattedValue nodes.
    if let Some(values) = node.children.get("values") {
        for val in values {
            if val.node_type == "FormattedValue" {
                // Skip slots with repr/ascii conversion: {x!r} and {x!a} quote the value,
                // making it safe for injection. conversion field: 114='r', 97='a', 115='s', -1=none.
                let conversion = val.fields.get("conversion")
                    .and_then(|v| v.as_ref()).and_then(|v| v.as_i64())
                    .unwrap_or(-1);
                if conversion == 114 || conversion == 97 { // !r or !a
                    continue;
                }
                // FormattedValue.children["value"] is the expression inside {}.
                if let Some(expr) = val.children.get("value").and_then(|v| v.get(0)) {
                    // Use get_direct_taint_names: only direct Name/Attribute/Subscript
                    // references — NOT recursive into function call arguments.
                    let names = get_direct_taint_names(expr);
                    for name in names {
                        if is_attacker_tainted(state, &name) {
                            report_issue(ruleset, "FSTRING867", file_path, node, content, issues);
                            return; // report once per f-string
                        }
                    }
                }
            }
        }
    }
}

/// Returns a dotted string representing the container of a Subscript node.
/// For `request.GET['key']` returns "request.GET".
fn get_subscript_container(node: &AstNode) -> String {
    if let Some(value) = node.children.get("value").and_then(|v| v.get(0)) {
        match value.node_type.as_str() {
            "Attribute" => {
                let mut parts = Vec::new();
                let mut cur = value;
                loop {
                    if let Some(attr) = cur.fields.get("attr").and_then(|v| v.as_ref()).and_then(|v| v.as_str()) {
                        parts.push(attr.to_string());
                    }
                    if let Some(next) = cur.children.get("value").and_then(|v| v.get(0)) {
                        cur = next;
                    } else {
                        break;
                    }
                }
                if let Some(base) = cur.fields.get("id").and_then(|v| v.as_ref()).and_then(|v| v.as_str()) {
                    parts.push(base.to_string());
                }
                parts.reverse();
                parts.join(".")
            }
            "Name" => value.fields.get("id")
                .and_then(|v| v.as_ref())
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            _ => String::new(),
        }
    } else {
        String::new()
    }
}

/// Returns all Name identifiers in the base (non-slice) part of a Subscript.
/// For `tainted_dict['key']` returns ["tainted_dict"].
fn get_subscript_base_names(node: &AstNode) -> Vec<String> {
    if let Some(value) = node.children.get("value").and_then(|v| v.get(0)) {
        extract_all_names(value)
    } else {
        Vec::new()
    }
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

/// Inspect a FunctionDef node's decorator_list and return the names of parameters
/// that receive user-controlled input based on known entry-point decorators.
///
/// Supported frameworks and decorator patterns:
///
/// **CLI** (click, typer, argparse):
///   @click.command / @click.option("--flag", "param_name") / @click.argument("name")
///   @app.command() / @typer.option / @typer.argument  (Typer uses same conventions)
///
/// **Web** (Flask, FastAPI, Django REST, aiohttp, Bottle, Falcon, Starlette):
///   @app.route("/path") / @app.get / @app.post / @app.put / @app.delete / @app.patch
///   @router.get / @router.post / @api_view / @require_http_methods
///   @web.get / @web.post  (aiohttp)
///
/// **Task queues** (Celery, RQ, Huey, Dramatiq):
///   @app.task / @celery.task / @shared_task / @dramatiq.actor / @huey.task
///   @periodic_task / @rq.job
///
/// **Event handlers** (Django signals, Flask signals, AWS Lambda, GCP Functions):
///   @receiver(signal) / @app.before_request / @app.after_request
///   @lambda_handler / @functions_framework.http
///
/// For all of these, ALL parameters (except self/cls) are considered user-controlled
/// because the framework injects request/event/message data into them.
/// Parameters classified by decorator type and the taint origin they should receive.
struct EntryPointParams {
    /// HTTP decorator params (@app.route, @api_view) → TaintOrigin::HttpRequest.
    /// Attacker-controlled: any internet user can send arbitrary values.
    http: Vec<String>,
    /// CLI decorator params (@app.command, @click.option) → TaintOrigin::OperatorConfig.
    /// Operator-trusted: the person running the tool chose these values.
    /// FILE_DESERIALIZERS still produce HttpRequest when reading file *contents*,
    /// so supply-chain detection is preserved even for operator-specified file paths.
    operator: Vec<String>,
}

impl EntryPointParams {
    fn is_empty(&self) -> bool { self.http.is_empty() && self.operator.is_empty() }
}

fn extract_cli_tainted_params(func_node: &AstNode) -> EntryPointParams {
    let mut result = EntryPointParams { http: Vec::new(), operator: Vec::new() };

    let decorator_list = match func_node.children.get("decorator_list") {
        Some(d) => d,
        None => return result,
    };

    // HTTP entry points — parameters receive attacker-controlled data from network requests.
    // These produce HttpRequest taint which triggers all security sinks.
    const HTTP_TAINT_DECORATOR_ATTRS: &[&str] = &[
        // Web frameworks — route/endpoint decorators
        "route", "get", "post", "put", "delete", "patch", "head", "options",
        // Django REST Framework
        "api_view", "action", "require_http_methods", "require_GET", "require_POST",
        // aiohttp
        "view", "endpoint",
        // Starlette / FastAPI router
        "add_route",
        // Task queues — tasks receive data from external message brokers
        "task", "shared_task", "periodic_task", "actor", "job",
        // Event handlers
        "receiver", "before_request", "after_request", "teardown_request",
        "before_app_request", "after_app_request",
        // Serverless
        "handler",
    ];

    // CLI entry points (Click, Typer) are treated the same as HTTP entry points:
    // both produce HttpRequest taint on all parameters.
    // Rationale: CLI tools that process third-party file contents (plugin configs,
    // user-supplied data) share the same supply-chain risk as HTTP handlers.
    const CLI_TAINT_DECORATOR_ATTRS: &[&str] = &[
        "command", "group",
    ];

    let mut has_http_taint_decorator = false;
    let mut has_cli_taint_decorator = false;
    let mut click_option_params: Vec<String> = Vec::new();

    for decorator in decorator_list {
        if decorator.node_type != "Call" {
            // Bare decorator (no parens): @app.route, @app.command
            if let Some(func) = decorator.children.get("func").and_then(|v| v.get(0)) {
                let attr = func.fields.get("attr")
                    .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
                    .unwrap_or("");
                if HTTP_TAINT_DECORATOR_ATTRS.contains(&attr) {
                    has_http_taint_decorator = true;
                } else if CLI_TAINT_DECORATOR_ATTRS.contains(&attr) {
                    has_cli_taint_decorator = true;
                }
            }
            continue;
        }

        // Call decorator: @click.option("--flag", "param_name") etc.
        let func = match decorator.children.get("func").and_then(|v| v.get(0)) {
            Some(f) => f,
            None => continue,
        };

        let attr = func.fields.get("attr")
            .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
            .unwrap_or("");

        if HTTP_TAINT_DECORATOR_ATTRS.contains(&attr) {
            has_http_taint_decorator = true;
            continue;
        } else if CLI_TAINT_DECORATOR_ATTRS.contains(&attr) {
            has_cli_taint_decorator = true;
            continue;
        }

        // click.option("--flag-name", "python_param_name") or just ("--flag-name")
        if attr == "option" {
            let args = decorator.children.get("args").map(|v| v.as_slice()).unwrap_or(&[]);
            let param_name = if args.len() >= 2 {
                // Second positional arg is the explicit Python parameter name
                args[1].fields.get("value")
                    .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            } else if args.len() == 1 {
                // Derive from flag: "--my-option" → "my_option"
                args[0].fields.get("value")
                    .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
                    .map(|s| s.trim_start_matches('-').replace('-', "_"))
            } else {
                None
            };
            if let Some(name) = param_name {
                click_option_params.push(name);
            }
        }

        // click.argument("param_name") or typer.argument
        if attr == "argument" {
            let args = decorator.children.get("args").map(|v| v.as_slice()).unwrap_or(&[]);
            if let Some(first) = args.first() {
                if let Some(name) = first.fields.get("value")
                    .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
                {
                    click_option_params.push(name.to_lowercase());
                }
            }
        }
    }

    // Helper closure: collect all non-self/cls parameter names
    let collect_params = |args_node: &AstNode| -> Vec<String> {
        let mut names = Vec::new();
        for key in &["args", "posonlyargs", "kwonlyargs"] {
            if let Some(params) = args_node.children.get(*key) {
                for param in params {
                    if let Some(name) = param.fields.get("arg")
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_str())
                    {
                        if name != "self" && name != "cls" {
                            names.push(name.to_string());
                        }
                    }
                }
            }
        }
        names
    };

    if has_http_taint_decorator {
        // HTTP entry point: all params → HttpRequest (attacker-controlled via network)
        if let Some(args_node) = func_node.children.get("args").and_then(|v| v.get(0)) {
            for name in collect_params(args_node) {
                result.http.push(name);
            }
        }
    } else if has_cli_taint_decorator {
        // CLI entry point: all params → OperatorConfig (operator chose these values).
        // The operator is trusted for PATH/URL choices. File CONTENTS they point to
        // may be third-party — FILE_DESERIALIZERS will upgrade those to HttpRequest.
        if let Some(args_node) = func_node.children.get("args").and_then(|v| v.get(0)) {
            for name in collect_params(args_node) {
                result.operator.push(name);
            }
        }
    } else {
        // @click.option / @click.argument without a command decorator:
        // these are also operator-controlled inputs
        result.operator.extend(click_option_params);
    }

    result
}

fn report_issue(ruleset: &RuleSet, vuln_id: &str, file_path: &str, stmt: &AstNode, content: &str, issues: &mut Vec<Issue>) {
    if let Some(vuln_rule) = ruleset.rules.iter().find(|r| r.id == vuln_id) {
        // Apply global and rule-level file exclusions (path + content) to taint findings
        if vuln_rule.is_excluded(file_path, content, &ruleset.defaults) {
            return;
        }
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
            vuln_rule.cwe.clone(),
        ));
    }
}
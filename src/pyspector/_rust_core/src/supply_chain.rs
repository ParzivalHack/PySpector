use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;
use serde_json::Value;

// Public API
pub fn scan_dependencies(project_path: &str) -> Vec<VulnerabilityMatch> {
    let files = find_dependency_files(project_path);
    
    // Collect all dependencies from all files
    let mut all_dependencies = Vec::new();
    for file in &files {
        all_dependencies.extend(parse_dependency_file(file));
    }
    
    // Deduplicate: same package@version might be in multiple files.
    // We want to query each unique package@version only once.
    // Use a HashMap to keep track of which files a dependency was seen in (optional, but good for reporting)
    // For now, simpler approach: just unique by name+version for querying
    
    let mut unique_deps_map: HashMap<String, Dependency> = HashMap::new();
    
    for dep in &all_dependencies {
        let key = format!("{}@{}", dep.name, dep.version);
        if !unique_deps_map.contains_key(&key) {
            unique_deps_map.insert(key, dep.clone());
        } else {
             // If we wanted to track multiple files, we'd need a different struct.
             // The spec says "Deduplication: Collect all dependencies... to ensure each unique package is only queried once"
             // But the report output shows "File: requirements.txt".
             // If a vuln is in multiple files, we should probably report it for each, or list all files.
             // However, for efficiency, we query once.
             // Let's stick to: Query unique deps, then map results back? 
             // Or better: Just query unique deps, and user sees one instance.
             // If I have requests in req.txt and pyproject.toml, reporting it once is probably fine.
             // But wait, the `VulnerabilityMatch` has a `file` field.
             // If I deduplicate, I lose the file info for the duplicates.
             // 
             // OPTION 1: Query unique, then map back to all occurrences?
             // That means I need to keep `all_dependencies` and join with query results.
             
             // Let's do that:
             // 1. Get all dependencies (with their file source)
             // 2. Extract unique (name, version, ecosystem) tuples
             // 3. Query OSV for those unique tuples
             // 4. For each original dependency, look up the vulnerabilities for its (name, version)
        }
    }

    // Prepare unique items for querying
    let unique_deps: Vec<&Dependency> = unique_deps_map.values().collect();
    
    // Build client once
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new());

    // Parallel query
    let vuln_results: Vec<(String, Vec<VulnerabilityMatch>)> = unique_deps
        .par_iter()
        .map(|dep| {
            let matches = query_osv(&client, dep);
            let key = format!("{}@{}", dep.name, dep.version);
            (key, matches)
        })
        .collect();
        
    let mut vulns_map: HashMap<String, Vec<VulnerabilityMatch>> = HashMap::new();
    for (key, matches) in vuln_results {
        vulns_map.insert(key, matches);
    }
    
    // now we need to reconstruct the full list of matches.
    // But wait, the `query_osv` returns `VulnerabilityMatch` which effectively clones the Dependency info
    // including the file path.
    // If I passed a Dependency from `unique_deps`, it has *one* of the file paths.
    // So if I just use the results from `unique_deps`, I miss the others.
    
    // Better strategy:
    // 1. `files` -> `all_dependencies` (Vec<Dependency>)
    // 2. `unique_keys` -> HashSet<String> of "name@version@ecosystem"
    // 3. Query OSV for each unique key -> Map<Key, Vec<OsvVulnerability>>
    // 4. Iterate `all_dependencies`, look up in Map, create `VulnerabilityMatch`
    
    let unique_keys: HashSet<(String, String, String)> = all_dependencies.iter()
        .map(|d| (d.name.clone(), d.version.clone(), d.ecosystem.clone()))
        .collect();
        
    let unique_list: Vec<(String, String, String)> = unique_keys.into_iter().collect();
    
    let query_results: Vec<((String, String, String), Vec<OsvVulnerability>)> = unique_list
        .par_iter()
        .map(|(name, version, ecosystem)| {
            let vulns = raw_query_osv(&client, name, version, ecosystem);
            ((name.clone(), version.clone(), ecosystem.clone()), vulns)
        })
        .collect();
        
    let mut vuln_lookup: HashMap<(String, String, String), Vec<OsvVulnerability>> = HashMap::new();
    for (key, vulns) in query_results {
        vuln_lookup.insert(key, vulns);
    }
    
    let mut final_matches = Vec::new();
    
    for dep in all_dependencies {
         let key = (dep.name.clone(), dep.version.clone(), dep.ecosystem.clone());
         if let Some(vulns) = vuln_lookup.get(&key) {
             for v in vulns {
                 final_matches.push(VulnerabilityMatch {
                     dependency: dep.name.clone(),
                     version: dep.version.clone(),
                     vulnerability_id: v.id.clone(),
                     severity: resolve_severity(v),
                     summary: v.summary.clone().unwrap_or_default(),
                     file: dep.file.clone(),
                     fixed_version: extract_fixed_version(v),
                 });
             }
         }
    }
    
    final_matches
}

// Data structures
#[derive(Debug, Clone)]
struct Dependency {
    name: String,
    version: String,
    file: String,
    ecosystem: String, // "PyPI" or "crates.io"
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilityMatch {
    pub dependency: String,
    pub version: String,
    pub vulnerability_id: String,
    pub severity: String,
    pub summary: String,
    pub file: String,
    pub fixed_version: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize, Clone)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverityEntry>, // CVSS vector
    #[serde(default)]
    affected: Vec<OsvAffected>,
    database_specific: Option<OsvDatabaseSpecific>,
}

#[derive(Debug, Deserialize, Clone)]
struct OsvDatabaseSpecific {
    severity: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct OsvSeverityEntry {
    #[serde(rename = "type")]
    type_: String,
    score: String,
}

#[derive(Debug, Deserialize, Clone)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize, Clone)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize, Clone)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
}

// Implementation

fn find_dependency_files(root: &str) -> Vec<String> {
    let mut files = Vec::new();
    let walker = WalkDir::new(root).max_depth(5);
    
    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Some(name) = entry.file_name().to_str() {
                if name == "requirements.txt" || 
                   name == "pyproject.toml" || 
                   name == "Pipfile" || 
                   name == "Cargo.toml" {
                    if let Some(path) = entry.path().to_str() {
                        files.push(path.to_string());
                    }
                }
            }
        }
    }
    files
}

fn parse_dependency_file(filepath: &str) -> Vec<Dependency> {
    let path = Path::new(filepath);
    let filename = match path.file_name() {
        Some(n) => n.to_str().unwrap_or(""),
        None => return vec![],
    };

    match filename {
        "requirements.txt" => parse_requirements_txt(filepath),
        "pyproject.toml" => parse_pyproject_toml(filepath),
        "Pipfile" => parse_pipfile(filepath),
        "Cargo.toml" => parse_cargo_toml(filepath),
        _ => vec![],
    }
}

fn parse_requirements_txt(filepath: &str) -> Vec<Dependency> {
    let content = match fs::read_to_string(filepath) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut deps = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        // Strip inline comments
        let part = line.split(&['#', ';'][..]).next().unwrap_or("").trim();
        if part.is_empty() {
             continue;
        }

        // simplistic parsing for package==version, package>=version etc
        // Split by operators
        let operators = ["==", ">=", "<=", "~=", ">", "<"];
        let mut found = false;
        
        for op in &operators {
            if let Some(idx) = part.find(op) {
                let name = part[..idx].trim().to_lowercase();
                let version = part[idx + op.len()..].trim();
                
                if !name.is_empty() && !version.is_empty() {
                    deps.push(Dependency {
                        name,
                        version: version.to_string(),
                        file: filepath.to_string(),
                        ecosystem: "PyPI".to_string(),
                    });
                    found = true;
                    break;
                }
            }
        }
        
        if !found {
            // maybe it's just package (no version)? OSV needs version.
            // Ignore unpinned dependencies? The spec implies pinned versions.
        }
    }
    deps
}

fn parse_pyproject_toml(filepath: &str) -> Vec<Dependency> {
    let content = match fs::read_to_string(filepath) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    
    let toml_val: Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    
    let mut deps = Vec::new();
    
    // Poetry: [tool.poetry.dependencies]
    if let Some(tool) = toml_val.get("tool") {
        if let Some(poetry) = tool.get("poetry") {
            if let Some(dependencies) = poetry.get("dependencies") {
                if let Some(table) = dependencies.as_object() {
                    for (k, v) in table {
                        if k == "python" { continue; }
                        
                        let version_str = if let Some(s) = v.as_str() {
                            s.to_string()
                        } else if let Some(v_table) = v.as_object() {
                            // sometimes version is in { version = "...", ... }
                            if let Some(ver) = v_table.get("version").and_then(|x| x.as_str()) {
                                ver.to_string()
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        };

                        let clean_version = version_str.trim_start_matches('^').trim_start_matches('~').to_string();
                         deps.push(Dependency {
                            name: k.to_string(),
                            version: clean_version,
                            file: filepath.to_string(),
                            ecosystem: "PyPI".to_string(),
                        });
                    }
                }
            }
        }
    }
    
    // PEP 621: [project] dependencies = []
    if let Some(project) = toml_val.get("project") {
        if let Some(dependencies) = project.get("dependencies").and_then(|d| d.as_array()) {
            for dep_val in dependencies {
                if let Some(dep_str) = dep_val.as_str() {
                     // Reuse logic similar to req.txt parsing
                     let operators = ["==", ">=", "<=", "~=", ">", "<"];
                     for op in &operators {
                        if let Some(idx) = dep_str.find(op) {
                            let name = dep_str[..idx].trim().to_lowercase();
                            let version = dep_str[idx + op.len()..].trim();
                            
                            if !name.is_empty() && !version.is_empty() {
                                deps.push(Dependency {
                                    name,
                                    version: version.to_string(),
                                    file: filepath.to_string(),
                                    ecosystem: "PyPI".to_string(),
                                });
                                break;
                            }
                        }
                     }
                }
            }
        }
    }
    
    deps
}

fn parse_pipfile(filepath: &str) -> Vec<Dependency> {
    let content = match fs::read_to_string(filepath) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let toml_val: Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    
    let mut deps = Vec::new();
    
    if let Some(packages) = toml_val.get("packages").and_then(|p| p.as_object()) {
        for (k, v) in packages {
            let version_str = match v.as_str() {
                Some(s) => s,
                None => continue,
            };
            
            if version_str == "*" { continue; }
            
            let clean_version = version_str.trim_start_matches("==");
            
             deps.push(Dependency {
                name: k.to_string(),
                version: clean_version.to_string(),
                file: filepath.to_string(),
                ecosystem: "PyPI".to_string(),
            });
        }
    }
    
    deps
}

fn parse_cargo_toml(filepath: &str) -> Vec<Dependency> {
    let content = match fs::read_to_string(filepath) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let toml_val: Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    
    let mut deps = Vec::new();
    
    if let Some(dependencies) = toml_val.get("dependencies").and_then(|d| d.as_object()) {
        for (k, v) in dependencies {
             let version_opt = if let Some(s) = v.as_str() {
                 Some(s.to_string())
             } else if let Some(table) = v.as_object() {
                 table.get("version").and_then(|x| x.as_str()).map(|s| s.to_string())
             } else {
                 None
             };
             
             if let Some(ver) = version_opt {
                 deps.push(Dependency {
                    name: k.to_string(),
                    version: ver,
                    file: filepath.to_string(),
                    ecosystem: "crates.io".to_string(),
                });
             }
        }
    }
    
    deps
}

// OSV Querying

// Kept this for reference, but we use raw_query_osv
fn query_osv(client: &reqwest::blocking::Client, dep: &Dependency) -> Vec<VulnerabilityMatch> {
    let vulns = raw_query_osv(client, &dep.name, &dep.version, &dep.ecosystem);
    
    vulns.into_iter().map(|v| {
         VulnerabilityMatch {
             dependency: dep.name.clone(),
             version: dep.version.clone(),
             vulnerability_id: v.id.clone(),
             severity: resolve_severity(&v),
             summary: v.summary.clone().unwrap_or_default(),
             file: dep.file.clone(),
             fixed_version: extract_fixed_version(&v),
         }
    }).collect()
}

fn raw_query_osv(client: &reqwest::blocking::Client, name: &str, version: &str, ecosystem: &str) -> Vec<OsvVulnerability> {
    let url = "https://api.osv.dev/v1/query";
    let body = serde_json::json!({
        "package": {
            "name": name,
            "ecosystem": ecosystem
        },
        "version": version
    });

    match client.post(url).json(&body).send() {
        Ok(resp) => {
            if resp.status().is_success() {
                 match resp.json::<OsvResponse>() {
                     Ok(osv_resp) => osv_resp.vulns,
                     Err(_) => vec![],
                 }
            } else {
                vec![]
            }
        },
        Err(_) => vec![],
    }
}

// Severity Resolution

fn resolve_severity(vuln: &OsvVulnerability) -> String {
    // Tier 1: Database Specific
    if let Some(db_spec) = &vuln.database_specific {
        if let Some(sev) = &db_spec.severity {
             return sev.to_uppercase();
        }
    }
    
    // Tier 2: CVSS
    // Find CVSS v3 score
    for sev_entry in &vuln.severity {
        if sev_entry.type_ == "CVSS_V3" {
            if let Some(base_score) = compute_cvss_base_score(&sev_entry.score) {
                if base_score >= 9.0 { return "CRITICAL".to_string(); }
                if base_score >= 7.0 { return "HIGH".to_string(); }
                if base_score >= 4.0 { return "MEDIUM".to_string(); }
                return "LOW".to_string();
            }
        }
    }

    "UNKNOWN".to_string()
}

fn compute_cvss_base_score(vector: &str) -> Option<f64> {
    // Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    // Parse metrics
    let parts: Vec<&str> = vector.split('/').collect();
    
    let mut av = 0.0;
    let mut ac = 0.0;
    let mut pr = 0.0;
    let mut ui = 0.0;
    let mut _s = 0.0; // Changed? 0 = unchanged (U), 1 = changed (C)
    let mut c = 0.0;
    let mut i = 0.0;
    let mut a = 0.0;
    
    let mut scope_changed = false;

    // Default values if missing - strictly simplistic parser
    for part in parts {
        if part.starts_with("AV:") {
             match &part[3..] {
                 "N" => av = 0.85,
                 "A" => av = 0.62,
                 "L" => av = 0.55,
                 "P" => av = 0.20,
                 _ => {}
             }
        } else if part.starts_with("AC:") {
            match &part[3..] {
                "L" => ac = 0.77,
                "H" => ac = 0.44,
                _ => {}
            }
        } else if part.starts_with("PR:") {
            // Logic handled later based on scope
            match &part[3..] {
                "N" => pr = 0.85, 
                "L" => pr = 0.62, // or 0.68
                "H" => pr = 0.27, // or 0.50
                _ => {}
            }
        } else if part.starts_with("UI:") {
            match &part[3..] {
                "N" => ui = 0.85,
                "R" => ui = 0.62,
                _ => {}
            }
        } else if part.starts_with("S:") {
            match &part[2..] {
                "U" => scope_changed = false,
                "C" => scope_changed = true,
                _ => {}
            }
        } else if part.starts_with("C:") {
            match &part[2..] {
                "N" => c = 0.0,
                "L" => c = 0.22,
                "H" => c = 0.56,
                _ => {}
            }
        } else if part.starts_with("I:") {
            match &part[2..] {
                "N" => i = 0.0,
                "L" => i = 0.22,
                "H" => i = 0.56,
                _ => {}
            }
        } else if part.starts_with("A:") {
             match &part[2..] {
                "N" => a = 0.0,
                "L" => a = 0.22,
                "H" => a = 0.56,
                _ => {}
            }
        }
    }
    
    // Adjust PR based on scope
    // We need to re-parse PR because its value depends on scope
    // But since I stored the mapped values, I need to know which actual string was used. 
    // Let's re-scan for PR string
    for part in vector.split('/') {
        if part.starts_with("PR:") {
            let pr_val = &part[3..];
            pr = match (pr_val, scope_changed) {
                ("N", _) => 0.85,
                ("L", false) => 0.62,
                ("L", true) => 0.68,
                ("H", false) => 0.27,
                ("H", true) => 0.50,
                _ => 0.85,
            };
        }
    }

    let iss: f64 = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    
    if impact <= 0.0 { return Some(0.0); }
    
    let exploitability = 8.22 * av * ac * pr * ui;
    
    let mut base_score: f64 = if scope_changed {
        1.08 * (impact + exploitability).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    
    // Round up to 1 decimal place
    // Simple roundup function: ceil(x * 10) / 10
    base_score = (base_score * 10.0).ceil() / 10.0;
    
    Some(base_score)
}

fn extract_fixed_version(vuln: &OsvVulnerability) -> Option<String> {
    for affected in &vuln.affected {
        for range in &affected.ranges {
            for event in &range.events {
                if let Some(fixed) = &event.fixed {
                    return Some(fixed.clone());
                }
            }
        }
    }
    None
}

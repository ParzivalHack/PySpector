use actix_web::{post, web, App, HttpServer, HttpResponse, Responder};
use actix_governor::{Governor, GovernorConfigBuilder};
use pyo3::prelude::*;
use actix_cors::Cors;
use pyo3::types::PyDict;
use serde::Deserialize;
use std::process::Command;
use std::fs;

#[derive(Deserialize)]
struct ScanRequest {
    path: Option<String>,
    url: Option<String>,
    ai: bool,
    json_output: bool,
}

#[post("/scan")]
async fn scan(req: web::Json<ScanRequest>) -> impl Responder {
    if req.path.is_none() && req.url.is_none() {
        return HttpResponse::BadRequest().body("Either 'path' or 'url' must be provided.");
    }
    if req.path.is_some() && req.url.is_some() {
        return HttpResponse::BadRequest().body("Cannot provide both 'path' and 'url'.");
    }

    let json_output = req.json_output;
    let ai = req.ai;
    let url = req.url.clone();
    let path = req.path.clone();

    let scan_result = web::block(move || {
        let mut temp_dir_path: Option<String> = None;
        let target_path = if let Some(u) = &url {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let temp_path = format!("/tmp/pyspector_scan_{}", timestamp);

            let output = Command::new("git")
                .args(&["clone", "--depth", "1", u, &temp_path])
                .output();

            match output {
                Ok(o) if o.status.success() => {
                    temp_dir_path = Some(temp_path.clone());
                    temp_path
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    return Err(format!("Failed to clone repository: {}", stderr));
                }
                Err(e) => return Err(format!("Failed to execute git clone: {}", e)),
            }
        } else {
            path.clone().unwrap()
        };

        let result = Python::with_gil(|py| -> Result<String, String> {
            // Import the required modules
            let pyspector_cli = py.import("pyspector.cli").map_err(|e| {
                format!("Failed to import pyspector.cli: {}. Is PySpector installed?", e)
            })?;
            
            let pyspector_config = py.import("pyspector.config").map_err(|e| {
                format!("Failed to import pyspector.config: {}", e)
            })?;
            
            let pyspector_reporting = py.import("pyspector.reporting").map_err(|e| {
                format!("Failed to import pyspector.reporting: {}", e)
            })?;

            let pyspector_rust_core = py.import("pyspector._rust_core").map_err(|e| {
                format!("Failed to import pyspector._rust_core: {}", e)
            })?;

            // Load configuration
            let config = pyspector_config
                .call_method1("load_config", (py.None(),))
                .map_err(|e| format!("Failed to load config: {}", e))?;

            // Get rules TOML string
            let rules_toml_str = pyspector_config
                .call_method1("get_default_rules", (ai,))
                .map_err(|e| format!("Failed to get default rules: {}", e))?;

            // Create Path object for the scan target
            let pathlib = py.import("pathlib").map_err(|e| {
                format!("Failed to import pathlib: {}", e)
            })?;
            
            let path_obj = pathlib
                .call_method1("Path", (&target_path,))
                .map_err(|e| format!("Failed to create Path object: {}", e))?;

            // Get Python file ASTs
            let python_files_data = pyspector_cli
                .call_method1("get_python_file_asts", (path_obj,))
                .map_err(|e| format!("Failed to get Python file ASTs: {}", e))?;

            // Run the scan
            let raw_issues = pyspector_rust_core
                .call_method1(
                    "run_scan",
                    (&target_path, rules_toml_str, config, python_files_data),
                )
                .map_err(|e| format!("Scan failed: {}", e))?;

            // Generate the report
            let report_format = if json_output { "json" } else { "console" };
            let reporter = pyspector_reporting
                .call_method1("Reporter", (raw_issues, report_format))
                .map_err(|e| format!("Failed to create reporter: {}", e))?;
            
            let output: String = reporter
                .call_method0("generate")
                .map_err(|e| format!("Failed to generate report: {}", e))?
                .extract()
                .map_err(|e| format!("Failed to extract report string: {}", e))?;

            Ok(output)
        });

        // Cleanup temporary directory
        if let Some(temp_dir) = temp_dir_path {
            let _ = fs::remove_dir_all(temp_dir);
        }

        result
    })
    .await;

    match scan_result {
        Ok(Ok(output)) => {
            if json_output {
                HttpResponse::Ok()
                    .content_type("application/json")
                    .body(output)
            } else {
                HttpResponse::Ok()
                    .content_type("text/plain")
                    .body(output)
            }
        }
        Ok(Err(e)) => HttpResponse::InternalServerError()
            .body(format!("Scan failed: {}", e)),
        Err(e) => HttpResponse::InternalServerError()
            .body(format!("Internal error: {}", e)),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let gov_conf = GovernorConfigBuilder::default()
        .per_second(12)
        .burst_size(5)
        .finish()
        .unwrap();

    println!("PySpector API started on port 10000!");

    HttpServer::new(move || {
        let cors = Cors::permissive();
        
        App::new()
            .wrap(cors)
            .wrap(Governor::new(&gov_conf))
            .service(scan)
    })
    .bind(("0.0.0.0", 10000))?
    .run()
    .await
}
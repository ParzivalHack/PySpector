use actix_web::{post, web, App, HttpServer, HttpResponse, Responder};
use actix_governor::{Governor, GovernorConfigBuilder};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde::Deserialize;
use std::path::Path;
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

            let sys = py.import("sys").map_err(|e| e.to_string())?;
            let path_list = sys.getattr("path").map_err(|e| e.to_string())?;
            
            // Try to find the source directory
            // 1. Check if we are in /app (Docker) and src exists
            // 2. Fallback to current directory + src
            let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
            let src_path = cwd.join("src");
            
            if src_path.exists() {
                 path_list.call_method1("append", (src_path.to_str().unwrap(),)).map_err(|e| e.to_string())?;
            } else {

                println!("Warning: Could not find 'src' directory at {:?}. Python imports might fail.", src_path);
            }


            let cli_mod = py.import("pyspector.cli").map_err(|e| format!("Failed to import pyspector.cli: {}. Ensure 'src' directory is in PYTHONPATH or current directory.", e))?;
            let config_mod = py.import("pyspector.config").map_err(|e| e.to_string())?;
            let rust_core_mod = py.import("pyspector._rust_core").map_err(|e| e.to_string())?;
            let reporting_mod = py.import("pyspector.reporting").map_err(|e| e.to_string())?;


            let config = config_mod.call_method1("load_config", (py.None(),)).map_err(|e| e.to_string())?;


            let rules_toml_str = config_mod.call_method1("get_default_rules", (ai,)).map_err(|e| e.to_string())?;


            let pathlib = py.import("pathlib").map_err(|e| e.to_string())?;
            let path_obj = pathlib.call_method1("Path", (&target_path,)).map_err(|e| e.to_string())?;
            let python_files_data = cli_mod.call_method1("get_python_file_asts", (path_obj,)).map_err(|e| e.to_string())?;


            let raw_issues = rust_core_mod.call_method1("run_scan", (
                &target_path,
                rules_toml_str,
                config,
                python_files_data
            )).map_err(|e| e.to_string())?;


            let report_format = if json_output { "json" } else { "console" };
            let reporter = reporting_mod.call_method1("Reporter", (raw_issues, report_format)).map_err(|e| e.to_string())?;
            let output: String = reporter.call_method0("generate").map_err(|e| e.to_string())?.extract().map_err(|e| e.to_string())?;

            Ok(output)
        });


        if let Some(temp_dir) = temp_dir_path {
            let _ = fs::remove_dir_all(temp_dir);
        }

        result
    }).await;

    match scan_result {
        Ok(Ok(output)) => {
            if json_output {
                HttpResponse::Ok().content_type("application/json").body(output)
            } else {
                HttpResponse::Ok().content_type("text/plain").body(output)
            }
        },
        Ok(Err(e)) => HttpResponse::InternalServerError().body(format!("Scan failed: {}", e)),
        Err(e) => HttpResponse::InternalServerError().body(format!("Internal error: {}", e)),
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
        App::new()
            .wrap(Governor::new(&gov_conf))
            .service(scan)
    })
    .bind(("0.0.0.0", 10000))?
    .run()
    .await
}
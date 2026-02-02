use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

mod ast_parser;
mod graph;
mod issues;
mod rules;
mod analysis;
mod supply_chain;


use issues::{Issue, Severity};
use rules::RuleSet;
use analysis::{run_analysis, AnalysisContext};
use ast_parser::PythonFile;

#[pymodule]
fn _rust_core(m: &Bound<'_, PyModule>) -> PyResult<()> { 
    m.add_class::<Issue>()?;
    m.add_class::<Severity>()?;

    #[pyfn(m)]
    #[pyo3(name = "run_scan")]
    fn run_scan_py(
        py: Python,
        path: String,
        rules_toml_str: String,
        config: &Bound<'_, PyDict>,
        python_files_data: &Bound<'_, PyList>,
    ) -> PyResult<PyObject> {
        
        let exclusions: Vec<String> = config.get_item("exclude")?.map_or(Ok(Vec::new()), |v| v.extract())?;

        let ruleset: RuleSet = toml::from_str(&rules_toml_str).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to parse rules: {}", e))
        })?;

        let mut py_files: Vec<PythonFile> = Vec::new();
        for item in python_files_data.iter() {
            let file_dict: &Bound<'_, PyDict> = item.downcast()?;
            let file_path: String = file_dict.get_item("file_path")?.unwrap().extract()?;
            let content: String = file_dict.get_item("content")?.unwrap().extract()?;
            let ast_json: String = file_dict.get_item("ast_json")?.unwrap().extract()?;

            py_files.push(PythonFile::new(file_path, content, ast_json));
        }

        let context = AnalysisContext {
            root_path: path,
            exclusions,
            ruleset,
            py_files: &py_files,
        };

        let issues = py.allow_threads(|| run_analysis(context));

        let py_issues = PyList::empty_bound(py);
        for issue in issues {
            py_issues.append(Py::new(py, issue)?)?;
        }
        
        Ok(py_issues.to_object(py))
    }



    #[pyfn(m)]
    #[pyo3(name = "scan_supply_chain")]
    fn scan_supply_chain_py(
        py: Python,
        project_path: String,
    ) -> PyResult<PyObject> {
        let vulnerabilities = py.allow_threads(|| {
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

        Ok(py_list.to_object(py))
    }

    Ok(())
}
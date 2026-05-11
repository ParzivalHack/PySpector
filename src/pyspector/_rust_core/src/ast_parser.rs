use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct AstNode {
    pub node_type: String,
    pub lineno: isize,
    pub col_offset: isize,
    #[serde(default)]
    pub children: HashMap<String, Vec<AstNode>>,
    #[serde(default)]
    pub fields: HashMap<String, Option<serde_json::Value>>,
}

#[derive(Debug)]
pub struct PythonFile {
    pub file_path: String,
    pub content: String,
    pub ast: Option<AstNode>,
}

impl PythonFile {
    pub fn new(file_path: String, content: String, ast_json: String) -> Self {
        let ast: Option<AstNode> = serde_json::from_str(&ast_json).ok();
        Self {
            file_path,
            content,
            ast,
        }
    }
}

use crate::ast_parser::AstNode;
use std::collections::{HashMap, HashSet};

pub type BlockId = usize;

#[derive(Debug, Clone)]
pub enum EdgeType {
    Unconditional,
    Conditional(bool),
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    pub statements: Vec<AstNode>,
    pub predecessors: HashSet<BlockId>,
    pub successors: HashMap<BlockId, EdgeType>,
}

impl BasicBlock {
    pub fn new(id: BlockId) -> Self {
        Self {
            id,
            statements: Vec::new(),
            predecessors: HashSet::new(),
            successors: HashMap::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct ControlFlowGraph {
    pub blocks: HashMap<BlockId, BasicBlock>,
    pub entry: BlockId,
    pub exits: HashSet<BlockId>,
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        let mut blocks = HashMap::new();
        let entry_block = BasicBlock::new(0);
        let entry_id = entry_block.id;
        blocks.insert(entry_id, entry_block);
        Self {
            blocks,
            entry: entry_id,
            exits: HashSet::new(),
        }
    }

    pub fn add_block(&mut self) -> &mut BasicBlock {
        let new_id = self.blocks.len();
        let new_block = BasicBlock::new(new_id);
        self.blocks.insert(new_id, new_block);
        self.blocks.get_mut(&new_id).unwrap()
    }

    pub fn add_edge(&mut self, from: BlockId, to: BlockId, edge_type: EdgeType) {
        if let Some(from_block) = self.blocks.get_mut(&from) {
            from_block.successors.insert(to, edge_type);
        }
        if let Some(to_block) = self.blocks.get_mut(&to) {
            to_block.predecessors.insert(from);
        }
    }
}

// CORRECTED: Definition for the global Call Graph now includes the 'graph' field
#[derive(Debug, Default)]
pub struct CallGraph<'a> {
    pub graph: HashMap<String, HashSet<String>>,
    pub functions: HashMap<String, &'a AstNode>,
    pub file_contents: HashMap<String, String>,
}

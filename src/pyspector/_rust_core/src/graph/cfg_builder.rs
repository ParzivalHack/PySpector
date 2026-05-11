use crate::ast_parser::AstNode;
use crate::graph::representation::{BlockId, ControlFlowGraph, EdgeType};
use std::collections::HashSet;

// Main function to build a CFG from a function's AST node
pub fn build_cfg(function_node: &AstNode) -> ControlFlowGraph {
    let mut cfg = ControlFlowGraph::new();
    if let Some(body) = function_node.children.get("body") {
        let mut loop_exits = HashSet::new();
        let entry_id = cfg.entry; // Read the value into a variable first
        build_from_statements(&mut cfg, body, entry_id, &mut loop_exits); // Then use the variable
    }
    cfg
}

// A recursive function to build the CFG from a list of statements
fn build_from_statements(
    cfg: &mut ControlFlowGraph,
    stmts: &[AstNode],
    mut current_block_id: BlockId,
    loop_exits: &mut HashSet<BlockId>,
) -> BlockId {
    for stmt in stmts {
        match stmt.node_type.as_str() {
            "If" => {
                // Create blocks for the two branches and the merge point after the if/else
                let if_body_block_id = cfg.add_block().id;
                let merge_block_id = cfg.add_block().id;

                // The 'else' block is optional
                let else_body_block_id =
                    if stmt.children.get("orelse").map_or(false, |v| !v.is_empty()) {
                        cfg.add_block().id
                    } else {
                        merge_block_id // If no else, the false branch goes straight to merge
                    };

                // Add edges from the current block to the branches
                cfg.add_edge(
                    current_block_id,
                    if_body_block_id,
                    EdgeType::Conditional(true),
                );
                cfg.add_edge(
                    current_block_id,
                    else_body_block_id,
                    EdgeType::Conditional(false),
                );

                // Recursively build the CFG for the 'if' body
                if let Some(if_body) = stmt.children.get("body") {
                    let final_if_block =
                        build_from_statements(cfg, if_body, if_body_block_id, loop_exits);
                    cfg.add_edge(final_if_block, merge_block_id, EdgeType::Unconditional);
                }

                // Recursively build the CFG for the 'else' body
                if let Some(orelse_body) = stmt.children.get("orelse") {
                    if !orelse_body.is_empty() {
                        let final_else_block =
                            build_from_statements(cfg, orelse_body, else_body_block_id, loop_exits);
                        cfg.add_edge(final_else_block, merge_block_id, EdgeType::Unconditional);
                    }
                }

                current_block_id = merge_block_id;
            }
            "For" | "While" => {
                let loop_body_id = cfg.add_block().id;
                let after_loop_id = cfg.add_block().id;

                // Edge from current block into the loop
                cfg.add_edge(current_block_id, loop_body_id, EdgeType::Unconditional);

                // Add the exit point for any 'break' statements
                loop_exits.insert(after_loop_id);
                if let Some(loop_body) = stmt.children.get("body") {
                    let final_loop_block =
                        build_from_statements(cfg, loop_body, loop_body_id, loop_exits);
                    // Edge from the end of the loop body back to the start
                    cfg.add_edge(final_loop_block, loop_body_id, EdgeType::Unconditional);
                }
                loop_exits.remove(&after_loop_id);

                // Edge to exit the loop
                cfg.add_edge(current_block_id, after_loop_id, EdgeType::Unconditional);

                current_block_id = after_loop_id;
            }
            "Break" => {
                // Connect the break statement to the loop's exit block
                if let Some(exit_id) = loop_exits.iter().last() {
                    cfg.add_edge(current_block_id, *exit_id, EdgeType::Unconditional);
                }
                // A break creates a new, unconnected block after it to stop flow
                current_block_id = cfg.add_block().id;
            }
            // For all other statements, just add them to the current block
            _ => {
                if let Some(block) = cfg.blocks.get_mut(&current_block_id) {
                    block.statements.push(stmt.clone());
                }
            }
        }
    }
    cfg.exits.insert(current_block_id);
    current_block_id
}

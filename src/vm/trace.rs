//! Execution trace for ZK proof generation (Plonky3 AIR preparation).
//!
//! Every VM execution produces a trace that can be converted into
//! an AIR matrix for Plonky3 STARK verification in Phase 3b.

use serde::{Deserialize, Serialize};

/// A single step in the VM execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmStep {
    /// Program counter before execution
    pub pc: usize,
    /// Opcode byte executed
    pub opcode: u8,
    /// Top 4 stack elements (index 0 = top)
    pub stack_top: [u64; 4],
    /// Gas remaining before this step
    pub gas_remaining: u64,
}

/// Complete execution trace of a VM run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// All execution steps
    pub steps: Vec<VmStep>,
    /// Initial storage root (set externally after execution)
    pub initial_state_root: [u8; 32],
    /// Final storage root (set externally after execution)
    pub final_state_root: [u8; 32],
    /// Total gas consumed
    pub gas_used: u64,
}

impl ExecutionTrace {
    /// Create an empty trace.
    pub fn new() -> Self {
        Self {
            steps: Vec::with_capacity(256),
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            gas_used: 0,
        }
    }

    /// Record a single execution step.
    pub fn record_step(&mut self, step: VmStep) {
        self.steps.push(step);
    }

    /// Number of execution steps.
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Convert trace to a flat matrix for AIR constraint system.
    /// Each row = [pc, opcode, stack[0], stack[1], stack[2], stack[3], gas]
    /// Returns (num_rows, num_cols, flat_data).
    pub fn to_air_matrix(&self) -> (usize, usize, Vec<u64>) {
        const COLS: usize = 7;
        let rows = self.steps.len();
        let mut data = Vec::with_capacity(rows * COLS);
        for step in &self.steps {
            data.push(step.pc as u64);
            data.push(step.opcode as u64);
            data.push(step.stack_top[0]);
            data.push(step.stack_top[1]);
            data.push(step.stack_top[2]);
            data.push(step.stack_top[3]);
            data.push(step.gas_remaining);
        }
        (rows, COLS, data)
    }
}

impl Default for ExecutionTrace {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_record() {
        let mut trace = ExecutionTrace::new();
        trace.record_step(VmStep {
            pc: 0,
            opcode: 0x01,
            stack_top: [42, 0, 0, 0],
            gas_remaining: 100_000,
        });
        trace.record_step(VmStep {
            pc: 9,
            opcode: 0x10,
            stack_top: [42, 10, 0, 0],
            gas_remaining: 99_999,
        });
        assert_eq!(trace.step_count(), 2);
    }

    #[test]
    fn test_air_matrix() {
        let mut trace = ExecutionTrace::new();
        trace.record_step(VmStep {
            pc: 0,
            opcode: 0x01,
            stack_top: [10, 0, 0, 0],
            gas_remaining: 1000,
        });
        let (rows, cols, data) = trace.to_air_matrix();
        assert_eq!(rows, 1);
        assert_eq!(cols, 7);
        assert_eq!(data.len(), 7);
        assert_eq!(data[0], 0);     // pc
        assert_eq!(data[1], 0x01);  // opcode
        assert_eq!(data[2], 10);    // stack top
        assert_eq!(data[6], 1000);  // gas
    }
}

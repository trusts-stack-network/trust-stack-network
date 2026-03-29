//! Gas cost table for TSN zkVM opcodes.

use super::opcode::OpCode;

/// Gas costs per opcode category.
pub const GAS_STACK_OP: u64 = 1;
pub const GAS_ARITHMETIC: u64 = 3;
pub const GAS_COMPARISON: u64 = 3;
pub const GAS_LOGIC: u64 = 3;
pub const GAS_JUMP: u64 = 5;
pub const GAS_SLOAD: u64 = 100;
pub const GAS_SSTORE: u64 = 200;
pub const GAS_SSTORE_NEW_SLOT: u64 = 20_000;
pub const GAS_MLOAD: u64 = 3;
pub const GAS_MSTORE: u64 = 3;
pub const GAS_HASH_POSEIDON: u64 = 50;
pub const GAS_VERIFY_SIG: u64 = 5_000;
pub const GAS_NOTE_COMMIT: u64 = 200;
pub const GAS_CONTEXT: u64 = 2;
pub const GAS_CALL: u64 = 700;
pub const GAS_TRANSFER: u64 = 10_000;
pub const GAS_EMIT_EVENT: u64 = 50;
pub const GAS_BALANCE: u64 = 100;

/// Block-level gas limit.
pub const BLOCK_GAS_LIMIT: u64 = 1_000_000;

/// Maximum bytecode size (64 KB).
pub const CONTRACT_MAX_SIZE: usize = 65_536;

/// Maximum storage slots per contract.
pub const CONTRACT_MAX_STORAGE_SLOTS: u64 = 100_000;

/// Maximum call depth for inter-contract calls.
pub const CONTRACT_MAX_CALL_DEPTH: u8 = 8;

/// Maximum stack depth.
pub const VM_MAX_STACK: usize = 1024;

/// Maximum memory slots.
pub const VM_MAX_MEMORY: usize = 4096;

/// Return the gas cost of executing a single opcode.
pub fn gas_cost(op: OpCode) -> u64 {
    match op {
        // Stack
        OpCode::Push | OpCode::PushBytes32 | OpCode::Pop |
        OpCode::Dup | OpCode::Swap | OpCode::Rot => GAS_STACK_OP,

        // Arithmetic
        OpCode::Add | OpCode::Sub | OpCode::Mul |
        OpCode::Div | OpCode::Mod => GAS_ARITHMETIC,

        // Comparison
        OpCode::Eq | OpCode::Neq | OpCode::Lt | OpCode::Gt |
        OpCode::Lte | OpCode::Gte => GAS_COMPARISON,

        // Logic
        OpCode::And | OpCode::Or | OpCode::Not => GAS_LOGIC,

        // Control flow
        OpCode::Jump | OpCode::JumpIf => GAS_JUMP,
        OpCode::Return | OpCode::Halt => GAS_STACK_OP,
        OpCode::Abort => GAS_STACK_OP,

        // Storage
        OpCode::SLoad => GAS_SLOAD,
        OpCode::SStore => GAS_SSTORE, // new-slot surcharge applied at runtime

        // Memory
        OpCode::MLoad => GAS_MLOAD,
        OpCode::MStore => GAS_MSTORE,

        // Crypto
        OpCode::HashPoseidon => GAS_HASH_POSEIDON,
        OpCode::VerifySig => GAS_VERIFY_SIG,
        OpCode::NoteCommit => GAS_NOTE_COMMIT,

        // Context
        OpCode::Caller | OpCode::SelfAddr | OpCode::BlockHeight |
        OpCode::BlockTimestamp | OpCode::TxFee | OpCode::CallValue => GAS_CONTEXT,

        // Calls
        OpCode::Call | OpCode::DelegateCall => GAS_CALL,
        OpCode::Transfer => GAS_TRANSFER,
        OpCode::Balance => GAS_BALANCE,

        // Events
        OpCode::EmitEvent => GAS_EMIT_EVENT,
    }
}

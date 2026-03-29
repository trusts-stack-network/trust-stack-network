//! TSN zkVM Opcodes — Stack-based bytecode instruction set.
//!
//! Minimalist instruction set for smart contract execution on TSN.
//! All arithmetic is u64 with checked overflow (ABORT on overflow).

use serde::{Deserialize, Serialize};

/// Single-byte opcode for the TSN zkVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum OpCode {
    // ── Stack manipulation ───────────────────────────────
    /// Push a u64 immediate (next 8 bytes LE)
    Push = 0x01,
    /// Push 32 bytes onto the stack as a hash/address (next 32 bytes)
    PushBytes32 = 0x02,
    /// Pop top of stack
    Pop = 0x03,
    /// Duplicate top of stack
    Dup = 0x04,
    /// Swap top two elements
    Swap = 0x05,
    /// Rotate top three elements (a b c → b c a)
    Rot = 0x06,

    // ── Arithmetic (u64 checked) ─────────────────────────
    Add = 0x10,
    Sub = 0x11,
    Mul = 0x12,
    Div = 0x13,
    Mod = 0x14,

    // ── Comparison ───────────────────────────────────────
    /// Equal: push 1 if a == b, else 0
    Eq = 0x20,
    /// Not equal
    Neq = 0x21,
    /// Less than
    Lt = 0x22,
    /// Greater than
    Gt = 0x23,
    /// Less than or equal
    Lte = 0x24,
    /// Greater than or equal
    Gte = 0x25,

    // ── Logic ────────────────────────────────────────────
    And = 0x30,
    Or = 0x31,
    Not = 0x32,

    // ── Control flow ─────────────────────────────────────
    /// Unconditional jump (next 4 bytes = offset u32 LE)
    Jump = 0x40,
    /// Conditional jump: pop top, jump if nonzero
    JumpIf = 0x41,
    /// Return: stop execution, top of stack is return value
    Return = 0x42,
    /// Halt: stop execution (no return value)
    Halt = 0x43,
    /// Abort with error code (next 1 byte)
    Abort = 0x44,

    // ── Contract storage ─────────────────────────────────
    /// Load from storage: pop slot key, push value
    SLoad = 0x50,
    /// Store to storage: pop slot key, pop value, write
    SStore = 0x51,

    // ── Memory (temporary, per-execution) ────────────────
    /// Load from memory: pop index, push value
    MLoad = 0x52,
    /// Store to memory: pop index, pop value, write
    MStore = 0x53,

    // ── Crypto ───────────────────────────────────────────
    /// Poseidon hash: pop 2 elements, push hash
    HashPoseidon = 0x60,
    /// Verify ML-DSA-65 signature: pop (msg_hash, sig_ptr, pk_ptr), push 1/0
    VerifySig = 0x61,
    /// Compute note commitment: pop (value, pk_hash, randomness), push commitment
    NoteCommit = 0x62,

    // ── Context (read-only blockchain state) ─────────────
    /// Push caller's pk_hash (32 bytes as 4×u64)
    Caller = 0x70,
    /// Push this contract's address (32 bytes as 4×u64)
    SelfAddr = 0x71,
    /// Push current block height
    BlockHeight = 0x72,
    /// Push current block timestamp
    BlockTimestamp = 0x73,
    /// Push transaction fee
    TxFee = 0x74,
    /// Push call value (TSN sent with this call)
    CallValue = 0x75,

    // ── Inter-contract calls ─────────────────────────────
    /// Call another contract: pop (addr, gas_limit, arg_count, args...), push result
    Call = 0x80,
    /// Delegate call (use caller's storage): same args as Call
    DelegateCall = 0x81,
    /// Transfer value: pop (recipient_addr, amount), push 1/0
    Transfer = 0x82,
    /// Get contract balance
    Balance = 0x83,

    // ── Events / Logging ─────────────────────────────────
    /// Emit event: pop (topic, data_count, data...)
    EmitEvent = 0x90,
}

impl OpCode {
    /// Decode a single byte into an opcode.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Push),
            0x02 => Some(Self::PushBytes32),
            0x03 => Some(Self::Pop),
            0x04 => Some(Self::Dup),
            0x05 => Some(Self::Swap),
            0x06 => Some(Self::Rot),

            0x10 => Some(Self::Add),
            0x11 => Some(Self::Sub),
            0x12 => Some(Self::Mul),
            0x13 => Some(Self::Div),
            0x14 => Some(Self::Mod),

            0x20 => Some(Self::Eq),
            0x21 => Some(Self::Neq),
            0x22 => Some(Self::Lt),
            0x23 => Some(Self::Gt),
            0x24 => Some(Self::Lte),
            0x25 => Some(Self::Gte),

            0x30 => Some(Self::And),
            0x31 => Some(Self::Or),
            0x32 => Some(Self::Not),

            0x40 => Some(Self::Jump),
            0x41 => Some(Self::JumpIf),
            0x42 => Some(Self::Return),
            0x43 => Some(Self::Halt),
            0x44 => Some(Self::Abort),

            0x50 => Some(Self::SLoad),
            0x51 => Some(Self::SStore),
            0x52 => Some(Self::MLoad),
            0x53 => Some(Self::MStore),

            0x60 => Some(Self::HashPoseidon),
            0x61 => Some(Self::VerifySig),
            0x62 => Some(Self::NoteCommit),

            0x70 => Some(Self::Caller),
            0x71 => Some(Self::SelfAddr),
            0x72 => Some(Self::BlockHeight),
            0x73 => Some(Self::BlockTimestamp),
            0x74 => Some(Self::TxFee),
            0x75 => Some(Self::CallValue),

            0x80 => Some(Self::Call),
            0x81 => Some(Self::DelegateCall),
            0x82 => Some(Self::Transfer),
            0x83 => Some(Self::Balance),

            0x90 => Some(Self::EmitEvent),

            _ => None,
        }
    }

    /// Encode this opcode to a single byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

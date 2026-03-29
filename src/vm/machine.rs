//! TSN zkVM — Stack-based bytecode interpreter.

use std::collections::HashMap;
use super::opcode::OpCode;
use super::gas::{self, gas_cost};
use super::trace::{ExecutionTrace, VmStep};

/// Execution context passed to the VM.
#[derive(Debug, Clone)]
pub struct ExecContext {
    pub caller: [u8; 32],
    pub self_addr: [u8; 32],
    pub block_height: u64,
    pub block_timestamp: u64,
    pub tx_fee: u64,
    pub call_value: u64,
    pub call_depth: u8,
}

/// Event emitted during contract execution.
#[derive(Debug, Clone)]
pub struct ContractEvent {
    pub topic: u64,
    pub data: Vec<u64>,
}

/// Transfer request generated during execution.
#[derive(Debug, Clone)]
pub struct TransferRequest {
    pub to: [u8; 32],
    pub amount: u64,
}

/// Result of VM execution.
#[derive(Debug)]
pub struct ExecResult {
    pub success: bool,
    pub return_value: Option<u64>,
    pub gas_used: u64,
    pub storage_writes: HashMap<u64, u64>,
    pub events: Vec<ContractEvent>,
    pub transfers: Vec<TransferRequest>,
    pub trace: ExecutionTrace,
    pub error: Option<VmError>,
}

/// VM error types.
#[derive(Debug, Clone)]
pub enum VmError {
    OutOfGas,
    StackOverflow,
    StackUnderflow,
    InvalidOpcode(u8),
    InvalidJump(u32),
    DivisionByZero,
    ArithmeticOverflow,
    MemoryOutOfBounds(usize),
    StorageLimitExceeded,
    MaxCallDepthExceeded,
    AbortCode(u8),
    InvalidBytecode,
    InvalidPushBytes,
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfGas => write!(f, "out of gas"),
            Self::StackOverflow => write!(f, "stack overflow"),
            Self::StackUnderflow => write!(f, "stack underflow"),
            Self::InvalidOpcode(b) => write!(f, "invalid opcode: 0x{:02x}", b),
            Self::InvalidJump(off) => write!(f, "invalid jump target: {}", off),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::ArithmeticOverflow => write!(f, "arithmetic overflow"),
            Self::MemoryOutOfBounds(i) => write!(f, "memory out of bounds: {}", i),
            Self::StorageLimitExceeded => write!(f, "storage slot limit exceeded"),
            Self::MaxCallDepthExceeded => write!(f, "max call depth exceeded"),
            Self::AbortCode(c) => write!(f, "abort code: {}", c),
            Self::InvalidBytecode => write!(f, "invalid bytecode"),
            Self::InvalidPushBytes => write!(f, "invalid push bytes"),
        }
    }
}

/// The TSN virtual machine.
pub struct Vm {
    stack: Vec<u64>,
    memory: Vec<u64>,
    pc: usize,
    gas_remaining: u64,
    gas_used: u64,

    // Contract storage: slot → value (reads come from snapshot, writes buffered)
    storage_snapshot: HashMap<u64, u64>,
    storage_writes: HashMap<u64, u64>,
    storage_slot_count: u64,

    // Side effects
    events: Vec<ContractEvent>,
    transfers: Vec<TransferRequest>,

    // Execution trace (for ZK proof generation)
    trace: ExecutionTrace,

    // Context
    ctx: ExecContext,
}

impl Vm {
    /// Create a new VM instance.
    pub fn new(
        gas_limit: u64,
        ctx: ExecContext,
        storage_snapshot: HashMap<u64, u64>,
    ) -> Self {
        let slot_count = storage_snapshot.len() as u64;
        Self {
            stack: Vec::with_capacity(64),
            memory: vec![0u64; 256],
            pc: 0,
            gas_remaining: gas_limit,
            gas_used: 0,
            storage_snapshot,
            storage_writes: HashMap::new(),
            storage_slot_count: slot_count,
            events: Vec::new(),
            transfers: Vec::new(),
            trace: ExecutionTrace::new(),
            ctx,
        }
    }

    /// Execute bytecode and return the result.
    pub fn execute(&mut self, bytecode: &[u8]) -> ExecResult {
        let result = self.run(bytecode);
        let return_value = if result.is_ok() {
            self.stack.last().copied()
        } else {
            None
        };

        ExecResult {
            success: result.is_ok(),
            return_value,
            gas_used: self.gas_used,
            storage_writes: if result.is_ok() {
                self.storage_writes.clone()
            } else {
                HashMap::new() // rollback on failure
            },
            events: if result.is_ok() {
                self.events.clone()
            } else {
                Vec::new()
            },
            transfers: if result.is_ok() {
                self.transfers.clone()
            } else {
                Vec::new()
            },
            trace: self.trace.clone(),
            error: result.err(),
        }
    }

    fn run(&mut self, bytecode: &[u8]) -> Result<(), VmError> {
        loop {
            if self.pc >= bytecode.len() {
                return Ok(()); // implicit halt
            }

            let byte = bytecode[self.pc];
            let op = OpCode::from_byte(byte).ok_or(VmError::InvalidOpcode(byte))?;

            // Charge gas
            let cost = gas_cost(op);
            self.consume_gas(cost)?;

            // Record trace step
            self.trace.record_step(VmStep {
                pc: self.pc,
                opcode: byte,
                stack_top: self.stack_top_4(),
                gas_remaining: self.gas_remaining,
            });

            self.pc += 1;

            match op {
                // ── Stack ────────────────────────────
                OpCode::Push => {
                    let val = self.read_u64(bytecode)?;
                    self.push(val)?;
                }
                OpCode::PushBytes32 => {
                    let bytes = self.read_bytes32(bytecode)?;
                    // Push as 4 u64s (big-endian chunks)
                    for i in 0..4 {
                        let offset = i * 8;
                        let val = u64::from_le_bytes(
                            bytes[offset..offset + 8].try_into().unwrap()
                        );
                        self.push(val)?;
                    }
                }
                OpCode::Pop => { self.pop()?; }
                OpCode::Dup => {
                    let val = *self.stack.last().ok_or(VmError::StackUnderflow)?;
                    self.push(val)?;
                }
                OpCode::Swap => {
                    let len = self.stack.len();
                    if len < 2 { return Err(VmError::StackUnderflow); }
                    self.stack.swap(len - 1, len - 2);
                }
                OpCode::Rot => {
                    let len = self.stack.len();
                    if len < 3 { return Err(VmError::StackUnderflow); }
                    let a = self.stack[len - 3];
                    self.stack[len - 3] = self.stack[len - 2];
                    self.stack[len - 2] = self.stack[len - 1];
                    self.stack[len - 1] = a;
                }

                // ── Arithmetic ───────────────────────
                OpCode::Add => {
                    let (b, a) = (self.pop()?, self.pop()?);
                    self.push(a.checked_add(b).ok_or(VmError::ArithmeticOverflow)?)?;
                }
                OpCode::Sub => {
                    let (b, a) = (self.pop()?, self.pop()?);
                    self.push(a.checked_sub(b).ok_or(VmError::ArithmeticOverflow)?)?;
                }
                OpCode::Mul => {
                    let (b, a) = (self.pop()?, self.pop()?);
                    self.push(a.checked_mul(b).ok_or(VmError::ArithmeticOverflow)?)?;
                }
                OpCode::Div => {
                    let (b, a) = (self.pop()?, self.pop()?);
                    if b == 0 { return Err(VmError::DivisionByZero); }
                    self.push(a / b)?;
                }
                OpCode::Mod => {
                    let (b, a) = (self.pop()?, self.pop()?);
                    if b == 0 { return Err(VmError::DivisionByZero); }
                    self.push(a % b)?;
                }

                // ── Comparison ───────────────────────
                OpCode::Eq  => { let (b, a) = (self.pop()?, self.pop()?); self.push((a == b) as u64)?; }
                OpCode::Neq => { let (b, a) = (self.pop()?, self.pop()?); self.push((a != b) as u64)?; }
                OpCode::Lt  => { let (b, a) = (self.pop()?, self.pop()?); self.push((a < b) as u64)?; }
                OpCode::Gt  => { let (b, a) = (self.pop()?, self.pop()?); self.push((a > b) as u64)?; }
                OpCode::Lte => { let (b, a) = (self.pop()?, self.pop()?); self.push((a <= b) as u64)?; }
                OpCode::Gte => { let (b, a) = (self.pop()?, self.pop()?); self.push((a >= b) as u64)?; }

                // ── Logic ────────────────────────────
                OpCode::And => { let (b, a) = (self.pop()?, self.pop()?); self.push(a & b)?; }
                OpCode::Or  => { let (b, a) = (self.pop()?, self.pop()?); self.push(a | b)?; }
                OpCode::Not => { let a = self.pop()?; self.push(if a == 0 { 1 } else { 0 })?; }

                // ── Control flow ─────────────────────
                OpCode::Jump => {
                    let offset = self.read_u32(bytecode)? as usize;
                    if offset >= bytecode.len() { return Err(VmError::InvalidJump(offset as u32)); }
                    self.pc = offset;
                }
                OpCode::JumpIf => {
                    let offset = self.read_u32(bytecode)? as usize;
                    let cond = self.pop()?;
                    if cond != 0 {
                        if offset >= bytecode.len() { return Err(VmError::InvalidJump(offset as u32)); }
                        self.pc = offset;
                    }
                }
                OpCode::Return => return Ok(()),
                OpCode::Halt => return Ok(()),
                OpCode::Abort => {
                    let code = if self.pc < bytecode.len() {
                        let c = bytecode[self.pc];
                        self.pc += 1;
                        c
                    } else {
                        0
                    };
                    return Err(VmError::AbortCode(code));
                }

                // ── Storage ──────────────────────────
                OpCode::SLoad => {
                    let slot = self.pop()?;
                    let val = self.storage_writes.get(&slot)
                        .or_else(|| self.storage_snapshot.get(&slot))
                        .copied()
                        .unwrap_or(0);
                    self.push(val)?;
                }
                OpCode::SStore => {
                    let slot = self.pop()?;
                    let val = self.pop()?;
                    // Extra gas for new slot
                    let is_new = !self.storage_snapshot.contains_key(&slot)
                        && !self.storage_writes.contains_key(&slot);
                    if is_new {
                        self.consume_gas(gas::GAS_SSTORE_NEW_SLOT - gas::GAS_SSTORE)?;
                        self.storage_slot_count += 1;
                        if self.storage_slot_count > gas::CONTRACT_MAX_STORAGE_SLOTS {
                            return Err(VmError::StorageLimitExceeded);
                        }
                    }
                    self.storage_writes.insert(slot, val);
                }

                // ── Memory ───────────────────────────
                OpCode::MLoad => {
                    let idx = self.pop()? as usize;
                    if idx >= gas::VM_MAX_MEMORY { return Err(VmError::MemoryOutOfBounds(idx)); }
                    // Extend memory if needed
                    if idx >= self.memory.len() {
                        self.memory.resize(idx + 1, 0);
                    }
                    self.push(self.memory[idx])?;
                }
                OpCode::MStore => {
                    let idx = self.pop()? as usize;
                    let val = self.pop()?;
                    if idx >= gas::VM_MAX_MEMORY { return Err(VmError::MemoryOutOfBounds(idx)); }
                    if idx >= self.memory.len() {
                        self.memory.resize(idx + 1, 0);
                    }
                    self.memory[idx] = val;
                }

                // ── Crypto ───────────────────────────
                OpCode::HashPoseidon => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    // Simple hash: we use a portable hash for now
                    // In production this would call the Poseidon2 hasher
                    let hash = portable_hash(a, b);
                    self.push(hash)?;
                }
                OpCode::VerifySig => {
                    // L4 audit fix: actually verify the signature instead of always returning 1.
                    // Stack: msg_hash (u64 low bits), sig_hash (u64 low bits), pk_hash (u64 low bits)
                    // In a full implementation, these would be pointers to memory buffers.
                    // For now, we do a portable hash check: push 1 only if hash(pk, msg) == sig
                    let msg = self.pop()?;
                    let sig = self.pop()?;
                    let pk = self.pop()?;
                    let expected = portable_hash(pk, msg);
                    if expected == sig {
                        self.push(1)?; // signature valid
                    } else {
                        self.push(0)?; // signature invalid
                    }
                }
                OpCode::NoteCommit => {
                    let randomness = self.pop()?;
                    let pk_hash = self.pop()?;
                    let value = self.pop()?;
                    let commitment = portable_hash(
                        portable_hash(value, pk_hash),
                        randomness,
                    );
                    self.push(commitment)?;
                }

                // ── Context ──────────────────────────
                OpCode::Caller => {
                    // Push first u64 of caller address (simplified)
                    let val = u64::from_le_bytes(self.ctx.caller[0..8].try_into().unwrap());
                    self.push(val)?;
                }
                OpCode::SelfAddr => {
                    let val = u64::from_le_bytes(self.ctx.self_addr[0..8].try_into().unwrap());
                    self.push(val)?;
                }
                OpCode::BlockHeight => self.push(self.ctx.block_height)?,
                OpCode::BlockTimestamp => self.push(self.ctx.block_timestamp)?,
                OpCode::TxFee => self.push(self.ctx.tx_fee)?,
                OpCode::CallValue => self.push(self.ctx.call_value)?,

                // ── Calls (stub — real implementation in contract/call.rs) ───
                OpCode::Call | OpCode::DelegateCall => {
                    if self.ctx.call_depth >= gas::CONTRACT_MAX_CALL_DEPTH {
                        return Err(VmError::MaxCallDepthExceeded);
                    }
                    // Pop args: addr, gas_limit, arg_count
                    let addr = self.pop()?;
                    let gas_limit = self.pop()?;
                    let arg_count = self.pop()?;
                    // Limit arg_count to prevent stack drain attacks
                    if arg_count > 256 {
                        return Err(VmError::StackUnderflow);
                    }
                    let mut args = Vec::with_capacity(arg_count as usize);
                    for _ in 0..arg_count {
                        args.push(self.pop()?);
                    }
                    // Phase 4 audit fix: return error code instead of silently succeeding.
                    // Real cross-contract calls require the ContractExecutor to dispatch.
                    // At VM level, we signal "call not available" by pushing error code 0xFFFF.
                    self.push(0xFFFF)?; // error: cross-contract calls not yet implemented
                }
                OpCode::Transfer => {
                    let amount = self.pop()?;
                    let to_low = self.pop()?;
                    let mut to = [0u8; 32];
                    to[0..8].copy_from_slice(&to_low.to_le_bytes());
                    self.transfers.push(TransferRequest { to, amount });
                    self.push(1)?; // success
                }
                OpCode::Balance => {
                    // Phase 4: Balance returns 0 for now — real lookup requires
                    // integration with the shielded state (not possible in pure VM).
                    // This is documented behavior: contracts should use Transfer, not Balance.
                    let _addr = self.pop()?;
                    self.push(0)?; // Balance always 0 in shielded model (no visible balances)
                }

                // ── Events ───────────────────────────
                OpCode::EmitEvent => {
                    let topic = self.pop()?;
                    let data_count = self.pop()?;
                    // Phase 4 audit fix: limit data_count to prevent event spam / memory exhaustion
                    const MAX_EVENT_DATA: u64 = 64;
                    if data_count > MAX_EVENT_DATA {
                        return Err(VmError::StackUnderflow); // reject oversized events
                    }
                    let mut data = Vec::with_capacity(data_count as usize);
                    for _ in 0..data_count {
                        data.push(self.pop()?);
                    }
                    self.events.push(ContractEvent { topic, data });
                }
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────

    fn push(&mut self, val: u64) -> Result<(), VmError> {
        if self.stack.len() >= gas::VM_MAX_STACK {
            return Err(VmError::StackOverflow);
        }
        self.stack.push(val);
        Ok(())
    }

    fn pop(&mut self) -> Result<u64, VmError> {
        self.stack.pop().ok_or(VmError::StackUnderflow)
    }

    fn consume_gas(&mut self, amount: u64) -> Result<(), VmError> {
        if self.gas_remaining < amount {
            self.gas_used += self.gas_remaining;
            self.gas_remaining = 0;
            return Err(VmError::OutOfGas);
        }
        self.gas_remaining -= amount;
        self.gas_used += amount;
        Ok(())
    }

    fn read_u64(&mut self, bytecode: &[u8]) -> Result<u64, VmError> {
        if self.pc + 8 > bytecode.len() {
            return Err(VmError::InvalidBytecode);
        }
        let val = u64::from_le_bytes(bytecode[self.pc..self.pc + 8].try_into().unwrap());
        self.pc += 8;
        Ok(val)
    }

    fn read_u32(&mut self, bytecode: &[u8]) -> Result<u32, VmError> {
        if self.pc + 4 > bytecode.len() {
            return Err(VmError::InvalidBytecode);
        }
        let val = u32::from_le_bytes(bytecode[self.pc..self.pc + 4].try_into().unwrap());
        self.pc += 4;
        Ok(val)
    }

    fn read_bytes32(&mut self, bytecode: &[u8]) -> Result<[u8; 32], VmError> {
        if self.pc + 32 > bytecode.len() {
            return Err(VmError::InvalidPushBytes);
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytecode[self.pc..self.pc + 32]);
        self.pc += 32;
        Ok(buf)
    }

    fn stack_top_4(&self) -> [u64; 4] {
        let len = self.stack.len();
        let mut top = [0u64; 4];
        for i in 0..4.min(len) {
            top[i] = self.stack[len - 1 - i];
        }
        top
    }
}

/// Portable deterministic hash (replacement for Poseidon when not in circuit).
/// Uses SipHash-like mixing for determinism.
fn portable_hash(a: u64, b: u64) -> u64 {
    let mut h = a.wrapping_mul(0x517cc1b727220a95);
    h = h.wrapping_add(b.wrapping_mul(0x6c62272e07bb0142));
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> ExecContext {
        ExecContext {
            caller: [1u8; 32],
            self_addr: [2u8; 32],
            block_height: 100,
            block_timestamp: 1700000000,
            tx_fee: 1000,
            call_value: 0,
            call_depth: 0,
        }
    }

    fn exec(bytecode: &[u8], gas: u64) -> ExecResult {
        let mut vm = Vm::new(gas, make_ctx(), HashMap::new());
        vm.execute(bytecode)
    }

    #[test]
    fn test_push_add_return() {
        // PUSH 10, PUSH 20, ADD, RETURN
        let mut bc = vec![OpCode::Push as u8];
        bc.extend_from_slice(&10u64.to_le_bytes());
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&20u64.to_le_bytes());
        bc.push(OpCode::Add as u8);
        bc.push(OpCode::Return as u8);

        let result = exec(&bc, 100_000);
        assert!(result.success);
        assert_eq!(result.return_value, Some(30));
    }

    #[test]
    fn test_arithmetic_overflow() {
        // PUSH u64::MAX, PUSH 1, ADD → overflow
        let mut bc = vec![OpCode::Push as u8];
        bc.extend_from_slice(&u64::MAX.to_le_bytes());
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&1u64.to_le_bytes());
        bc.push(OpCode::Add as u8);

        let result = exec(&bc, 100_000);
        assert!(!result.success);
        assert!(matches!(result.error, Some(VmError::ArithmeticOverflow)));
    }

    #[test]
    fn test_out_of_gas() {
        // Infinite loop: PUSH 1, JUMP 0
        let mut bc = vec![OpCode::Push as u8];
        bc.extend_from_slice(&1u64.to_le_bytes());
        bc.push(OpCode::Jump as u8);
        bc.extend_from_slice(&0u32.to_le_bytes());

        let result = exec(&bc, 50); // very little gas
        assert!(!result.success);
        assert!(matches!(result.error, Some(VmError::OutOfGas)));
    }

    #[test]
    fn test_storage_read_write() {
        let mut initial = HashMap::new();
        initial.insert(42, 999);

        // SLOAD slot 42, PUSH 1, ADD, SSTORE slot 42, SLOAD slot 42, RETURN
        let mut bc = vec![];
        // Push 42, SLOAD
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&42u64.to_le_bytes());
        bc.push(OpCode::SLoad as u8);
        // PUSH 1, ADD
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&1u64.to_le_bytes());
        bc.push(OpCode::Add as u8);
        // Push 42 (slot), swap, then SSTORE (slot, value order: pop slot, pop value)
        // SStore pops slot then value, so: stack has [1000], push 42
        // Wait: SStore pops slot first, then value. So we need: value on stack, then slot on top
        // Current stack: [1000]
        // Push slot 42
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&42u64.to_le_bytes());
        // Swap so slot is on top: [42, 1000] → swap → [1000, 42]
        // Actually SStore: pop slot, pop value. So we need slot on top, value below
        // Stack is [1000, 42] after push. SStore pops 42 (slot), then 1000 (value). Correct!
        bc.push(OpCode::SStore as u8);
        // Now SLOAD 42 to verify
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&42u64.to_le_bytes());
        bc.push(OpCode::SLoad as u8);
        bc.push(OpCode::Return as u8);

        let mut vm = Vm::new(100_000, make_ctx(), initial);
        let result = vm.execute(&bc);
        assert!(result.success);
        assert_eq!(result.return_value, Some(1000));
        assert_eq!(result.storage_writes.get(&42), Some(&1000));
    }

    #[test]
    fn test_conditional_jump() {
        // if (1) jump to PUSH 42, else PUSH 0
        let mut bc = vec![];
        // PUSH 1
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&1u64.to_le_bytes());
        // JUMPIF to offset (we'll fill in)
        bc.push(OpCode::JumpIf as u8);
        let jump_offset_pos = bc.len();
        bc.extend_from_slice(&0u32.to_le_bytes()); // placeholder
        // False branch: PUSH 0, RETURN
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&0u64.to_le_bytes());
        bc.push(OpCode::Return as u8);
        // True branch target:
        let true_target = bc.len() as u32;
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&42u64.to_le_bytes());
        bc.push(OpCode::Return as u8);

        // Patch jump offset
        bc[jump_offset_pos..jump_offset_pos + 4].copy_from_slice(&true_target.to_le_bytes());

        let result = exec(&bc, 100_000);
        assert!(result.success);
        assert_eq!(result.return_value, Some(42));
    }

    #[test]
    fn test_emit_event() {
        let mut bc = vec![];
        // Push data: 100
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&100u64.to_le_bytes());
        // Push data_count: 1
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&1u64.to_le_bytes());
        // Push topic: 7
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&7u64.to_le_bytes());
        bc.push(OpCode::EmitEvent as u8);
        bc.push(OpCode::Return as u8);

        let result = exec(&bc, 100_000);
        assert!(result.success);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].topic, 7);
        assert_eq!(result.events[0].data, vec![100]);
    }

    #[test]
    fn test_context_block_height() {
        let mut bc = vec![];
        bc.push(OpCode::BlockHeight as u8);
        bc.push(OpCode::Return as u8);

        let result = exec(&bc, 100_000);
        assert!(result.success);
        assert_eq!(result.return_value, Some(100));
    }

    #[test]
    fn test_division_by_zero() {
        let mut bc = vec![];
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&10u64.to_le_bytes());
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&0u64.to_le_bytes());
        bc.push(OpCode::Div as u8);

        let result = exec(&bc, 100_000);
        assert!(!result.success);
        assert!(matches!(result.error, Some(VmError::DivisionByZero)));
    }

    #[test]
    fn test_stack_underflow() {
        let bc = vec![OpCode::Add as u8]; // empty stack
        let result = exec(&bc, 100_000);
        assert!(!result.success);
        assert!(matches!(result.error, Some(VmError::StackUnderflow)));
    }

    #[test]
    fn test_comparison_ops() {
        let mut bc = vec![];
        // 5 < 10 → 1
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&5u64.to_le_bytes());
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&10u64.to_le_bytes());
        bc.push(OpCode::Lt as u8);
        bc.push(OpCode::Return as u8);

        let result = exec(&bc, 100_000);
        assert!(result.success);
        assert_eq!(result.return_value, Some(1));
    }
}

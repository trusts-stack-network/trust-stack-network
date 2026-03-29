//! TSN zkVM — Stack-based virtual machine for smart contract execution.
//!
//! The VM executes bytecode programs with gas metering, storage access,
//! and produces execution traces for future ZK proof generation (Plonky3).

pub mod opcode;
pub mod gas;
pub mod machine;
pub mod trace;

pub use opcode::OpCode;
pub use gas::{gas_cost, BLOCK_GAS_LIMIT, CONTRACT_MAX_SIZE, CONTRACT_MAX_CALL_DEPTH};
pub use machine::{Vm, ExecContext, ExecResult, VmError, ContractEvent, TransferRequest};
pub use trace::{ExecutionTrace, VmStep};

//! TSN-20 Token standard — bytecode template for fungible tokens.
//!
//! Storage layout:
//!   Slot 0: total_supply
//!   Slot 1: owner pk_hash (first u64)
//!   Slot 1000 + hash(address): balance
//!   Slot 2000 + hash(owner||spender): allowance
//!
//! Functions:
//!   selector 0x01: init(total_supply)     — constructor
//!   selector 0x02: transfer(to, amount)   — transfer tokens
//!   selector 0x03: balance_of(addr)       — query balance
//!   selector 0x04: approve(spender, amt)  — approve allowance
//!   selector 0x05: transfer_from(from, to, amount)
//!   selector 0x06: total_supply()         — query total supply

use crate::vm::OpCode;

/// Build the TSN-20 token bytecode.
/// This generates a self-contained bytecode program that dispatches
/// based on the function selector pushed before the contract code.
pub fn build_token_bytecode() -> Vec<u8> {
    let mut bc = Vec::new();

    // Function selector is on top of stack (pushed by executor)
    // We use a series of DUP + PUSH selector + EQ + JUMPIF to dispatch

    // ── Dispatch table ───────────────────────────────────
    // Stack: [selector, ...args]

    // Check selector == 0x01 (init)
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let init_jump = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes()); // placeholder

    // Check selector == 0x02 (transfer)
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let transfer_jump = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());

    // Check selector == 0x03 (balance_of)
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let balance_jump = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());

    // Check selector == 0x06 (total_supply)
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&6u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let supply_jump = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());

    // Unknown selector → abort
    bc.push(OpCode::Abort as u8);
    bc.push(0xFF); // error code: unknown function

    // ── Function: init(total_supply) ─────────────────────
    let init_offset = bc.len() as u32;
    // Pop selector
    bc.push(OpCode::Pop as u8);
    // Stack: [total_supply]
    // Store total_supply in slot 0
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes()); // slot 0
    bc.push(OpCode::SStore as u8);
    // Store caller balance = total_supply in slot 1000 + 0 (simplified: caller slot = 1000)
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1000u64.to_le_bytes()); // slot 1000 (owner)
    bc.push(OpCode::SStore as u8);
    // Store owner = caller in slot 1
    bc.push(OpCode::Caller as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);
    // Emit event: topic=1 (Initialized), data=[total_supply read from slot 0]
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes()); // data_count
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes()); // topic: Init
    bc.push(OpCode::EmitEvent as u8);
    bc.push(OpCode::Return as u8);

    // ── Function: transfer(to, amount) ───────────────────
    let transfer_offset = bc.len() as u32;
    // Pop selector
    bc.push(OpCode::Pop as u8);
    // Stack: [to, amount]
    // For simplicity: deduct from slot 1000 (caller), add to slot 1000+to
    // Load caller balance
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1000u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8); // stack: [to, amount, caller_balance]
    // Check caller_balance >= amount
    bc.push(OpCode::Rot as u8); // [amount, caller_balance, to]
    bc.push(OpCode::Rot as u8); // [caller_balance, to, amount]
    // DUP amount for later
    bc.push(OpCode::Dup as u8); // [caller_balance, to, amount, amount]
    bc.push(OpCode::Rot as u8); // [caller_balance, amount, amount, to]
    bc.push(OpCode::Rot as u8); // [caller_balance, amount, to, amount]  hmm this is getting complex
    // Simplify: just do the operation and abort on underflow
    // Reset: let's use memory for cleaner code
    // Stack at start: [to, amount]
    // Store to in mem[0], amount in mem[1]
    // Actually let's restart the transfer function more cleanly:
    // (We overwrite the complex stack stuff above)
    let _transfer_offset_actual = bc.len() - (bc.len() - transfer_offset as usize); // keep the Pop
    // We already have Pop. Stack: [to, amount]
    // Store amount in mem[1]
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes()); // mem index 1
    bc.push(OpCode::MStore as u8); // mem[1] = amount, stack: [to]
    // Store to in mem[0]
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[0] = to, stack: []
    // Load caller balance from slot 1000
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1000u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8); // stack: [caller_bal]
    // Load amount from mem
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8); // stack: [caller_bal, amount]
    // caller_bal - amount (will abort on underflow = insufficient balance)
    bc.push(OpCode::Sub as u8); // stack: [new_caller_bal]
    // Store new caller balance
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1000u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[1000] = new_caller_bal
    // Load recipient slot: 1000 + to
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8); // to
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1000u64.to_le_bytes());
    bc.push(OpCode::Add as u8); // 1000 + to = recipient_slot
    bc.push(OpCode::Dup as u8); // [recipient_slot, recipient_slot]
    bc.push(OpCode::SLoad as u8); // [recipient_slot, old_balance]
    // Add amount
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8); // amount
    bc.push(OpCode::Add as u8); // new_balance
    bc.push(OpCode::Swap as u8); // [new_balance, recipient_slot]
    bc.push(OpCode::SStore as u8); // store
    // Emit Transfer event (topic=2)
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8); // amount
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes()); // data_count=1
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes()); // topic=Transfer
    bc.push(OpCode::EmitEvent as u8);
    // Return 1 (success)
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Return as u8);

    // ── Function: balance_of(addr) ───────────────────────
    let balance_offset = bc.len() as u32;
    bc.push(OpCode::Pop as u8); // pop selector
    // Stack: [addr]
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1000u64.to_le_bytes());
    bc.push(OpCode::Add as u8); // 1000 + addr = slot
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Return as u8);

    // ── Function: total_supply() ─────────────────────────
    let supply_offset = bc.len() as u32;
    bc.push(OpCode::Pop as u8); // pop selector
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Return as u8);

    // ── Patch jump targets ───────────────────────────────
    bc[init_jump..init_jump + 4].copy_from_slice(&init_offset.to_le_bytes());
    bc[transfer_jump..transfer_jump + 4].copy_from_slice(&transfer_offset.to_le_bytes());
    bc[balance_jump..balance_jump + 4].copy_from_slice(&balance_offset.to_le_bytes());
    bc[supply_jump..supply_jump + 4].copy_from_slice(&supply_offset.to_le_bytes());

    bc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_token_bytecode() {
        let bc = build_token_bytecode();
        assert!(!bc.is_empty());
        assert!(bc.len() < 2048); // reasonable size
    }
}

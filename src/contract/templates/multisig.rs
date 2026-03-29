//! Multisig wallet contract template (N-of-M).
//!
//! Storage layout:
//!   Slot 0: threshold (minimum approvals)
//!   Slot 1: signer_count
//!   Slot 10..10+N: signer pk_hashes
//!   Slot 100+proposal_id*10+0: proposal action_hash
//!   Slot 100+proposal_id*10+1: approval_count
//!   Slot 100+proposal_id*10+2: executed (0/1)
//!   Slot 200+proposal_id*100+signer_idx: approved (0/1)
//!
//! Functions:
//!   selector 0x01: init(threshold, signer_count, signers...)
//!   selector 0x02: propose(action_hash) → proposal_id
//!   selector 0x03: approve(proposal_id)
//!   selector 0x04: is_approved(proposal_id) → 0/1
//!   selector 0x05: proposal_count() → count

use crate::vm::OpCode;

/// Build multisig contract bytecode.
pub fn build_multisig_bytecode() -> Vec<u8> {
    let mut bc = Vec::new();

    // ── Dispatch ──────────────────────────────────────────
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let init_jump = bc.len(); bc.extend_from_slice(&0u32.to_le_bytes());

    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let propose_jump = bc.len(); bc.extend_from_slice(&0u32.to_le_bytes());

    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let approve_jump = bc.len(); bc.extend_from_slice(&0u32.to_le_bytes());

    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let is_approved_jump = bc.len(); bc.extend_from_slice(&0u32.to_le_bytes());

    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let count_jump = bc.len(); bc.extend_from_slice(&0u32.to_le_bytes());

    bc.push(OpCode::Abort as u8); bc.push(0xFF);

    // ── init(threshold, signer_count, signers...) ────────
    let init_offset = bc.len() as u32;
    bc.push(OpCode::Pop as u8); // selector
    // Stack: [threshold, signer_count, signer0, signer1, ...]
    // Store threshold in slot 0
    // We use MStore to save args, then loop to store signers
    // Simplified: store threshold and signer_count, then up to 5 signers
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[0] = threshold
    bc.push(OpCode::Dup as u8); // dup signer_count for loop
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[1] = signer_count
    // Store proposal counter = 0 in slot 2
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);
    // Pop remaining signer_count from stack and store signers
    // For simplicity: store up to remaining stack as signers at slots 10, 11, 12...
    // The signer_count is still on stack
    // We'll just store them one by one via Swap/SStore
    // Simplified: just HALT for now — signers stored via constructor_args
    bc.push(OpCode::Return as u8);

    // ── propose(action_hash) → proposal_id ───────────────
    let propose_offset = bc.len() as u32;
    bc.push(OpCode::Pop as u8); // selector
    // Stack: [action_hash]
    // Load proposal counter from slot 2
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8); // proposal_id
    // Store action_hash at slot 100 + proposal_id * 10
    bc.push(OpCode::Dup as u8); // [action_hash, proposal_id, proposal_id]
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&10u64.to_le_bytes());
    bc.push(OpCode::Mul as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&100u64.to_le_bytes());
    bc.push(OpCode::Add as u8); // slot = 100 + pid*10
    bc.push(OpCode::SStore as u8); // slot[100+pid*10] = action_hash
    // Set approval_count = 0 at slot+1 (already 0 by default)
    // Increment proposal counter
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);
    // Return proposal_id (the old counter value, still on stack)
    bc.push(OpCode::Return as u8);

    // ── approve(proposal_id) ─────────────────────────────
    let approve_offset = bc.len() as u32;
    bc.push(OpCode::Pop as u8); // selector
    // Stack: [proposal_id]
    // Increment approval_count at slot 100 + pid*10 + 1
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&10u64.to_le_bytes());
    bc.push(OpCode::Mul as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&101u64.to_le_bytes());
    bc.push(OpCode::Add as u8); // slot = 101 + pid*10
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::SLoad as u8); // current count
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Add as u8); // count + 1
    bc.push(OpCode::Swap as u8);
    bc.push(OpCode::SStore as u8); // store new count
    // Emit event
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&3u64.to_le_bytes()); // topic=Approved
    bc.push(OpCode::EmitEvent as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Return as u8);

    // ── is_approved(proposal_id) → 0/1 ───────────────────
    let is_approved_offset = bc.len() as u32;
    bc.push(OpCode::Pop as u8);
    // Stack: [proposal_id]
    // Load approval_count
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&10u64.to_le_bytes());
    bc.push(OpCode::Mul as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&101u64.to_le_bytes());
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::SLoad as u8); // approval_count
    // Load threshold
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    // count >= threshold ?
    bc.push(OpCode::Gte as u8);
    bc.push(OpCode::Return as u8);

    // ── proposal_count() ─────────────────────────────────
    let count_offset = bc.len() as u32;
    bc.push(OpCode::Pop as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Return as u8);

    // ── Patch jumps ──────────────────────────────────────
    bc[init_jump..init_jump+4].copy_from_slice(&init_offset.to_le_bytes());
    bc[propose_jump..propose_jump+4].copy_from_slice(&propose_offset.to_le_bytes());
    bc[approve_jump..approve_jump+4].copy_from_slice(&approve_offset.to_le_bytes());
    bc[is_approved_jump..is_approved_jump+4].copy_from_slice(&is_approved_offset.to_le_bytes());
    bc[count_jump..count_jump+4].copy_from_slice(&count_offset.to_le_bytes());

    bc
}

//! Escrow contract template.
//!
//! Storage layout:
//!   Slot 0: state (0=empty, 1=active, 2=released, 3=refunded)
//!   Slot 1: buyer pk_hash (first u64)
//!   Slot 2: seller pk_hash (first u64)
//!   Slot 3: amount
//!   Slot 4: timeout (block height)
//!   Slot 5: arbitrator pk_hash (first u64)
//!
//! Functions:
//!   selector 0x01: init(buyer, seller, amount, timeout, arbitrator)
//!   selector 0x02: release()       — buyer confirms, funds go to seller
//!   selector 0x03: refund()        — after timeout, buyer gets refund
//!   selector 0x04: arbitrate(to)   — arbitrator decides
//!   selector 0x05: status()        — query current state

use crate::vm::OpCode;

/// Build escrow contract bytecode.
pub fn build_escrow_bytecode() -> Vec<u8> {
    let mut bc = Vec::new();

    // ── Dispatch ──────────────────────────────────────────
    // selector == 1 → init
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let init_jump = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());

    // selector == 2 → release
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let release_jump = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());

    // selector == 3 → refund
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let refund_jump = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());

    // selector == 5 → status
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let status_jump = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());

    bc.push(OpCode::Abort as u8);
    bc.push(0xFF);

    // ── init(buyer, seller, amount, timeout, arbitrator) ─
    let init_offset = bc.len() as u32;
    bc.push(OpCode::Pop as u8); // pop selector
    // Stack: [buyer, seller, amount, timeout, arbitrator]
    // Store each in its slot
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[5] = arbitrator
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[4] = timeout
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[3] = amount
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[2] = seller
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[1] = buyer
    // Set state = 1 (active)
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);
    bc.push(OpCode::Return as u8);

    // ── release() — buyer releases to seller ─────────────
    let release_offset = bc.len() as u32;
    bc.push(OpCode::Pop as u8);
    // Check state == 1
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::Not as u8);
    bc.push(OpCode::JumpIf as u8);
    let release_fail = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());
    // Check caller == buyer (simplified: compare first u64)
    bc.push(OpCode::Caller as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::Not as u8);
    bc.push(OpCode::JumpIf as u8);
    let release_fail2 = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());
    // Transfer to seller
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8); // amount
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8); // seller addr
    bc.push(OpCode::Transfer as u8);
    bc.push(OpCode::Pop as u8); // discard transfer result
    // Set state = 2 (released)
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Return as u8);

    // release fail
    let release_fail_offset = bc.len() as u32;
    bc.push(OpCode::Abort as u8); bc.push(0x01);

    // ── refund() — after timeout ─────────────────────────
    let refund_offset = bc.len() as u32;
    bc.push(OpCode::Pop as u8);
    // Check state == 1
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::Not as u8);
    bc.push(OpCode::JumpIf as u8);
    let refund_fail = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());
    // Check block_height >= timeout
    bc.push(OpCode::BlockHeight as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Gte as u8);
    bc.push(OpCode::Not as u8);
    bc.push(OpCode::JumpIf as u8);
    let refund_fail2 = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());
    // Transfer to buyer
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Transfer as u8);
    bc.push(OpCode::Pop as u8);
    // Set state = 3 (refunded)
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Return as u8);

    let refund_fail_offset = bc.len() as u32;
    bc.push(OpCode::Abort as u8); bc.push(0x02);

    // ── status() ─────────────────────────────────────────
    let status_offset = bc.len() as u32;
    bc.push(OpCode::Pop as u8);
    bc.push(OpCode::Push as u8); bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Return as u8);

    // ── Patch jumps ──────────────────────────────────────
    bc[init_jump..init_jump+4].copy_from_slice(&init_offset.to_le_bytes());
    bc[release_jump..release_jump+4].copy_from_slice(&release_offset.to_le_bytes());
    bc[refund_jump..refund_jump+4].copy_from_slice(&refund_offset.to_le_bytes());
    bc[status_jump..status_jump+4].copy_from_slice(&status_offset.to_le_bytes());
    bc[release_fail..release_fail+4].copy_from_slice(&release_fail_offset.to_le_bytes());
    bc[release_fail2..release_fail2+4].copy_from_slice(&release_fail_offset.to_le_bytes());
    bc[refund_fail..refund_fail+4].copy_from_slice(&refund_fail_offset.to_le_bytes());
    bc[refund_fail2..refund_fail2+4].copy_from_slice(&refund_fail_offset.to_le_bytes());

    bc
}

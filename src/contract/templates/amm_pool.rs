//! NetherSwap AMM Pool contract — Constant Product Market Maker (x * y = k).
//!
//! Storage layout:
//!   Slot 0:  state (0=uninitialized, 1=active, 2=paused)
//!   Slot 1:  owner pk_hash (first u64)
//!   Slot 2:  token_a contract address (first u64)
//!   Slot 3:  token_b contract address (first u64)
//!   Slot 4:  reserve_a (amount of token A in pool)
//!   Slot 5:  reserve_b (amount of token B in pool)
//!   Slot 6:  total_lp_shares (total LP tokens minted)
//!   Slot 7:  fee_bps (fee in basis points, e.g. 30 = 0.3%)
//!   Slot 8:  protocol_fee_bps (protocol share of fees, e.g. 15 = 0.15%)
//!   Slot 9:  total_volume (cumulative swap volume)
//!   Slot 10: k_last (last recorded k = reserve_a * reserve_b)
//!   Slot 3000 + hash(provider): LP share balance for provider
//!
//! Functions:
//!   selector 0x01: init(token_a, token_b, fee_bps, protocol_fee_bps) — constructor
//!   selector 0x02: add_liquidity(amount_a, amount_b)      — provide liquidity, mint LP shares
//!   selector 0x03: remove_liquidity(lp_shares)             — burn LP shares, withdraw tokens
//!   selector 0x04: swap_a_to_b(amount_in)                  — swap token A → B
//!   selector 0x05: swap_b_to_a(amount_in)                  — swap token B → A
//!   selector 0x06: get_reserves()                           — query (reserve_a, reserve_b)
//!   selector 0x07: get_lp_balance(provider)                 — query LP shares for address
//!   selector 0x08: get_price()                              — query price ratio (reserve_b / reserve_a)
//!   selector 0x09: pause()                                  — owner only: pause the pool
//!   selector 0x0A: unpause()                                — owner only: unpause the pool

use crate::vm::OpCode;

/// Emit helper: pushes an event with topic and one data value.
fn emit_event_1(bc: &mut Vec<u8>, topic: u64, data_slot: u64) {
    // Push data from storage slot
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&data_slot.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    // Push data_count = 1
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    // Push topic
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&topic.to_le_bytes());
    bc.push(OpCode::EmitEvent as u8);
}

/// Build the AMM Pool contract bytecode for NetherSwap.
pub fn build_amm_pool_bytecode() -> Vec<u8> {
    let mut bc = Vec::new();

    // ── Dispatch table ───────────────────────────────────
    // Stack on entry: [selector, ...args]

    let selectors: &[(u64, &str)] = &[
        (0x01, "init"),
        (0x02, "add_liquidity"),
        (0x03, "remove_liquidity"),
        (0x04, "swap_a_to_b"),
        (0x05, "swap_b_to_a"),
        (0x06, "get_reserves"),
        (0x07, "get_lp_balance"),
        (0x08, "get_price"),
        (0x09, "pause"),
        (0x0A, "unpause"),
    ];

    // Build dispatch: DUP, PUSH sel, EQ, JUMPIF placeholder
    let mut jump_patches: Vec<(usize, &str)> = Vec::new();
    for (sel, name) in selectors {
        bc.push(OpCode::Dup as u8);
        bc.push(OpCode::Push as u8);
        bc.extend_from_slice(&sel.to_le_bytes());
        bc.push(OpCode::Eq as u8);
        bc.push(OpCode::JumpIf as u8);
        let patch_pos = bc.len();
        bc.extend_from_slice(&0u32.to_le_bytes());
        jump_patches.push((patch_pos, name));
    }

    // Unknown selector → abort
    bc.push(OpCode::Abort as u8);
    bc.push(0xFF);

    // ── Function offsets (collect as we build) ──────────
    let mut fn_offsets: Vec<(&str, u32)> = Vec::new();

    // ════════════════════════════════════════════════════
    // init(token_a, token_b, fee_bps, protocol_fee_bps)
    // ════════════════════════════════════════════════════
    fn_offsets.push(("init", bc.len() as u32));
    bc.push(OpCode::Pop as u8); // pop selector
    // Stack: [token_a, token_b, fee_bps, protocol_fee_bps]

    // Store protocol_fee_bps → slot 8
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&8u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    // Store fee_bps → slot 7
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&7u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    // Store token_b → slot 3
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    // Store token_a → slot 2
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    // Store owner = Caller → slot 1
    bc.push(OpCode::Caller as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    // Set state = 1 (active) → slot 0
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    // Init reserves to 0
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&6u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    bc.push(OpCode::Halt as u8);

    // ════════════════════════════════════════════════════
    // add_liquidity(amount_a, amount_b)
    // ════════════════════════════════════════════════════
    fn_offsets.push(("add_liquidity", bc.len() as u32));
    bc.push(OpCode::Pop as u8); // pop selector
    // Stack: [amount_a, amount_b]

    // Check state == 1 (active)
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::Not as u8);
    bc.push(OpCode::JumpIf as u8);
    let abort_paused = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes()); // → abort

    // Save amount_b to memory[1], amount_a to memory[0]
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[1] = amount_b
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[0] = amount_a

    // Load current reserves
    // reserve_a = SLoad(4)
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[2] = reserve_a

    // reserve_b = SLoad(5)
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[3] = reserve_b

    // total_shares = SLoad(6)
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&6u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[4] = total_shares

    // Calculate LP shares to mint:
    // If total_shares == 0: shares = amount_a (initial liquidity)
    // Else: shares = amount_a * total_shares / reserve_a
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8); // total_shares
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::JumpIf as u8);
    let initial_liq = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes()); // → initial liquidity

    // Proportional: shares = amount_a * total_shares / reserve_a
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8); // amount_a
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8); // total_shares
    bc.push(OpCode::Mul as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8); // reserve_a
    bc.push(OpCode::Div as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[5] = new_shares
    bc.push(OpCode::Jump as u8);
    let after_shares = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes()); // → after shares calc

    // Initial liquidity: shares = amount_a
    let initial_liq_offset = bc.len() as u32;
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8); // amount_a
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[5] = new_shares

    // After shares calculation: update state
    let after_shares_offset = bc.len() as u32;

    // new_reserve_a = reserve_a + amount_a
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[4] = new_reserve_a

    // new_reserve_b = reserve_b + amount_b
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[5] = new_reserve_b

    // new_total = total_shares + new_shares
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&6u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[6] = new_total

    // Update provider LP balance: slot[3000 + hash(caller)]
    // Simplified: use Caller as key directly → slot[3000 + caller_u64]
    bc.push(OpCode::Caller as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3000u64.to_le_bytes());
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::SLoad as u8); // old balance
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8); // new_shares
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Swap as u8); // [new_balance, slot_key]
    bc.push(OpCode::SStore as u8);

    // Emit AddLiquidity event (topic=2)
    emit_event_1(&mut bc, 2, 5); // new_shares from mem[5]

    // Return new_shares
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Return as u8);

    // Abort: pool paused
    let abort_paused_offset = bc.len() as u32;
    bc.push(OpCode::Abort as u8);
    bc.push(0x02); // error: pool paused

    // ════════════════════════════════════════════════════
    // remove_liquidity(lp_shares)
    // ════════════════════════════════════════════════════
    fn_offsets.push(("remove_liquidity", bc.len() as u32));
    bc.push(OpCode::Pop as u8);
    // Stack: [lp_shares]
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[0] = lp_shares

    // Load total_shares, reserve_a, reserve_b
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&6u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8); // total_shares
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[1] = total_shares

    // amount_a_out = lp_shares * reserve_a / total_shares
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Mul as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Div as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[2] = amount_a_out

    // amount_b_out = lp_shares * reserve_b / total_shares
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Mul as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Div as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[3] = amount_b_out

    // Update reserves: reserve_a -= amount_a_out
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Sub as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    // reserve_b -= amount_b_out
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Sub as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    // total_shares -= lp_shares
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Sub as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&6u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    // Update provider balance
    bc.push(OpCode::Caller as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3000u64.to_le_bytes());
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Dup as u8);
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Sub as u8);
    bc.push(OpCode::Swap as u8);
    bc.push(OpCode::SStore as u8);

    // Emit RemoveLiquidity event (topic=3)
    emit_event_1(&mut bc, 3, 0);

    // Return amount_a_out
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Return as u8);

    // ════════════════════════════════════════════════════
    // swap_a_to_b(amount_in)  — constant product AMM
    // ════════════════════════════════════════════════════
    fn_offsets.push(("swap_a_to_b", bc.len() as u32));
    bc.push(OpCode::Pop as u8);
    // Stack: [amount_in]
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[0] = amount_in

    // fee = amount_in * fee_bps / 10000
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&7u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8); // fee_bps
    bc.push(OpCode::Mul as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&10000u64.to_le_bytes());
    bc.push(OpCode::Div as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[1] = fee

    // amount_in_after_fee = amount_in - fee
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Sub as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[2] = amount_after_fee

    // Load reserves
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[3] = reserve_a

    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[4] = reserve_b

    // amount_out = reserve_b * amount_after_fee / (reserve_a + amount_after_fee)
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8); // reserve_b
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8); // amount_after_fee
    bc.push(OpCode::Mul as u8);
    // denominator = reserve_a + amount_after_fee
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Div as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[5] = amount_out

    // Update reserves: reserve_a += amount_in, reserve_b -= amount_out
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[4] = reserve_a + amount_in

    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Sub as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::SStore as u8); // slot[5] = reserve_b - amount_out

    // Update volume: slot[9] += amount_in
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&9u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&9u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    // Emit Swap event (topic=4)
    emit_event_1(&mut bc, 4, 5); // amount_out

    // Return amount_out
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Return as u8);

    // ════════════════════════════════════════════════════
    // swap_b_to_a(amount_in)  — reverse direction
    // ════════════════════════════════════════════════════
    fn_offsets.push(("swap_b_to_a", bc.len() as u32));
    bc.push(OpCode::Pop as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[0] = amount_in

    // Same AMM logic but reversed: amount_out = reserve_a * after_fee / (reserve_b + after_fee)
    // fee
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&7u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Mul as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&10000u64.to_le_bytes());
    bc.push(OpCode::Div as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[1] = fee

    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Sub as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[2] = after_fee

    // reserves
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[3] = reserve_a

    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[4] = reserve_b

    // amount_out = reserve_a * after_fee / (reserve_b + after_fee)
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Mul as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Div as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::MStore as u8); // mem[5] = amount_out

    // Update reserves: reserve_a -= amount_out, reserve_b += amount_in
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Sub as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    // volume
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&9u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&9u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);

    emit_event_1(&mut bc, 4, 5);

    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::MLoad as u8);
    bc.push(OpCode::Return as u8);

    // ════════════════════════════════════════════════════
    // get_reserves() — returns reserve_a (reserve_b on stack below)
    // ════════════════════════════════════════════════════
    fn_offsets.push(("get_reserves", bc.len() as u32));
    bc.push(OpCode::Pop as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8); // reserve_a
    bc.push(OpCode::Return as u8);

    // ════════════════════════════════════════════════════
    // get_lp_balance(provider)
    // ════════════════════════════════════════════════════
    fn_offsets.push(("get_lp_balance", bc.len() as u32));
    bc.push(OpCode::Pop as u8);
    // Stack: [provider_addr]
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&3000u64.to_le_bytes());
    bc.push(OpCode::Add as u8);
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Return as u8);

    // ════════════════════════════════════════════════════
    // get_price() — reserve_b / reserve_a (integer division)
    // ════════════════════════════════════════════════════
    fn_offsets.push(("get_price", bc.len() as u32));
    bc.push(OpCode::Pop as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&5u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&10000u64.to_le_bytes());
    bc.push(OpCode::Mul as u8); // scale up for precision
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&4u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Div as u8);
    bc.push(OpCode::Return as u8);

    // ════════════════════════════════════════════════════
    // pause() — owner only
    // ════════════════════════════════════════════════════
    fn_offsets.push(("pause", bc.len() as u32));
    bc.push(OpCode::Pop as u8);
    // Check caller == owner
    bc.push(OpCode::Caller as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::Not as u8);
    bc.push(OpCode::JumpIf as u8);
    let abort_auth = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());
    // Set state = 2 (paused)
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&2u64.to_le_bytes());
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);
    bc.push(OpCode::Halt as u8);

    // ════════════════════════════════════════════════════
    // unpause() — owner only
    // ════════════════════════════════════════════════════
    fn_offsets.push(("unpause", bc.len() as u32));
    bc.push(OpCode::Pop as u8);
    bc.push(OpCode::Caller as u8);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::SLoad as u8);
    bc.push(OpCode::Eq as u8);
    bc.push(OpCode::Not as u8);
    bc.push(OpCode::JumpIf as u8);
    let abort_auth2 = bc.len();
    bc.extend_from_slice(&0u32.to_le_bytes());
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&1u64.to_le_bytes());
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0u64.to_le_bytes());
    bc.push(OpCode::SStore as u8);
    bc.push(OpCode::Halt as u8);

    // Abort: unauthorized
    let abort_auth_offset = bc.len() as u32;
    bc.push(OpCode::Abort as u8);
    bc.push(0x01); // error: unauthorized

    // ── Patch all jump targets ─────────────────────────
    for (patch_pos, name) in &jump_patches {
        let target = fn_offsets.iter().find(|(n, _)| n == name).map(|(_, o)| *o).unwrap_or(0);
        bc[*patch_pos..*patch_pos + 4].copy_from_slice(&target.to_le_bytes());
    }

    // Patch conditional jumps within functions
    bc[abort_paused..abort_paused + 4].copy_from_slice(&abort_paused_offset.to_le_bytes());
    bc[initial_liq..initial_liq + 4].copy_from_slice(&initial_liq_offset.to_le_bytes());
    bc[after_shares..after_shares + 4].copy_from_slice(&after_shares_offset.to_le_bytes());
    bc[abort_auth..abort_auth + 4].copy_from_slice(&abort_auth_offset.to_le_bytes());
    bc[abort_auth2..abort_auth2 + 4].copy_from_slice(&abort_auth_offset.to_le_bytes());

    bc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amm_pool_bytecode_builds() {
        let bc = build_amm_pool_bytecode();
        assert!(!bc.is_empty());
        assert!(bc.len() < 65536, "Bytecode too large: {} bytes", bc.len());
        println!("AMM Pool bytecode: {} bytes", bc.len());
    }

    #[test]
    fn test_amm_pool_has_dispatch() {
        let bc = build_amm_pool_bytecode();
        // First instruction should be DUP (for dispatch)
        assert_eq!(bc[0], OpCode::Dup as u8);
    }
}

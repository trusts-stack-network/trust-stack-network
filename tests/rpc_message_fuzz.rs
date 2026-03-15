// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Fuzzing côté intégration des messages RPC
use tsn_network::api::RpcMessage;
use std::convert::TryFrom;

#[test]
fn rpc_messages_never_panic() {
    // 100 000 messages aléatoires
    for _ in 0..100_000 {
        let raw = (0..256).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        let _ = RpcMessage::try_from(raw);
    }
}

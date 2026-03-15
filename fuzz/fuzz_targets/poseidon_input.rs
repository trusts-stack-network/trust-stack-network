#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::poseidon::PoseidonHash;

fuzz_target!(|data: Vec<[u8;32]>| {
    let mut h = PoseidonHash::new();
    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            h.update(&chunk[0]);
            h.update(&chunk[1]);
        }
    }
    black_box(h.finalize());
});

fn black_box<T>(x: T) -> T { x }
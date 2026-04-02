use criterion::{criterion_group, criterion_main, Criterion};
use tsn::crypto::pq::slh_dsa::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

fn bench_slh_dsa(c: &mut Criterion) {
    let (sk, pk) = SigningKey::generate(&mut OsRng);
    let msg = [0x42; 32];
    let sig = sk.sign(&msg);

    c.bench_function("slh_dsa sign", |b| {
        b.iter(|| sk.sign(&msg))
    });

    c.bench_function("slh_dsa verify", |b| {
        b.iter(|| pk.verify(&msg, &sig))
    });
}

criterion_group!(benches, bench_slh_dsa);
criterion_main!(benches);
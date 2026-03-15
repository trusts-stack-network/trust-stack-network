use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

fn bench_timing_compare(c: &mut Criterion) {
    let a = [0u8; 32];
    let b = [0u8; 32];
    
    c.bench_function("constant_time_eq", |bencher| {
        bencher.iter(|| {
            black_box(constant_time_compare(black_box(&a), black_box(&b)))
        });
    });
}

criterion_group!(benches, bench_timing_compare);
criterion_main!(benches);
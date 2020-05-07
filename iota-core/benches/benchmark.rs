use criterion::{criterion_group, criterion_main, Criterion};
use iota::bundle::{Address, TransactionField};
use iota::crypto::Kerl;
use iota::signing::{
    IotaSeed, PrivateKey, PrivateKeyGenerator, PublicKey, Seed, WotsPrivateKeyGeneratorBuilder,
    WotsSecurityLevel,
};
use iota::ternary::TritBuf;

use rand::Rng;

fn seed() -> [i8; 243] {
    let mut rng = rand::thread_rng();
    let mut seed = [0i8; 243];
    for i in 0..243 {
        seed[i] = rng.gen_range(-1, 1);
    }
    seed
}

fn addr_r1() {
    let seed = IotaSeed::<Kerl>::from_buf(TritBuf::from_i8_unchecked(&seed())).unwrap();

    let _: Address = Address::try_from_inner(
        WotsPrivateKeyGeneratorBuilder::<Kerl>::default()
            .security_level(WotsSecurityLevel::Low)
            .build()
            .unwrap()
            .generate(&seed, 0)
            .unwrap()
            .generate_public_key()
            .unwrap()
            .trits()
            .to_owned(),
    )
    .unwrap();
}

fn benchmark_r1(c: &mut Criterion) {
    c.bench_function("generate security 1 address in Rust", |b| {
        b.iter(|| addr_r1())
    });
}

fn addr_c1() {
    let seed = seed();
    unsafe {
        iota::iota_sign_address_gen_trytes(seed.as_ptr(), 0, 1);
    }
}

fn benchmark_c1(c: &mut Criterion) {
    c.bench_function("generate security 1 address in C", |b| b.iter(|| addr_c1()));
}

fn addr_r2() {
    let seed = IotaSeed::<Kerl>::from_buf(TritBuf::from_i8_unchecked(&seed())).unwrap();

    let _: Address = Address::try_from_inner(
        WotsPrivateKeyGeneratorBuilder::<Kerl>::default()
            .security_level(WotsSecurityLevel::Medium)
            .build()
            .unwrap()
            .generate(&seed, 0)
            .unwrap()
            .generate_public_key()
            .unwrap()
            .trits()
            .to_owned(),
    )
    .unwrap();
}

fn benchmark_r2(c: &mut Criterion) {
    c.bench_function("generate security 2 address in Rust", |b| {
        b.iter(|| addr_r2())
    });
}

fn addr_c2() {
    let seed = seed();
    unsafe {
        iota::iota_sign_address_gen_trytes(seed.as_ptr(), 0, 2);
    }
}

fn benchmark_c2(c: &mut Criterion) {
    c.bench_function("generate security 2 address in C", |b| b.iter(|| addr_c2()));
}

fn addr_r3() {
    let seed = IotaSeed::<Kerl>::from_buf(TritBuf::from_i8_unchecked(&seed())).unwrap();

    let _: Address = Address::try_from_inner(
        WotsPrivateKeyGeneratorBuilder::<Kerl>::default()
            .security_level(WotsSecurityLevel::High)
            .build()
            .unwrap()
            .generate(&seed, 0)
            .unwrap()
            .generate_public_key()
            .unwrap()
            .trits()
            .to_owned(),
    )
    .unwrap();
}

fn benchmark_r3(c: &mut Criterion) {
    c.bench_function("generate security 3 address in Rust", |b| {
        b.iter(|| addr_r3())
    });
}

fn addr_c3() {
    let seed = seed();
    unsafe {
        iota::iota_sign_address_gen_trytes(seed.as_ptr(), 0, 3);
    }
}

fn benchmark_c3(c: &mut Criterion) {
    c.bench_function("generate security 3 address in C", |b| b.iter(|| addr_c3()));
}

criterion_group!(
    benches,
    benchmark_c1,
    benchmark_r1,
    benchmark_c2,
    benchmark_r2,
    benchmark_c3,
    benchmark_r3
);
criterion_main!(benches);

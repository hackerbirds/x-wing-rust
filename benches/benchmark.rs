use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use x_wing::{Ciphertext, PublicKey, XWing, XWingDecapsulator, XWingEncapsulator};

pub fn criterion_benchmark(c: &mut Criterion) {
    let csprng = OsRng;
    let mut group = c.benchmark_group("x-wing");
    // Configure Criterion.rs to detect smaller differences and increase sample size to improve
    // precision and counteract the resulting noise.
    group.significance_level(0.1).sample_size(2000);
    group.bench_function(
        "XWing: Generate+Encaps+Decaps with Ciphertext/Public Key serialization roundtrip",
        |b| {
            b.iter(|| {
                let (secret_key_bob, pub_key_bob) = XWing::derive_key_pair(csprng).unwrap();

                let (_shared_key_alice, cipher_alice) = XWing::encapsulate(
                    csprng,
                    PublicKey::from_bytes(pub_key_bob.to_bytes()).unwrap(),
                )
                .unwrap();

                let _shared_key_bob = XWing::decapsulate(
                    Ciphertext::from_bytes(cipher_alice.to_bytes()).unwrap(),
                    secret_key_bob,
                )
                .unwrap();
            })
        },
    );
    group.bench_function("XWing: Generate+Encaps+Decaps", |b| {
        b.iter(|| {
            let (secret_key_bob, pub_key_bob) = XWing::derive_key_pair(csprng).unwrap();

            let (_shared_key_alice, cipher_alice) = XWing::encapsulate(csprng, pub_key_bob).unwrap();
            let _shared_key_bob = XWing::decapsulate(cipher_alice, secret_key_bob).unwrap();
        })
    });
    group.bench_function(
        "XWingDecapsulator + XWingEncapsulator: Generate+Encaps+Decaps with PK+CT serialization roundtrip",
        |b| {
            b.iter(|| {
                let (decapsulator, decapsulator_public) = XWingDecapsulator::new(csprng).unwrap();
                let encapsulator = XWingEncapsulator::new(
                    PublicKey::from_bytes(decapsulator_public.to_bytes()).unwrap(),
                    csprng,
                );
                let (_encapsulator_key, encapsulator_cipher) = encapsulator.encapsulate().unwrap();
                let _decapsulator_key = decapsulator
                    .decapsulate(Ciphertext::from_bytes(encapsulator_cipher.to_bytes()).unwrap())
                    .unwrap();
            })
        },
    );
    group.bench_function(
        "XWingDecapsulator + XWingEncapsulator: Generate+Encaps+Decaps with CT-only serialization roundtrip",
        |b| {
            b.iter(|| {
                let (decapsulator, decapsulator_public) = XWingDecapsulator::new(csprng).unwrap();
                let encapsulator = XWingEncapsulator::new(decapsulator_public, csprng);
                let (_encapsulator_key, encapsulator_cipher) = encapsulator.encapsulate().unwrap();
                let _decapsulator_key = decapsulator
                    .decapsulate(Ciphertext::from_bytes(encapsulator_cipher.to_bytes()).unwrap())
                    .unwrap();
            })
        },
    );
    group.bench_function(
        "XWingDecapsulator + XWingEncapsulator: Generate+Encaps+Decaps",
        |b| {
            b.iter(|| {
                let (decapsulator, decapsulator_public) = XWingDecapsulator::new(csprng).unwrap();
                let encapsulator = XWingEncapsulator::new(decapsulator_public, csprng);
                let (_encapsulator_key, encapsulator_cipher) = encapsulator.encapsulate().unwrap();
                let _decapsulator_key = decapsulator.decapsulate(encapsulator_cipher).unwrap();
            })
        },
    );
    group.bench_function("Deserialise+Serialise public key", |b| {
        let (_secret_key, public_key) = XWing::derive_key_pair(csprng).unwrap();
        b.iter(|| PublicKey::from_bytes(public_key.to_bytes()))
    });
    group.bench_function("Deserialise+Serialise ciphertext", |b| {
        let (_secret_key, public_key) = XWing::derive_key_pair(csprng).unwrap();
        let (_shared_secret, cipher) = XWing::encapsulate(csprng, public_key).unwrap();
        b.iter(|| Ciphertext::from_bytes(cipher.to_bytes()))
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

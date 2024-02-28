use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use x_wing::{Ciphertext, PublicKey, XWing, XWingClient, XWingServer};

pub fn criterion_benchmark(c: &mut Criterion) {
    let csprng = OsRng;
    c.bench_function("XWing: Generate+Encaps+Decaps", |b| {
        b.iter(|| {
            let (secret_key_bob, pub_key_bob) = XWing::derive_key_pair(csprng).unwrap();

            let (shared_key_alice, cipher_alice) = XWing::encapsulate(csprng, pub_key_bob).unwrap();
            let shared_key_bob = XWing::decapsulate(cipher_alice, secret_key_bob).unwrap();

            assert_eq!(shared_key_alice, shared_key_bob);
        })
    });
    c.bench_function("XWingServer + XWingclient: Generate+Encaps+Decaps", |b| {
        b.iter(|| {
            let (server, server_public) = XWingServer::new(csprng).unwrap();
            let client = XWingClient::new(server_public, csprng);
            let (client_key, client_cipher) = client.encapsulate().unwrap();
            let server_key = server.decapsulate(client_cipher).unwrap();

            assert_eq!(client_key, server_key);
        })
    });

    c.bench_function("Deserialise+Serialise public key", |b| {
        let (_, public_key) = XWing::derive_key_pair(csprng).unwrap();
        b.iter(|| PublicKey::from_bytes(public_key.to_bytes()))
    });
    c.bench_function("Deserialise+Serialise ciphertext", |b| {
        let (_, public_key) = XWing::derive_key_pair(csprng).unwrap();
        let (_, cipher) = XWing::encapsulate(csprng, public_key).unwrap();
        b.iter(|| Ciphertext::from_bytes(cipher.to_bytes()))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

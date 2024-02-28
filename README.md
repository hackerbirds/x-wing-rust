# A (not serious) implementation of the "X-Wing" Hybrid KEM in Rust

X-Wing is a Hybrid KEM combining X25519 and ML-KEM-768 (formerly known as Kyber-768). It is designed such that if either X25519 or ML-KEM-768 is secure, then X-Wing is also secure.

The X25519 implementation we're using is `x25519-dalek` and the ML-KEM implementation we're using is `pycrypto-kyber`.

X-Wing is currently under an RFC draft at https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-00.html.
The X-Wing paper which includes the IND-CCA security proof is at https://eprint.iacr.org/2024/039.pdf. 

*Please do note that X-Wing is designed with ML-KEM-768/X25519 specifically, and that changing these primitives to something else could break the security of X-Wing.*

# ! IMPORTANT !

## *This library did \_NOT\_...*

- Implement and verify the test vectors

The Kyber library we're using does not allow for deterministic decapsulation/encapsulation which is needed for the test vectors.

- Properly check time-constant operations

The X25519 and ML-KEM implementation are out of our control, and we are not checking for time-constant operations when it comes to generation etc. Such implementation that aren't constant-time are dangerous. 
However we do attempt to have a constant-time equality check for `PublicKey`, `SharedKey` and `Ciphertext` using the `subtle` crate.

- Receive any audits of any sort

...and we are absolutely not professionals. We wrote this for fun and learning, although this library may serve as a reference point to someone else trying to build a more serious library. Having said that, feel free to give us feedback.

# Usage

The recommended usage is with `XWingServer` and `XWingClient`. `XWingServer` is the part that generates the KEM secret and decapsulation (typically a server, hence the name) while `XWingClient` handles the generation of the shared key and the encapsulation using the server's public key.

```rust
use x_wing::{XWingClient, XWingServer};
use rand::rngs::OsRng;

let csprng = OsRng;
let server = XWingServer::new(csprng);
let client = XWingClient::new(server.public, csprng);

let (client_shared_key, client_cipher) = client.encapsulate();
let server_shared_key = server.decapsulate(client_cipher);

assert_eq!(client_shared_key, server_shared_key);
```

These structs make it difficult to Fuck Up™ because Rust will prevent you from leaking the secret, and will safely zeroize everything after encapsulating and decapsulating.

If you don't want that, you may also use `XWing` directly, and feed it the necessary secrets yourself:

```rust
use x_wing::XWing;
use rand::rngs::OsRng;

// In this example, Alice is the "client" and Bob is the "server". 
let csprng = OsRng;
let (secret_key_bob, pub_key_bob) = XWing::derive_key_pair(csprng);

let (shared_key_alice, cipher_alice) = XWing::encapsulate(csprng, pub_key_bob);
let shared_key_bob = XWing::decapsulate(cipher_alice, secret_key_bob);

assert_eq!(shared_key_alice, shared_key_bob);
```

# Install

Incluse the following like in the `[depedencies]` section of your `Cargo.toml`:

```x-wing = { git = "https://github.com/hackerbirds/x-wing-rust.git" }```

# Design considerations

- `SecretKey`, `Ciphertext`, and `SharedKey` are zeroized on Drop.
- The SecretKey is consumed after `decapsulate` to prevent secret reusage. SecretKey and SharedKey are not serialisable by default, although if you must, you can use the `serialise_secret_key` (and `serialise_shared_key`) feature.
# A POC implementation of the "X-Wing" Hybrid KEM in Rust

X-Wing is a Hybrid KEM combining X25519 and ML-KEM-768 (formerly known as Kyber-768). It is designed such that if either X25519 or ML-KEM-768 is secure, then X-Wing is also secure.

The X25519 implementation we're using is `x25519_dalek` and the ML-KEM implementation we're using is `pqc_kyber`.

X-Wing is currently under an RFC draft at https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-00.html.
The X-Wing paper which includes the IND-CCA security proof is at https://eprint.iacr.org/2024/039.pdf. 

*Please do note that X-Wing is designed with ML-KEM-768/X25519 specifically, and that changing these primitives to something else could break the security of X-Wing.*

# ⚠️ IMPORTANT

This library is not ready or safe for production. The ML-KEM/Kyber library we are using isn't currently compliant with the latest standard draft. See https://github.com/Argyle-Software/kyber/issues/54. 

## *This library did \_NOT\_...*

- Implement and verify the test vectors

The ML-KEM library we're using does not allow for deterministic decapsulation/encapsulation which is needed for the test vectors, but we do try to verify the ones we can. Furthermore, ML-KEM isn't finalised yet, so the test vectors might change again in the future.

- Check for time-constant operations

The X25519 and ML-KEM libraries are out of our control, and we are not checking for time-constant operations when it comes to generation etc. Such implementation that aren't constant-time are dangerous. 
However we do attempt to have a constant-time equality check for `PublicKey`, `SharedSecret` and `Ciphertext` using the `subtle` crate.

- Receive any audits of any sort

...and we are absolutely not professionals. We wrote this for fun and learning, although this library may serve as a reference point to someone else trying to build a more serious library. Having said that, feel free to give us feedback.

# Recommended usage

The recommended usage is with `XWingServer` and `XWingClient`. Note that "server" and "client" are just terms to differentiate between who's starting the key exchange. `XWingServer` can very well be used by clients. 

`XWingServer` is the party that generates the KEM secret and handles decapsulation while `XWingClient` generates the shared secret and handles the encapsulation using `XWingServer`'s public key.

These structs make it difficult to Fuck Up™ because this library will do a best-effort attempt at preventing you from leaking the secret, and will safely zeroize everything after encapsulating and decapsulating.

```rust
use x_wing::{XWingClient, XWingServer};
use rand::rngs::OsRng;

let csprng = OsRng;
let (server, server_public_key) = XWingServer::new(csprng)?;
let client = XWingClient::new(server_public_key, csprng);

let (client_shared_secret, client_cipher) = client.encapsulate()?;
let server_shared_secret = server.decapsulate(client_cipher)?;

assert_eq!(client_shared_secret, server_shared_secret);
```

### More general (but riskier) API 

If you don't want to use `XWingServer`/`XWingClient`, you may use `XWing` directly, and feed it the necessary secrets yourself:

```rust
use x_wing::XWing;
use rand::rngs::OsRng;

// In this example, Alice is the "client" and Bob is the "server". 
let csprng = OsRng;
let (secret_key_bob, pub_key_bob) = XWing::derive_key_pair(csprng)?;

let (shared_secret_alice, cipher_alice) = XWing::encapsulate(csprng, pub_key_bob)?;
let shared_secret_bob = XWing::decapsulate(cipher_alice, secret_key_bob)?;

assert_eq!(shared_secret_alice, shared_secret_bob);
```

# Install

Include the following line in the `[depedencies]` section of your `Cargo.toml`:

```x-wing = { git = "https://github.com/hackerbirds/x-wing-rust.git" }```

The crate in its current state will not be uploaded to crates.io because it simply isn't ready to be used in production--something that most people assume when they look for crates there, especially for cryptography.

# Design considerations

This crate makes it difficult to accidentally leak/keep secrets/one-time values in memory. The structures will zeroize and drop all the secrets/one-time values after usage. You must consume `XWingClient`/`XWingServer` to encapsulate/decapsulate the values. If needed, secrets also implement a constant-time `PartialEq` through the `subtle` crate. 

Serializing/deserializing secret values is only permitted when activating non-default flags, and of course you should be aware of the risks when doing that. It might also be that `serde` does not do constant-time serialisation, so keep this in mind. However, `to_bytes()` is probably constant-time, but `from_bytes()` might not be because of deserialization errors if the input slice is too small.
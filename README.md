# A POC implementation of the "X-Wing" Hybrid KEM in Rust

X-Wing is a Hybrid KEM combining X25519 and ML-KEM-768 (formerly known as Kyber-768). It is designed such that if either X25519 or ML-KEM-768 is secure, then X-Wing is also secure.

The X25519 implementation we're using is the `x25519_dalek` and the ML-KEM implementation we're using is the `ml-kem` crate.

X-Wing is currently under an RFC draft at https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-00.html.
The X-Wing paper which includes the IND-CCA security proof is at https://eprint.iacr.org/2024/039.pdf. 

*Please do note that X-Wing is designed with ML-KEM-768/X25519 specifically, and that changing these primitives to something else could break the security of X-Wing.*

## This library is not production ready

This library did not receive any audits, and the `ml-kem` crate we're using is not yet stable, and you should not use this in any production setting. 

...and we are absolutely not professionals. We wrote this for fun and learning, although this library may serve as a reference point to someone else trying to build a more serious library. Having said that, feel free to give us feedback.

# Recommended usage

The recommended usage is with `XWingDecapsulator` and `XWingEncapsulator`.

`XWingDecapsulator` is the party that generates the KEM secret and handles decapsulation while `XWingEncapsulator` generates the shared secret and handles the encapsulation using `XWingDecapsulator`'s public key.

These structs make it difficult to Fuck Up™ because this library will do a best-effort attempt at preventing you from leaking the secret, and will safely zeroize everything after encapsulating and decapsulating.

```rust
use x_wing::{XWingEncapsulator, XWingDecapsulator};
use rand::rngs::OsRng;

let csprng = OsRng;
let (decapsulator, decapsulator_public_key) = XWingDecapsulator::new(csprng)?;
let encapsulator = XWingEncapsulator::new(decapsulator_public_key, csprng);

let (encapsulator_shared_secret, encapsulator_cipher) = encapsulator.encapsulate()?;
let decapsulator_shared_secret = decapsulator.decapsulate(encapsulator_cipher)?;

assert_eq!(encapsulator_shared_secret, decapsulator_shared_secret);
```

### More general (but riskier) API 

If you don't want to use `XWingDecapsulator`/`XWingEncapsulator`, you may use `XWing` directly, and feed it the necessary secrets yourself:

```rust
use x_wing::XWing;
use rand::rngs::OsRng;

// In this example, Alice is the "encapsulator" and Bob is the "decapsulator". 
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

This crate makes it difficult to accidentally leak/keep secrets/one-time values in memory. The structures will zeroize and drop all the secrets/one-time values after usage. You must consume `XWingEncapsulator`/`XWingDecapsulator` to encapsulate/decapsulate the values. If needed, secrets also implement a constant-time `PartialEq` through the `subtle` crate. 

Serializing/deserializing secret values is only permitted when activating non-default flags, and of course you should be aware of the risks when doing that. It might also be that `serde` does not do constant-time serialisation, so keep this in mind. However, `to_bytes()` is probably constant-time, but `from_bytes()` might not be because of deserialization errors if the input slice is too small.
# A POC implementation of the "X-Wing" Hybrid KEM in Rust

X-Wing is a Hybrid KEM combining X25519 and ML-KEM-768 (formerly known as Kyber-768). It is designed such that if either X25519 or ML-KEM-768 is secure, then X-Wing is also secure.

The X25519 implementation we're using is the `x25519_dalek` and the ML-KEM implementation we're using is the `ml-kem` crate.

X-Wing is currently under an RFC draft at https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-00.html.
The X-Wing paper which includes the IND-CCA security proof is at https://eprint.iacr.org/2024/039.pdf. 

*Please do note that X-Wing is designed with ML-KEM-768/X25519 specifically, and that changing these primitives to something else could break the security of X-Wing.*

## Security

The safety of the implementation of this crate mainly depends: 

 - The implementation of the `ml-kem` and `x25519-dalek`, which we don't control. 
 - The randomness of the cryptographic RNG used (usually `OsRng`), which is up to the operating system.

Beyond that, we try to make sure that all secret values are handled in constant time, and are zeroized from memory after being used/dropped. 

## This library is not production ready

This library did not receive any audits, and the `ml-kem` crate we're using is not yet stable, and you should not use this in any production setting. 

...and we are absolutely not professionals. We wrote this for fun and learning, although this library may serve as a reference point to someone else trying to build a more serious library. Having said that, feel free to give us feedback.

# Recommended usage

The recommended usage is with `XWingDecapsulator` and `XWingEncapsulator`.

`XWingDecapsulator` is the party that generates the KEM secret and handles decapsulation while `XWingEncapsulator` generates the shared secret and handles the encapsulation using `XWingDecapsulator`'s public key.

These structs make it difficult to Fuck Up™ because this library will do a best-effort attempt at preventing you from leaking the secret, and will safely zeroize everything after completing encapsulating and decapsulating.

```rust
use x_wing::{XWingEncapsulator, XWingDecapsulator};
use rand::rngs::OsRng;

let csprng = OsRng;
let (server, server_public_key) = XWingDecapsulator::new(csprng)?;
let encapsulator = XWingEncapsulator::new(server_public_key, csprng);

let (encapsulator_shared_secret, encapsulator_cipher) = encapsulator.encapsulate()?;
let server_shared_secret = server.decapsulate(encapsulator_cipher)?;

assert_eq!(encapsulator_shared_secret, server_shared_secret);
```

### More general (but riskier) API 

If you don't want to use `XWingDecapsulator`/`XWingEncapsulator`, you may use `XWing` directly, and feed it the necessary secrets yourself:

```rust
use x_wing::XWing;
use rand::rngs::OsRng;

// In this example, Alice is the "encapsulator" and Bob is the "server". 
let csprng = OsRng;
let (secret_key_bob, pub_key_bob) = XWing::derive_key_pair(csprng)?;

let (shared_secret_alice, cipher_alice) = XWing::encapsulate(csprng, pub_key_bob)?;
let shared_secret_bob = XWing::decapsulate(cipher_alice, secret_key_bob)?;

assert_eq!(shared_secret_alice, shared_secret_bob);
```

# Install

Use `cargo`:

```
cargo add --git https://github.com/hackerbirds/x-wing-rust
```

The crate in its current state will not be uploaded to crates.io because it simply isn't ready to be used in production--something that most people assume when they look for crates there, especially for cryptography.
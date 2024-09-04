# A Rust library for the "X-Wing" Hybrid KEM 

X-Wing is a post-quantum secure Hybrid KEM combining X25519 and ML-KEM-768 (formerly known as Kyber-768). It is designed such that if SHA-3 and either X25519 or ML-KEM-768 is secure, then X-Wing is also secure.

X-Wing is currently under an RFC draft at https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/.
You may read more about X-Wing in this paper, which includes the security proofs https://eprint.iacr.org/2024/039.pdf.

## ⚠️ This library is not production ready

- This library (and `ml-kem`) did not receive any audits.
- X-Wing is not yet finalized and things may still change.
- This library was written by an idiot.

## Security

The security of the implementation of this crate depends:

 - The implementation of `ml-kem`, `sha3`, and `x25519-dalek`.
 - The randomness of the cryptographically secure PRNG used, which you will need to provide (typically `rand::OsRng`, which is the operating system's and in most cases is safe).

Beyond that, we have a best-effort attempt to prevent misuse of secret values through enforcements in the type system. By default, all secret values are zeroized after being used.

# Recommended usage

The recommended usage is with `XWingDecapsulator` and `XWingEncapsulator`.

`XWingDecapsulator` is the party that generates the KEM secret and handles decapsulation while `XWingEncapsulator` generates the shared secret and handles the encapsulation using `XWingDecapsulator`'s public key.

## Example

```rust
use x_wing::{XWingEncapsulator, XWingDecapsulator};
use rand::rngs::OsRng;

let csprng = OsRng;

let (decapsulator, decapsulator_public_key) = XWingDecapsulator::new(csprng);
let encapsulator = XWingEncapsulator::new(decapsulator_public_key, csprng);

let (encapsulator_shared_secret, encapsulator_cipher) = encapsulator.encapsulate();
let decapsulator_shared_secret = decapsulator.decapsulate(encapsulator_cipher);

assert_eq!(shared_secret_alice.to_slice(), shared_secret_bob.to_slice())
```

---

# More flexible (but risky) API

If you don't want to use `XWingDecapsulator`/`XWingEncapsulator`, you may use `XWing` instead, and feed it the necessary secrets yourself.

Because you are handling secret values directly, you must handle them with extra care. This API is therefore gated behind the `risky-api` feature, and you must enable it to use `XWing`.

```rust
use x_wing::XWing;
use rand::rngs::OsRng;

let csprng = OsRng;

// In this example, Alice is the "encapsulator" and Bob is the "decapsulator".
let (secret_key_bob, pub_key_bob) = XWing::derive_key_pair(csprng);
let (shared_secret_alice, cipher_alice) = XWing::encapsulate(csprng, &pub_key_bob);
let shared_secret_bob = XWing::decapsulate(cipher_alice, &secret_key_bob);

assert_eq!(shared_secret_alice.to_slice(), shared_secret_bob.to_slice())
```

# Serializing/exporting the secret key

If you must read/export the secret key, for instance in order to clone/reuse it, you can use the `serialize_secret_key` feature to serialize/deserialize `SecretKey` into bytes.

`SharedSecret` may be accessed with no feature flag.

# Install

Before installing, make sure you have read the "This library is not production ready" section, and understand that you should not use this code in production. However, if you just want to test out X-Wing or experiment with it, feel free to use this library.

To install this library, use `cargo`:

```
cargo add --git https://github.com/hackerbirds/x-wing-rust
```

The crate in its current state will not be uploaded to crates.io because it simply isn't ready to be used in production--something that most people assume when they look for crates there, especially for cryptography.

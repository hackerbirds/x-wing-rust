//! # A (not serious) implementation of the "X-Wing" Hybrid KEM in Rust
//!
//! X-Wing is a Hybrid KEM combining X25519 and ML-KEM-768 (formerly known as Kyber-768).
//! It is designed such that if either X25519 or ML-KEM-768 is secure, then X-Wing is also secure.
//!
//! The X25519 implementation we're using is [`x25519_dalek`] and the ML-KEM implementation we're using is [`pqc_kyber`].
//!
//! X-Wing is currently under an RFC draft at <https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-00.html>.
//! The X-Wing paper which includes the IND-CCA security proof is at <https://eprint.iacr.org/2024/039.pdf>.
//!
//! *Please do note that X-Wing is designed with ML-KEM-768/X25519 specifically, and that changing
//! these primitives to something else could break the security of X-Wing.*
//!
//! # ! IMPORTANT !
//!
//! ## *This library did \_NOT\_...*
//!
//! - Implement and verify the test vectors
//!
//! The Kyber library we're using does not allow for deterministic decapsulation/encapsulation which is
//! needed for the test vectors.
//!
//! - Properly check time-constant operations
//!
//! The X25519 and ML-KEM implementation are out of our control, and we are not checking for time-constant
//! operations when it comes to generation etc. Such implementation that aren't constant-time are dangerous.
//! However we do attempt to have a constant-time equality check for [`PublicKey`], [`SharedSecret`] and [`Ciphertext`]
//! using the [`subtle`] crate.
//!
//! - Receive any audits of any sort
//!
//! ...and we are absolutely not professionals. We wrote this for fun and learning, although this library may
//! serve as a reference point to someone else trying to build a more serious library. Having said that,
//! feel free to give us feedback.
//!
//! # Recommended usage
//!
//! The recommended usage is with [`XWingServer`] and [`XWingClient`]. Note that "server" and "client" are just
//! terms to differentiate between who's starting the key exchange. [`XWingServer`] can very well be used by clients.
//!
//! [`XWingServer`] is the party that generates the KEM secret and handles decapsulation while [`XWingClient`]
//! generates the shared secret and handles the encapsulation using [`XWingServer`]'s public key.
//!
//! ```rust
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use x_wing::{XWingClient, XWingServer};
//! use rand::rngs::OsRng;
//!
//! let csprng = OsRng;
//! let (server, server_public_key) = XWingServer::new(csprng)?;
//! let client = XWingClient::new(server_public_key, csprng);
//!
//! let (client_shared_secret, client_cipher) = client.encapsulate()?;
//! let server_shared_secret = server.decapsulate(client_cipher)?;
//!
//! assert_eq!(client_shared_secret, server_shared_secret);
//! #
//! #     Ok(())
//! # }
//! ```
//!
//! These structs make it difficult to Fuck Up™ because Rust will prevent you from leaking the secret, and
//! will safely zeroize everything after encapsulating and decapsulating.
//!
//! ### More general (but riskier) API  
//!
//! If you don't want to use [`XWingClient`]/[`XWingServer`], you may also use [`XWing`] directly, and feed
//! it the necessary secrets yourself:
//!
//! ```rust
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use x_wing::XWing;
//! use rand::rngs::OsRng;
//!
//! // In this example, Alice is the "client" and Bob is the "server".
//! let csprng = OsRng;
//! let (secret_key_bob, pub_key_bob) = XWing::derive_key_pair(csprng)?;
//!
//! let (shared_secret_alice, cipher_alice) = XWing::encapsulate(csprng, pub_key_bob)?;
//! let shared_secret_bob = XWing::decapsulate(cipher_alice, secret_key_bob)?;
//!
//! assert_eq!(shared_secret_alice, shared_secret_bob);
//! #
//! #     Ok(())
//! # }
//! ```
//!
//! # Install
//!
//! Include the following line in the `[depedencies]` section of your `Cargo.toml`:
//!
//! ```x-wing = { git = "https://github.com/hackerbirds/x-wing-rust.git" }```
//!
//! # Design considerations
//!
//! This crate makes it difficult to accidentally leak/keep secrets/one-time values in memory. The structures
//! will zeroize and drop all the secrets/one-time values after usage. You must consume [`XWingClient`]/[`XWingServer`]
//! to encapsulate/decapsulate the values. If needed, secrets also implement a constant-time [`PartialEq`]
//! through the [`subtle`] crate.
//!
//! Serializing/deserializing secret values is only permitted when activating non-default flags, and of course
//! you should be aware of the risks when doing that. It might also be that `serde` does not do constant-time
//! serialisation, so keep this in mind. However, `to_bytes()` is probably constant-time, but `from_bytes()`
//! might not be because of deserialization errors if the input slice is too small.

// Some constants give warnings
#![allow(dead_code)]
#![forbid(unsafe_code)]

use pqc_kyber::{PublicKey as MlKemPublicKey, SecretKey as MlKemSecretKey};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt::Debug;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{StaticSecret as X25519SecretKey, X25519_BASEPOINT_BYTES};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unexpected data when serialising")]
    SerialiseError,
    #[error("Unexpected data when deserialising")]
    DeserialiseError,
    #[error("Kyber error")]
    KyberError(#[from] pqc_kyber::KyberError),
}

// NOTE: ML-KEM is not finalised and thus these values can change
const XWING_SECRET_KEY_BYTES_LENGTH: usize = 2464;
const XWING_PUBLIC_KEY_BYTES_LENGTH: usize = 1216;
const XWING_CIPHERTEXT_BYTES_LENGTH: usize = 1120;
const XWING_SHARED_SECRET_BYTES_LENGTH: usize = 32;

type XWingSecretKey = [u8; XWING_SECRET_KEY_BYTES_LENGTH];
type XWingPublicKey = [u8; XWING_PUBLIC_KEY_BYTES_LENGTH];
type XWingSharedSecret = [u8; XWING_SHARED_SECRET_BYTES_LENGTH];
type XWingCiphertext = [u8; XWING_CIPHERTEXT_BYTES_LENGTH];

const ML_KEM_768_SECRET_KEY_BYTES_LENGTH: usize = pqc_kyber::KYBER_SECRETKEYBYTES;
const ML_KEM_768_PUBLIC_KEY_BYTES_LENGTH: usize = pqc_kyber::KYBER_PUBLICKEYBYTES;
const ML_KEM_768_CIPHERTEXT_BYTES_LENGTH: usize = pqc_kyber::KYBER_CIPHERTEXTBYTES;

const X25519_SECRET_KEY_BYTES_LENGTH: usize = 32;
const X25519_PUBLIC_KEY_BYTES_LENGTH: usize = 32;
type X25519PublicKey = [u8; X25519_PUBLIC_KEY_BYTES_LENGTH];

const X25519_CIPHERTEXT_BYTES_LENGTH: usize = 32;

// Rust's String/&str are UTF-8 encoded,
// and the X-Wing label is ASCII, but this
// is fine because ASCII is a subset of UTF-8.
const X_WING_LABEL: &[u8] = "\\.//^\\".as_bytes();

#[cfg_attr(
    all(feature = "serde", feature = "serialize_secret_key"),
    derive(Serialize, Deserialize)
)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[cfg_attr(
        all(feature = "serde", feature = "serialize_secret_key"),
        serde(with = "serde_arrays")
    )]
    ml_kem_secret: MlKemSecretKey,
    x25519_secret: X25519SecretKey,
    x25519_public: X25519PublicKey,
}

impl AsMut<SecretKey> for SecretKey {
    fn as_mut(&mut self) -> &mut SecretKey {
        self
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PublicKey {
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    ml_kem_public: MlKemPublicKey,
    x25519_public: X25519PublicKey,
}

impl AsMut<PublicKey> for PublicKey {
    fn as_mut(&mut self) -> &mut PublicKey {
        self
    }
}

impl ConstantTimeEq for PublicKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.ml_kem_public.ct_eq(&other.ml_kem_public)
            & self.x25519_public.ct_eq(&other.x25519_public)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Ciphertext {
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    ml_kem_cipher: [u8; ML_KEM_768_CIPHERTEXT_BYTES_LENGTH],
    x25519_cipher: [u8; X25519_CIPHERTEXT_BYTES_LENGTH],
}

impl AsMut<Ciphertext> for Ciphertext {
    fn as_mut(&mut self) -> &mut Ciphertext {
        self
    }
}

impl ConstantTimeEq for Ciphertext {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.ml_kem_cipher.ct_eq(&other.ml_kem_cipher)
            & self.x25519_cipher.ct_eq(&other.x25519_cipher)
    }
}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; XWING_SHARED_SECRET_BYTES_LENGTH]);

impl ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

/// The all-purpose API. Note that using this means you are handling with
/// secrets and one-time values on your own, and you must do so carefully.
/// For general purpose usage we highly recommend using [`XWingClient`] + [`XWingServer`]
/// instead.
pub struct XWing;

impl XWing {
    /// X-Wing's SHA-3 combiner to generate the shared secret from a multitude of values
    fn combiner(
        ml_kem_shared_secret: &[u8],
        x25519_shared_secret: &[u8],
        x25519_cipher: &[u8],
        x25519_public: &[u8],
    ) -> SharedSecret {
        let mut hasher = Sha3_256::new();

        hasher.update(X_WING_LABEL);
        hasher.update(ml_kem_shared_secret);
        hasher.update(x25519_shared_secret);
        hasher.update(x25519_cipher);
        hasher.update(x25519_public);
        let shared_secret_hash = hasher.finalize();

        SharedSecret(shared_secret_hash.into())
    }

    /// Deterministically generate a secret key and private key. Do not use this
    /// outside of testing.
    #[cfg(test)]
    fn derive_keypair_from_seed(seed: [u8; 96]) -> Result<(SecretKey, PublicKey), Error> {
        let ml_kem_keypair = pqc_kyber::derive(seed[0..64].try_into().expect("seed is 96 bytes"))?;
        let x25519_secret_bytes: [u8; 32] = seed[64..96].try_into().expect("seed is 96 bytes");
        let x25519_secret = X25519SecretKey::from(x25519_secret_bytes);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret).to_bytes();

        let secret = SecretKey {
            ml_kem_secret: ml_kem_keypair.secret,
            x25519_secret,
            x25519_public,
        };

        let public = PublicKey {
            ml_kem_public: ml_kem_keypair.public,
            x25519_public,
        };

        Ok((secret, public))
    }

    /// Generate a secret key and public key.
    pub fn derive_key_pair<R: Rng + CryptoRng>(
        mut csprng: R,
    ) -> Result<(SecretKey, PublicKey), Error> {
        let ml_kem_keypair = pqc_kyber::keypair(&mut csprng)?;
        let x25519_secret = X25519SecretKey::random_from_rng(&mut csprng);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret).to_bytes();

        let secret = SecretKey {
            ml_kem_secret: ml_kem_keypair.secret,
            x25519_secret,
            x25519_public,
        };

        let public = PublicKey {
            ml_kem_public: ml_kem_keypair.public,
            x25519_public,
        };

        Ok((secret, public))
    }

    /// Generate and encapsulate a secret value (as the "client") into a [`Ciphertext`]
    /// which should be sent to the other person (the "server").
    pub fn encapsulate<R: Rng + CryptoRng, Pk: AsMut<PublicKey>>(
        mut csprng: R,
        mut public_key: Pk,
    ) -> Result<(SharedSecret, Ciphertext), Error> {
        let secret_key_ephemeral = X25519SecretKey::random_from_rng(&mut csprng);
        let x25519_cipher = secret_key_ephemeral
            .diffie_hellman(&x25519_dalek::PublicKey::from(X25519_BASEPOINT_BYTES))
            .to_bytes();
        let pk = public_key.as_mut();
        let (ml_kem_cipher, ml_kem_shared_secret) =
            pqc_kyber::encapsulate(&pk.ml_kem_public, &mut csprng)?;
        let x25519_shared_secret = secret_key_ephemeral.diffie_hellman(&pk.x25519_public.into());

        let shared_secret = Self::combiner(
            &ml_kem_shared_secret,
            x25519_shared_secret.as_bytes(),
            &x25519_cipher,
            &pk.x25519_public,
        );

        let ciphertext = Ciphertext {
            ml_kem_cipher,
            x25519_cipher,
        };

        // Zeroize public key from memory when we're done
        pk.zeroize();

        Ok((shared_secret, ciphertext))
    }

    /// Decapsulate a [`Ciphertext`] using the KEM's [`SecretKey`] (that the "server" has)
    /// to retrieve [`SharedSecret`] sent by the "client"
    pub fn decapsulate<Ct: AsMut<Ciphertext>, Sk: AsMut<SecretKey>>(
        mut cipher: Ct,
        mut secret_key: Sk,
    ) -> Result<SharedSecret, Error> {
        let ct = cipher.as_mut();
        let sk = secret_key.as_mut();

        let ml_kem_shared_secret = pqc_kyber::decapsulate(&ct.ml_kem_cipher, &sk.ml_kem_secret)?;

        let x25519_shared_secret = sk
            .x25519_secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(ct.x25519_cipher));

        let shared_secret = Self::combiner(
            &ml_kem_shared_secret,
            x25519_shared_secret.as_bytes(),
            &ct.x25519_cipher,
            &sk.x25519_public,
        );

        // Zeroize cipher and secret key
        ct.zeroize();
        sk.zeroize();

        Ok(shared_secret)
    }
}

impl SecretKey {
    #[cfg(feature = "serialize_secret_key")]
    pub fn from_bytes(bytes: XWingSecretKey) -> Result<Self, Error> {
        let ml_kem_secret = bytes[0..ML_KEM_768_SECRET_KEY_BYTES_LENGTH]
            .try_into()
            .map_err(|_| Error::DeserialiseError)?;

        let x25519_secret_bytes: [u8; 32] = bytes[ML_KEM_768_SECRET_KEY_BYTES_LENGTH
            ..(ML_KEM_768_SECRET_KEY_BYTES_LENGTH + X25519_SECRET_KEY_BYTES_LENGTH)]
            .try_into()
            .map_err(|_| Error::DeserialiseError)?;

        let x25519_public: [u8; 32] = bytes[(ML_KEM_768_SECRET_KEY_BYTES_LENGTH
            + X25519_SECRET_KEY_BYTES_LENGTH)
            ..(ML_KEM_768_SECRET_KEY_BYTES_LENGTH
                + X25519_SECRET_KEY_BYTES_LENGTH
                + X25519_PUBLIC_KEY_BYTES_LENGTH)]
            .try_into()
            .map_err(|_| Error::DeserialiseError)?;

        Ok(SecretKey {
            ml_kem_secret,
            x25519_secret: X25519SecretKey::from(x25519_secret_bytes),
            x25519_public,
        })
    }

    #[cfg(feature = "serialize_secret_key")]
    pub fn to_bytes(&self) -> XWingSecretKey {
        let mut bytes = [0u8; XWING_SECRET_KEY_BYTES_LENGTH];
        bytes[0..ML_KEM_768_SECRET_KEY_BYTES_LENGTH].copy_from_slice(&self.ml_kem_secret);
        bytes[ML_KEM_768_SECRET_KEY_BYTES_LENGTH
            ..(ML_KEM_768_SECRET_KEY_BYTES_LENGTH + X25519_SECRET_KEY_BYTES_LENGTH)]
            .copy_from_slice(self.x25519_secret.as_bytes());
        bytes[(ML_KEM_768_SECRET_KEY_BYTES_LENGTH + X25519_SECRET_KEY_BYTES_LENGTH)
            ..(ML_KEM_768_SECRET_KEY_BYTES_LENGTH
                + X25519_SECRET_KEY_BYTES_LENGTH
                + X25519_PUBLIC_KEY_BYTES_LENGTH)]
            .copy_from_slice(&self.x25519_public);

        bytes
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: XWingPublicKey) -> Result<Self, Error> {
        let ml_kem_public = bytes[0..ML_KEM_768_PUBLIC_KEY_BYTES_LENGTH]
            .try_into()
            .map_err(|_| Error::DeserialiseError)?;

        let x25519_public = bytes[ML_KEM_768_PUBLIC_KEY_BYTES_LENGTH
            ..(ML_KEM_768_PUBLIC_KEY_BYTES_LENGTH + X25519_PUBLIC_KEY_BYTES_LENGTH)]
            .try_into()
            .map_err(|_| Error::DeserialiseError)?;

        Ok(PublicKey {
            ml_kem_public,
            x25519_public,
        })
    }

    pub fn to_bytes(&self) -> XWingPublicKey {
        let mut bytes = [0u8; XWING_PUBLIC_KEY_BYTES_LENGTH];
        bytes[0..ML_KEM_768_PUBLIC_KEY_BYTES_LENGTH].copy_from_slice(&self.ml_kem_public);
        bytes[ML_KEM_768_PUBLIC_KEY_BYTES_LENGTH
            ..(ML_KEM_768_PUBLIC_KEY_BYTES_LENGTH + X25519_PUBLIC_KEY_BYTES_LENGTH)]
            .copy_from_slice(&self.x25519_public);

        bytes
    }
}

impl Ciphertext {
    pub fn from_bytes(bytes: XWingCiphertext) -> Result<Self, Error> {
        let ml_kem_cipher = bytes[0..ML_KEM_768_CIPHERTEXT_BYTES_LENGTH]
            .try_into()
            .map_err(|_| Error::DeserialiseError)?;
        let x25519_cipher = bytes[ML_KEM_768_CIPHERTEXT_BYTES_LENGTH
            ..(ML_KEM_768_CIPHERTEXT_BYTES_LENGTH + X25519_CIPHERTEXT_BYTES_LENGTH)]
            .try_into()
            .map_err(|_| Error::DeserialiseError)?;

        Ok(Ciphertext {
            ml_kem_cipher,
            x25519_cipher,
        })
    }

    pub fn to_bytes(&self) -> XWingCiphertext {
        let mut bytes = [0u8; XWING_CIPHERTEXT_BYTES_LENGTH];
        bytes[0..ML_KEM_768_CIPHERTEXT_BYTES_LENGTH].copy_from_slice(&self.ml_kem_cipher);
        bytes[ML_KEM_768_CIPHERTEXT_BYTES_LENGTH
            ..(ML_KEM_768_CIPHERTEXT_BYTES_LENGTH + X25519_CIPHERTEXT_BYTES_LENGTH)]
            .copy_from_slice(&self.x25519_cipher);

        bytes
    }
}

#[cfg(feature = "serialize_shared_secret")]
impl SharedSecret {
    pub fn from_bytes(bytes: XWingSharedSecret) -> Self {
        SharedSecret(bytes)
    }

    pub fn to_bytes(&self) -> XWingSharedSecret {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// The "server" portion of XWing. The "server" is
/// whoever shares their public key to the other person
/// (the "client") and decapsulates their ciphertext.
///
/// Here is a basic usage:
/// ```rust
/// # use std::error::Error;
/// #
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use rand::rngs::OsRng;
/// use x_wing::*;
///
/// let csprng = OsRng;
/// let (server, server_public_key) = XWingServer::new(csprng)?;
/// let client = XWingClient::new(server_public_key, csprng);
///
/// let (client_shared_secret, client_cipher) = client.encapsulate()?;
/// let server_shared_secret = server.decapsulate(client_cipher)?;
/// assert_eq!(client_shared_secret, server_shared_secret);
/// #
/// #     Ok(())
/// # }
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct XWingServer {
    secret: Box<SecretKey>,
}

impl XWingServer {
    /// Initialise the server. It is crucial that `csprng` is *cryptographically secure*.
    /// You may use [`rand::rngs::OsRng`] under the (generally safe) assumption that all operating systems
    /// provide a cryptographically secure PRNG.
    ///
    /// Usage:
    /// ```rust
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use rand::rngs::OsRng;
    /// use x_wing::*;
    ///
    /// let csprng = OsRng;
    /// let (server, server_public_key) = XWingServer::new(csprng)?;
    /// #
    /// #     Ok(())
    /// # }
    /// ```
    pub fn new<R: Rng + CryptoRng>(csprng: R) -> Result<(Self, PublicKey), Error> {
        let (secret, public) = XWing::derive_key_pair(csprng)?;

        Ok((
            Self {
                secret: Box::new(secret),
            },
            public,
        ))
    }

    /// Decapsulate a [`Ciphertext`] generated by a "client"
    /// and retrieve the [`SharedSecret`]. Note that this call
    /// consumes [`XWingServer`], and you will no longer be able
    /// to use it afterward
    /// Usage:
    /// ```rust
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use rand::rngs::OsRng;
    /// use x_wing::*;
    /// // stuff...
    /// let csprng = OsRng;
    /// let (server, server_public_key) = XWingServer::new(csprng)?;
    /// let client = XWingClient::new(server_public_key, csprng);
    /// // Client generates ciphertext
    /// let (_, client_cipher) = client.encapsulate()?;
    /// // Ciphertext gets sent to server and decapsulates it...
    /// let shared_secret = server.decapsulate(client_cipher)?;
    /// // After this point, `server` is dropped and no longer exists
    /// #
    /// #     Ok(())
    /// # }
    /// ```
    pub fn decapsulate(mut self, cipher: Ciphertext) -> Result<SharedSecret, Error> {
        // NOTE: XWing::encapsulate will use zeroize() on the secret key and ciphertext after it's done
        XWing::decapsulate(cipher, &mut self.secret)
    }
}

/// The "client" portion of XWing. The "client" is
/// whoever encapsulates a generated shared secret with
/// the other person (the "server").
///
/// Here is a basic usage:
/// ```
/// # use std::error::Error;
/// #
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use rand::rngs::OsRng;
/// use x_wing::*;
///
/// let csprng = OsRng;
/// let (server, server_public_key) = XWingServer::new(csprng)?;
/// let client = XWingClient::new(server_public_key, csprng);
///
/// let (client_shared_secret, client_cipher) = client.encapsulate()?;
/// let server_shared_secret = server.decapsulate(client_cipher)?;
/// assert_eq!(client_shared_secret, server_shared_secret);
/// #
/// #     Ok(())
/// # }
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct XWingClient<R: Rng + CryptoRng> {
    pub server_public: Box<PublicKey>,
    #[zeroize(skip)]
    csprng: R,
}

impl<R: Rng + CryptoRng> XWingClient<R> {
    /// Initialise the client. It is crucial that `csprng` is *cryptographically secure*.
    /// You may use `rand`'s `OsRng` under the (generally safe) assumption that all operating systems
    /// provide a cryptographically secure PRNG.
    ///
    /// Usage:
    /// ```rust
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use rand::rngs::OsRng;
    /// use x_wing::*;
    ///
    /// let csprng = OsRng;
    /// let (server, server_public_key) = XWingServer::new(csprng)?;
    /// // ...
    /// let client = XWingClient::new(server_public_key, csprng);
    /// #
    /// #     Ok(())
    /// # }
    /// ```
    pub fn new<Pk: Into<PublicKey>>(server_public: Pk, csprng: R) -> Self {
        Self {
            server_public: Box::new(server_public.into()),
            csprng,
        }
    }

    /// Generate a shared secret, and encapsulate it with the server's public key.
    /// The [`SharedSecret`] should be kept secret and the [`Ciphertext`] should be sent to the server.
    pub fn encapsulate(mut self) -> Result<(SharedSecret, Ciphertext), Error> {
        // NOTE: XWing::encapsulate will use zeroize() on the public key after it's done
        XWing::encapsulate(&mut self.csprng, &mut self.server_public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn client_and_server() {
        let csprng = OsRng;
        let (server, server_public_key) =
            XWingServer::new(csprng).expect("XWingServer should generate keys successfully");
        let client = XWingClient::new(server_public_key, csprng);

        let (client_shared_secret, client_cipher) =
            client.encapsulate().expect("honest encapsulation works");
        let server_shared_secret = server
            .decapsulate(client_cipher)
            .expect("honest decapsulation works");

        assert_eq!(client_shared_secret, server_shared_secret);
    }

    #[test]
    fn encaps_decaps() {
        let csprng = OsRng;
        let (secret_key_bob, pub_key_bob) =
            XWing::derive_key_pair(csprng).expect("key generation works");

        let (shared_secret_alice, cipher_alice) =
            XWing::encapsulate(csprng, pub_key_bob).expect("honest encapsulation works");
        let shared_secret_bob =
            XWing::decapsulate(cipher_alice, secret_key_bob).expect("honest decapsulation works");

        assert_eq!(shared_secret_alice, shared_secret_bob);
    }

    #[cfg(feature = "serialize_secret_key")]
    #[test]
    fn test_vector_1_ietf() {
        use hex_literal::hex;
        // Incomplete
        //
        // Values taken from https://dconnolly.github.io/draft-connolly-cfrg-xwing-kem/draft-connolly-cfrg-xwing-kem.html#name-test-vectors-todo-replace-w
        // Because the values on the IETF document lack the X25519 public key in the secret key section?
        const KEY_SEED: [u8; 96] = hex!(
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2"
        );

        const XWING_SECRET_KEY: XWingSecretKey = hex!("24c59d1c7603e7b74bc7aa1bc2cb3a214b3cfaebb63bd85b65408427c498ba394371bb271f92a3b506b81d54a95a7c0ddfbaa1519553d6f3cd5a601b7db6b0e91a5149468f1f68ad26478bf3c6670e093ac4c49e7a90ba46595de94c50e04129a811a841b39534a87f0ae7b1116553e20c9a566b9b8ff7c7e728b8b201893403a4f252a55230874c256b897834cda349807b25cbd75a30867bfb80328200017f1cb70b56cc546b65d3dc9cdb45107cf10dba349619043ac35c0b9546309a239039813ed5c40f353a5e8e42193564496112bda56cb38c081df252ae9c2c7e441a062e92a7c8da7a240c9952d86b5f1bb6a53b38a5ac0a54a84b43f12da1d0525655684a12090b60b28b0c628db092015547d1070af5d6192e639636615d03c654bb90008ca15b784119f6178a00d7bef4a54a274ac922e55c61a3a8840aa258639484a3bce2e43b6c969b11275631daa129a61ea0e2939f0877e1a110c8a44b24c54fbb07a958db9feeca1eb52b086c87bf43a9b02a5b2c4762117c3a99ae4c4e2eaa7a33b9a714737215c10317514f6c4299ef92acd64c4858e85ce737a801890022d7381f3540230c0c8ef50a848a28b09ba0bf8b50619c905751601d7629767449c9c0b2bae321f438a77f412a55e45ecab4b39053c6561801c639be6495be8fa144ef6029af663407ca9181946de5f3aec7236343ab3bc5a38a09c01b412baf0afb23f9e9b8f2b40810f2ce4ffbcdbfd87972323e98065160bcba34b3afd6c25b664745fca99a9ea75cef019d768485ec23336d9b39e4d05d8d587b30633d4f69ade5753a39680235e44f27995da96798f3a85e184a9fad19320829629f4140417bb7dbf5851ab79258134146d088452774991a087a1c2beaea89f218087ba774ae253b494c27750b1de04b44d953c5e47ab10f65205ee212f9c30391e5299553954916873a0b41164543e801c0b099cb44f48995675823c10b40f4bbac9177a558ca0c30765c2aabfd6a4da54c8413e33902d63f064330f0464982429de2604cd03b4de84a9f821a5470423a40a964dcc41863363d77b02c3127304f942ee71c98c643a427533ef300104948b825277953aaabfd855588f75a77d199a213ad348116e9e539f6d37068a551c710548b7a2c7ee95f9cd9b3483332673cc44bcb18a778a49455c768e0b340f81102ac6b76b064057151ef101ae143787f548553558df8035a3ce00c9c43cda43142cca39034b09a7e6089867b4c64980a69ecab2e6818724c35cb909d5d45bc6a349c71b306567664adc0cc8ef698049b4b4b432dd0f69fac07580f77c4f79b22bb90cb97b341880716853431694c9120f6724ad58d57127fced999ff6229a5d4c3c240129cc812acc73698f949d8e73661f2528262bfccfa5cdf5a2104649806e295ea161217083365aa26cee6ae2f1356e8e1c5cefcc85703447ef1160a1b4a0e8c017b173802c66c88ab70d39a6c96c1569d5a86245a7eeb087d682219080768745b44bf244f65b567b2658dbae6962ba52b322118e214cfadd7cf3502582dc9cafba952a9637ad3600710259778d99d23f8235da90791604b4f0a4f7640680f59b633d93dfb84282ba54c674b115684a41bc331b659a61a04883d0c5ebbc0772754a4c33b6a90e52e0678ce06a0453ba8a188b15a496bae6a24177b636d12fbb088f2cd9504ac200231473031a31a5c62e46288fb3edb858b21bc0ea59a212fd1c6dba09e920712d068a2be7abcf4f2a3533443ee1780dd419681a960cd90af5fcaab8c1552ef25572f157a2bbb934a18a5c57a761b54a45d774ac6bc593583a1bcfc4dcd0cca87ab9cff463dc5e80ebbb501d18c8b39e324dbd07ca06cbf75ba33297abcc7aabdd5b308401ba387f533f3927b51e91380f5a59b119e354835ab182db62c76d6d85fa63241743a52012aac281222bc0037e2c493b4777a99cb5929aba155a006bc9b461c365fa3583fac5414b403af9135079b33a10df8819cb462f067253f92b3c45a7fb1c1478d4091e39010ba44071019010daa15c0f43d14641a8fa3a94cfaa2a877ae8113bbf8221ee13223376494fb128b825952d5105ae4157dd6d70f71d5bd48f34d469976629bce6c12931c88ca0882965e27538f272b19796b251226075b131b38564f90159583cd9c4c3c098c8f06a267b262b8731b9e962976c41152a76c30b502d0425635357b43cd3a3ecef5bc9910bb89ca9e91ba75e8121d53c2329b5222df12560d242724523ff60b6ead310d99954d483b91383a726a937f1b60b474b22ea5b81954580339d81c9f47bab44a3fe0c833a7dba1f5b33a5a2a459812645c6537c2317163d71b7bd7a4a5459a28a1c28659aad9a1ca9a99a363062d453355108445a673438e77624e73757c1a84d031cf0fb24b1187aafbe6738e9abaf5b42b004b1fa0d96426d3c5324235dd871e7a89364d335ebb6718ad098154208b143b2b43eb9e5fd8816c5225d494b40809b2459903c6486a1db9ac3414945e1867b5869c2f88cf9edc0a216681804578d34923e5a353babba923db907725b384e74e66987292e007e05c6766f267f839b7617c55e28b0fa2121da2d037d6830af9d869e1fb52b0cb645fe221a79b2a46e41980d34671ccc58d8756054b2cca7b13715a05f3925355cca838ab8d2425255f61135727167ad6bcb0632ebf86384b950ad21088c292b4a4fcc0e59c42d3f77fac85cd9f5cb049b3a29505a984c4c6ac98ca3d0a8f30d2b1bd9815b94b27051b40ffc3455a668b9e141428611b280c1b8f2b55f6eb04e10c68f1340ef1582115f10ee2b785b7ebb0ec3a0c61670cf48107b594cd6e238e0d68961b47983b87879771519d2b7c21681cd494b420f03d004bb06eeb54f9c080c2f2aff6759074d5b3a3b11c73f1af6dc874eeec254d5409fceaa90ff66d90b6930a540fd1d9be1844af1d861ff96a611a414a6c61a78fb2a78e74383ab05ebc73855a818a627242d523a3e2a35ab4285b4a2564f76772aaf8cdc9f87c65f1b4b5819905fb4f9ea59166fbbdb201c5eefc0df7418ca211b5b079a511b8b94429847b537fbed82d57632d63e815d8212d8a280d43328604a6c4d2c1887e7ab061f120a0168db2f4735369b193780f0aeb381ff2653f3b46e206afe77a7e814c7716a1b166727dd2a0b9a7d8aeace425da63977f8103457c9f438a2676c10e3a9c630b855873288ee560ca05c37cc7329e9e502cfac918b9420544445d4cfa93f56ee922c7d660937b5937c3074d62968f006d1211c60296685953e5def3804c2dad5c36180137c1df12f31385b670fde5cfe76447f6c4b5b50083553c3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2e56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15");
        const XWING_PUBLIC_KEY: XWingPublicKey = hex!("1bc331b659a61a04883d0c5ebbc0772754a4c33b6a90e52e0678ce06a0453ba8a188b15a496bae6a24177b636d12fbb088f2cd9504ac200231473031a31a5c62e46288fb3edb858b21bc0ea59a212fd1c6dba09e920712d068a2be7abcf4f2a3533443ee1780dd419681a960cd90af5fcaab8c1552ef25572f157a2bbb934a18a5c57a761b54a45d774ac6bc593583a1bcfc4dcd0cca87ab9cff463dc5e80ebbb501d18c8b39e324dbd07ca06cbf75ba33297abcc7aabdd5b308401ba387f533f3927b51e91380f5a59b119e354835ab182db62c76d6d85fa63241743a52012aac281222bc0037e2c493b4777a99cb5929aba155a006bc9b461c365fa3583fac5414b403af9135079b33a10df8819cb462f067253f92b3c45a7fb1c1478d4091e39010ba44071019010daa15c0f43d14641a8fa3a94cfaa2a877ae8113bbf8221ee13223376494fb128b825952d5105ae4157dd6d70f71d5bd48f34d469976629bce6c12931c88ca0882965e27538f272b19796b251226075b131b38564f90159583cd9c4c3c098c8f06a267b262b8731b9e962976c41152a76c30b502d0425635357b43cd3a3ecef5bc9910bb89ca9e91ba75e8121d53c2329b5222df12560d242724523ff60b6ead310d99954d483b91383a726a937f1b60b474b22ea5b81954580339d81c9f47bab44a3fe0c833a7dba1f5b33a5a2a459812645c6537c2317163d71b7bd7a4a5459a28a1c28659aad9a1ca9a99a363062d453355108445a673438e77624e73757c1a84d031cf0fb24b1187aafbe6738e9abaf5b42b004b1fa0d96426d3c5324235dd871e7a89364d335ebb6718ad098154208b143b2b43eb9e5fd8816c5225d494b40809b2459903c6486a1db9ac3414945e1867b5869c2f88cf9edc0a216681804578d34923e5a353babba923db907725b384e74e66987292e007e05c6766f267f839b7617c55e28b0fa2121da2d037d6830af9d869e1fb52b0cb645fe221a79b2a46e41980d34671ccc58d8756054b2cca7b13715a05f3925355cca838ab8d2425255f61135727167ad6bcb0632ebf86384b950ad21088c292b4a4fcc0e59c42d3f77fac85cd9f5cb049b3a29505a984c4c6ac98ca3d0a8f30d2b1bd9815b94b27051b40ffc3455a668b9e141428611b280c1b8f2b55f6eb04e10c68f1340ef1582115f10ee2b785b7ebb0ec3a0c61670cf48107b594cd6e238e0d68961b47983b87879771519d2b7c21681cd494b420f03d004bb06eeb54f9c080c2f2aff6759074d5b3a3b11c73f1af6dc874eeec254d5409fceaa90ff66d90b6930a540fd1d9be1844af1d861ff96a611a414a6c61a78fb2a78e74383ab05ebc73855a818a627242d523a3e2a35ab4285b4a2564f76772aaf8cdc9f87c65f1b4b5819905fb4f9ea59166fbbdb201c5eefc0df7418ca211b5b079a511b8b94429847b537fbed82d57632d63e815d8212d8a280d43328604a6c4d2c1887e7ab061f120a0168db2f4735369b193780f0aeb381ff2653f3b46e206afe77a7e814c7716a1b166727dd2a0b9a7d8aeace425da63977f8103457c9f438a2676c10e3a9c630b855873288ee560ca05c37cc7329e9e502cfac918b9420544445d4cfa93f56ee922c7d660937b5937c3074d62968f006d1211c60296685953e5dee56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15");

        let (secret_key_bob, pub_key_bob) =
            XWing::derive_keypair_from_seed(KEY_SEED).expect("key generation works");

        assert_eq!(secret_key_bob.to_bytes(), XWING_SECRET_KEY);
        assert_eq!(pub_key_bob.to_bytes(), XWING_PUBLIC_KEY);
    }

    #[test]
    fn deserialise_and_serialize() {
        let csprng = OsRng;
        #[allow(unused_variables)]
        let (secret_key, public_key) =
            XWing::derive_key_pair(csprng).expect("key generation works");

        #[cfg(feature = "serialize_secret_key")]
        {
            let other_secret =
                SecretKey::from_bytes(secret_key.to_bytes()).expect("deserialisation works");
            assert!(other_secret.ml_kem_secret.eq(&secret_key.ml_kem_secret));
            assert!(other_secret
                .x25519_secret
                .as_bytes()
                .eq(secret_key.x25519_secret.as_bytes()));
            assert!(other_secret.x25519_public.eq(&secret_key.x25519_public));
        }

        let other_public =
            PublicKey::from_bytes(public_key.to_bytes()).expect("deserialisation works");
        assert!(other_public.ml_kem_public.eq(&public_key.ml_kem_public));
        assert!(other_public.x25519_public.eq(&public_key.x25519_public));

        #[cfg(feature = "serialize_shared_secret")]
        {
            let (shared_secret, cipher) =
                XWing::encapsulate(csprng, public_key).expect("honest encapsulation works");
            let other_cipher =
                Ciphertext::from_bytes(cipher.to_bytes()).expect("deserialisation works");
            assert_eq!(cipher, other_cipher);
            let other_shared_secret = SharedSecret::from_bytes(shared_secret.to_bytes());
            assert_eq!(shared_secret, other_shared_secret);
        }
    }
}

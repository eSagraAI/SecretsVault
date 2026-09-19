//! Symmetric primitives: zeroizing keys, Argon2id KDF, XChaCha20-Poly1305 AEAD.
//!
//! Nothing here ever renders key material: `Debug` is redacted and buffers are
//! wrapped in `Zeroizing` (wiped on drop / lock).

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;

use crate::error::VaultError;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

/// 256-bit symmetric key (MEK, DEK or KEK). Wiped on drop; `Debug` redacts.
#[derive(Clone)]
pub struct SecretKey(Zeroizing<[u8; KEY_LEN]>);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Generate from the operating system CSPRNG. Panics only if the OS RNG
    /// itself fails, which is unrecoverable.
    pub fn generate() -> Self {
        Self(Zeroizing::new(
            random_bytes::<KEY_LEN>().expect("operating system CSPRNG failed"),
        ))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// Fill a buffer from the operating system CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf)
        .map_err(|e| VaultError::Io(std::io::Error::other(format!("csprng failure: {e}"))))?;
    Ok(buf)
}

/// SHA-256 digest used for token storage (high-entropy random tokens — no
/// slow KDF needed), for agent lookups and for lease credential lookups.
pub fn token_digest(token: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode lowercase (or upper) hex; `None` on any malformed input.
/// Used for handshake nonces/keys — never for secrets.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Generate a 256-bit capability credential from the OS CSPRNG, base64url
/// encoded. Returns the credential plus its digest and display prefix; only
/// the digest and prefix are ever persisted or shown.
pub fn generate_capability() -> Result<(String, [u8; 32], String), VaultError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let bytes = random_bytes::<32>()?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let digest = token_digest(&token);
    Ok((token, digest, hex(&digest[..4])))
}

/// Generate a one-time agent token (256-bit capability credential).
pub fn generate_agent_token() -> Result<(String, [u8; 32], String), VaultError> {
    generate_capability()
}

/// Derive a 256-bit KEK from a passphrase with Argon2id.
pub fn derive_kek(
    passphrase: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
    salt: &[u8],
) -> Result<SecretKey, VaultError> {
    let params = Params::new(m_kib, t, p, Some(KEY_LEN))
        .map_err(|e| VaultError::Protocol(format!("invalid kdf params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut kek)
        .map_err(|e| VaultError::Protocol(format!("kdf failure: {e}")))?;
    Ok(SecretKey::from_bytes(kek))
}

/// Authenticated encryption (XChaCha20-Poly1305) with associated data.
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AEAD seal with explicit key/nonce cannot fail")
}

/// Opaque AEAD failure. Carries no detail on purpose: callers classify the
/// error (Auth vs Corrupt) without learning why authentication failed.
#[derive(Debug)]
pub struct AeadMismatch;

/// Authenticated decryption; any tag/AAD mismatch is an opaque failure
/// (`Err(AeadMismatch)`) so callers classify it without leaking why.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadMismatch> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_tamper() {
        let key = SecretKey::generate();
        let nonce = random_bytes::<NONCE_LEN>().unwrap();
        let ct = seal(key.as_bytes(), &nonce, b"attack at dawn", b"header");
        let pt = open(key.as_bytes(), &nonce, &ct, b"header").unwrap();
        assert_eq!(pt, b"attack at dawn");

        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert!(open(key.as_bytes(), &nonce, &tampered, b"header").is_err());

        // AAD is authenticated: flipping it must fail the tag.
        assert!(open(key.as_bytes(), &nonce, &ct, b"other").is_err());
    }

    #[test]
    fn fresh_nonces_produce_different_ciphertexts() {
        let key = SecretKey::generate();
        let n1 = random_bytes::<NONCE_LEN>().unwrap();
        let n2 = random_bytes::<NONCE_LEN>().unwrap();
        assert_ne!(n1, n2);
        assert_ne!(
            seal(key.as_bytes(), &n1, b"x", b""),
            seal(key.as_bytes(), &n2, b"x", b"")
        );
    }

    #[test]
    fn derive_kek_is_deterministic_and_input_sensitive() {
        let salt = random_bytes::<SALT_LEN>().unwrap();
        let a = derive_kek(b"passphrase", 19456, 2, 1, &salt).unwrap();
        let b = derive_kek(b"passphrase", 19456, 2, 1, &salt).unwrap();
        let c = derive_kek(b"passphrase2", 19456, 2, 1, &salt).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }
}

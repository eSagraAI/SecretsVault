//! Versioned vault envelope: header (key slots + DEK wrap) and the
//! DEK-encrypted document, bound together by header-as-AAD authentication.
//!
//! File layout:
//! `SVAULT` (6B magic) · u32 LE version · u32 LE header length · header JSON ·
//! 24B document nonce · document ciphertext (includes the 16B Poly1305 tag).
//!
//! Classification of AEAD failures (cryptographically honest):
//! - passphrase-slot unwrap failure → `Auth` (wrong passphrase and tampered
//!   slot are indistinguishable by design);
//! - DEK-wrap or document failure after a successful unwrap → `Corrupt`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_ENGINE;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, KEY_LEN, NONCE_LEN, SALT_LEN, SecretKey};
use crate::error::VaultError;

pub const MAGIC: &[u8; 6] = b"SVAULT";
pub const VERSION: u32 = 1;
pub const TAG_LEN: usize = 16;

const MEK_AAD_PREFIX: &str = "svault/v1/mek:";
const DEK_AAD: &[u8] = b"svault/v1/dek";
const ARGON2ID: &str = "argon2id";
/// OWASP-recommended minimums; anything below is refused at unlock.
pub const MIN_M_KIB: u32 = 19456;
pub const MIN_T: u32 = 2;
/// Upper bounds for untrusted header KDF parameters: a tampered vault must
/// not be able to request absurd memory/time/lanes and turn unlock into a
/// local DoS (OOM / multi-minute hashing).
///
/// These are generous multiples of the 64 MiB / t=3 / p=4 defaults — 4x
/// memory, 3.3x passes, 2x lanes — because a header is attacker-writable and
/// a denial is charged to the legitimate owner. The previous 1 GiB / t=16
/// ceiling let a valid header demand ~6 s of CPU and 1 GiB of RAM per attempt
/// (measured, release; ~133 s unoptimized), and no real vault needs that.
pub const MAX_M_KIB: u32 = 262_144; // 256 MiB
pub const MAX_T: u32 = 10;
pub const MAX_P: u32 = 8;
/// Most key slots a vault may declare. Every passphrase slot costs a full
/// Argon2 derivation per unlock attempt, so an unbounded slot table is a
/// straight CPU amplification vector. A real vault needs one (a handful, at
/// most, once backup slots land).
pub const MAX_SLOTS: usize = 8;
/// Structural limits applied before any parsing or allocation: the header is
/// plaintext and attacker-writable, so its claimed size is capped, and files
/// beyond the cap are rejected without being read into memory.
pub const MAX_HEADER_LEN: usize = 1024 * 1024;
pub const MAX_FILE_LEN: usize = 16 * 1024 * 1024;

/// A byte blob serialized as a base64 string in JSON. Backed by
/// `Zeroizing` so key-wraps, salts and secret values are wiped on drop.
#[derive(Clone, PartialEq)]
pub struct B64(pub Zeroizing<Vec<u8>>);

impl Serialize for B64 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&B64_ENGINE.encode(&*self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        B64_ENGINE
            .decode(&s)
            .map(|v| B64(Zeroizing::new(v)))
            .map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for B64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "B64(<{} bytes>)", self.0.len())
    }
}

/// Slot types. Unknown types from newer versions are preserved as `Other`
/// so older readers never destroy data they do not understand.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(from = "String", into = "String")]
pub enum SlotType {
    Passphrase,
    Backup,
    Keychain,
    Sync,
    Other(String),
}

impl From<String> for SlotType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "passphrase" => Self::Passphrase,
            "backup" => Self::Backup,
            "keychain" => Self::Keychain,
            "sync" => Self::Sync,
            _ => Self::Other(s),
        }
    }
}

impl From<SlotType> for String {
    fn from(t: SlotType) -> Self {
        match t {
            SlotType::Passphrase => "passphrase".into(),
            SlotType::Backup => "backup".into(),
            SlotType::Keychain => "keychain".into(),
            SlotType::Sync => "sync".into(),
            SlotType::Other(s) => s,
        }
    }
}

impl std::fmt::Display for SlotType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from(self.clone()))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct KdfParams {
    pub algo: String,
    /// Argon2 memory cost, in KiB.
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// CLI defaults: 64 MiB, 3 passes, 4 lanes.
    pub fn argon2id_defaults() -> Self {
        Self {
            algo: ARGON2ID.into(),
            m_kib: 65536,
            t: 3,
            p: 4,
        }
    }

    pub fn validate(&self) -> Result<(), VaultError> {
        if self.algo != ARGON2ID
            || self.m_kib < MIN_M_KIB
            || self.m_kib > MAX_M_KIB
            || self.t < MIN_T
            || self.t > MAX_T
            || self.p < 1
            || self.p > MAX_P
        {
            return Err(VaultError::InsecureParams);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Slot {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: SlotType,
    pub kdf: KdfParams,
    pub salt: B64,
    pub nonce: B64,
    pub wrapped_mek: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WrappedKey {
    pub nonce: B64,
    pub wrapped: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Header {
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub slots: Vec<Slot>,
    pub dek: WrappedKey,
}

/// Key material held only while unlocked. Wiped on drop (zeroized buffers).
/// `Debug` is safe to derive: `SecretKey`'s own `Debug` redacts contents.
#[derive(Clone, Debug)]
pub struct Keys {
    pub mek: SecretKey,
    pub dek: SecretKey,
}

pub struct Envelope {
    pub header: Header,
    doc_nonce: [u8; NONCE_LEN],
    doc_ct: Vec<u8>,
}

impl Envelope {
    /// Build a fresh v1 envelope with a single passphrase slot wrapping a new
    /// MEK, which wraps a new DEK, which seals `document`.
    pub fn create(
        passphrase: &[u8],
        document: &[u8],
        created_at: OffsetDateTime,
    ) -> Result<Self, VaultError> {
        let mek = SecretKey::generate();
        let dek = SecretKey::generate();

        let salt: [u8; SALT_LEN] = crypto::random_bytes()?;
        let nonce: [u8; NONCE_LEN] = crypto::random_bytes()?;
        let id = hex_id()?;
        let kdf = KdfParams::argon2id_defaults();
        let kek = crypto::derive_kek(passphrase, kdf.m_kib, kdf.t, kdf.p, &salt)?;
        let wrapped_mek = crypto::seal(kek.as_bytes(), &nonce, mek.as_bytes(), &mek_aad(&id));
        let slot = Slot {
            id,
            kind: SlotType::Passphrase,
            kdf,
            salt: B64(Zeroizing::new(salt.to_vec())),
            nonce: B64(Zeroizing::new(nonce.to_vec())),
            wrapped_mek: B64(Zeroizing::new(wrapped_mek)),
        };

        let dek_nonce: [u8; NONCE_LEN] = crypto::random_bytes()?;
        let dek_wrap = WrappedKey {
            nonce: B64(Zeroizing::new(dek_nonce.to_vec())),
            wrapped: B64(Zeroizing::new(crypto::seal(
                mek.as_bytes(),
                &dek_nonce,
                dek.as_bytes(),
                DEK_AAD,
            ))),
        };

        let header = Header {
            created_at,
            slots: vec![slot],
            dek: dek_wrap,
        };
        let doc_nonce: [u8; NONCE_LEN] = crypto::random_bytes()?;
        let doc_ct = crypto::seal(
            dek.as_bytes(),
            &doc_nonce,
            document,
            &canonical_header(&header)?,
        );
        Ok(Self {
            header,
            doc_nonce,
            doc_ct,
        })
    }

    /// Parse and validate an envelope from raw file bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, VaultError> {
        const PREFIX: usize = MAGIC.len() + 4 + 4;
        let corrupt = |why: &str| Err(VaultError::Corrupt(why.to_string()));

        if bytes.len() < PREFIX + NONCE_LEN + TAG_LEN {
            return corrupt("truncated file");
        }
        if bytes.len() > MAX_FILE_LEN {
            return corrupt("file exceeds maximum size");
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return corrupt("bad magic");
        }
        let version = u32::from_le_bytes(bytes[MAGIC.len()..MAGIC.len() + 4].try_into().unwrap());
        if version != VERSION {
            return corrupt("unsupported envelope version");
        }
        let header_len =
            u32::from_le_bytes(bytes[MAGIC.len() + 4..PREFIX].try_into().unwrap()) as usize;
        if header_len > MAX_HEADER_LEN {
            return corrupt("header exceeds maximum size");
        }
        let rest = &bytes[PREFIX..];
        if header_len + NONCE_LEN + TAG_LEN > rest.len() {
            return corrupt("header length out of bounds");
        }
        let header: Header = serde_json::from_slice(&rest[..header_len])
            .map_err(|_| VaultError::Corrupt("invalid header".to_string()))?;
        if header.slots.is_empty() {
            return corrupt("no key slots");
        }
        if header.slots.len() > MAX_SLOTS {
            return corrupt("too many key slots");
        }
        for slot in &header.slots {
            // Structural checks only for slot types this version understands;
            // unknown types belong to future versions and are preserved as-is.
            match slot.kind {
                SlotType::Passphrase | SlotType::Backup | SlotType::Keychain | SlotType::Sync => {
                    if slot.salt.0.len() != SALT_LEN
                        || slot.nonce.0.len() != NONCE_LEN
                        || slot.wrapped_mek.0.len() != KEY_LEN + TAG_LEN
                    {
                        return corrupt("invalid slot field lengths");
                    }
                }
                SlotType::Other(_) => {}
            }
        }
        if header.dek.nonce.0.len() != NONCE_LEN || header.dek.wrapped.0.len() != KEY_LEN + TAG_LEN
        {
            return corrupt("invalid dek wrap field lengths");
        }
        let doc_nonce: [u8; NONCE_LEN] =
            rest[header_len..header_len + NONCE_LEN].try_into().unwrap();
        let doc_ct = rest[header_len + NONCE_LEN..].to_vec();
        if doc_ct.len() < TAG_LEN {
            return corrupt("document ciphertext truncated");
        }
        Ok(Self {
            header,
            doc_nonce,
            doc_ct,
        })
    }

    /// Serialize back to file bytes (header is re-canonicalized).
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = canonical_header(&self.header).expect("header serialization");
        let mut out = Vec::with_capacity(14 + header_bytes.len() + NONCE_LEN + self.doc_ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&self.doc_nonce);
        out.extend_from_slice(&self.doc_ct);
        out
    }

    /// Validate that this envelope could be read back by [`Self::parse`].
    ///
    /// The loader refuses files/headers beyond the format caps; a writer that
    /// skipped this check could persist a vault that is permanently
    /// unopenable. Must be called before any publish (the caps are the same
    /// constants the parser enforces, so writer and reader cannot drift).
    pub fn validate_persistable(&self) -> Result<(), VaultError> {
        let header_len = canonical_header(&self.header)?.len();
        if header_len > MAX_HEADER_LEN {
            return Err(VaultError::VaultTooLarge);
        }
        let total = MAGIC.len() + 4 + 4 + header_len + NONCE_LEN + self.doc_ct.len();
        if total > MAX_FILE_LEN {
            return Err(VaultError::VaultTooLarge);
        }
        Ok(())
    }

    /// Unwrap MEK and DEK using a passphrase slot. All slot failures collapse
    /// into the generic `Auth` error.
    ///
    /// Convenience wrapper over [`Self::kek_recipe`] + [`KekRecipe::derive`] +
    /// [`Self::unlock_with`]. Callers that must keep a lock out of the
    /// derivation (the broker: see `Daemon::derive_human_proof`) use the split
    /// form directly.
    pub fn unlock(&self, passphrase: &[u8]) -> Result<Keys, VaultError> {
        self.unlock_with(&KekRecipe::of(self)?.derive(passphrase)?)
    }

    /// Derive the KEK candidates for `passphrase` from this header.
    ///
    /// Cheap and secretless: only public header fields (salts, KDF params,
    /// slot kinds) are read. The caller does the expensive work in
    /// [`KekRecipe::derive`] and comes back to [`Self::unlock_with`].
    pub fn kek_recipe(&self) -> Result<KekRecipe, VaultError> {
        KekRecipe::of(self)
    }

    /// Apply pre-derived KEKs. Only the AEAD unwraps happen here — no key
    /// derivation — so this is cheap enough to run under a lock.
    ///
    /// All failures collapse into the generic `Auth` error: a wrong
    /// passphrase and a tampered slot are indistinguishable by design.
    pub fn unlock_with(&self, derived: &DerivedKeks) -> Result<Keys, VaultError> {
        for (index, kek) in derived.iter() {
            let Some(slot) = self.header.slots.get(index) else {
                continue;
            };
            if slot.kind != SlotType::Passphrase {
                continue;
            }
            let nonce: [u8; NONCE_LEN] = match slot.nonce.0.as_slice().try_into() {
                Ok(n) => n,
                Err(_) => return Err(VaultError::Corrupt("invalid slot nonce length".into())),
            };
            if let Ok(mut mek_bytes) = crypto::open(
                kek.as_bytes(),
                &nonce,
                &slot.wrapped_mek.0,
                &mek_aad(&slot.id),
            ) {
                let arr: [u8; KEY_LEN] = match mek_bytes.as_slice().try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        mek_bytes.zeroize();
                        return Err(VaultError::Corrupt("wrapped mek length invalid".into()));
                    }
                };
                mek_bytes.zeroize();
                let mek = SecretKey::from_bytes(arr);
                let dek = self.unwrap_dek(&mek)?;
                return Ok(Keys { mek, dek });
            }
            // Wrong passphrase (or tampered slot — indistinguishable):
            // try remaining passphrase slots, else generic Auth.
        }
        Err(VaultError::Auth)
    }

    fn unwrap_dek(&self, mek: &SecretKey) -> Result<SecretKey, VaultError> {
        let nonce: [u8; NONCE_LEN] = self
            .header
            .dek
            .nonce
            .0
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Corrupt("invalid dek nonce length".into()))?;
        let mut dek_bytes =
            crypto::open(mek.as_bytes(), &nonce, &self.header.dek.wrapped.0, DEK_AAD)
                .map_err(|_| VaultError::Corrupt("dek wrap failed authentication".into()))?;
        let arr: [u8; KEY_LEN] = match dek_bytes.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => {
                dek_bytes.zeroize();
                return Err(VaultError::Corrupt("wrapped dek length invalid".into()));
            }
        };
        dek_bytes.zeroize();
        Ok(SecretKey::from_bytes(arr))
    }

    /// Decrypt the document (bound to the exact header via AAD).
    pub fn open_document(&self, keys: &Keys) -> Result<Vec<u8>, VaultError> {
        crypto::open(
            keys.dek.as_bytes(),
            &self.doc_nonce,
            &self.doc_ct,
            &canonical_header(&self.header)?,
        )
        .map_err(|_| VaultError::Corrupt("document failed authentication".into()))
    }

    /// Re-seal the document under the current header with a fresh nonce and
    /// replace the header bytes (used before every save).
    pub fn reseal_document(&mut self, document: &[u8], keys: &Keys) -> Result<(), VaultError> {
        self.doc_nonce = crypto::random_bytes()?;
        self.doc_ct = crypto::seal(
            keys.dek.as_bytes(),
            &self.doc_nonce,
            document,
            &canonical_header(&self.header)?,
        );
        Ok(())
    }
}

fn canonical_header(header: &Header) -> Result<Vec<u8>, VaultError> {
    serde_json::to_vec(header).map_err(|_| VaultError::Corrupt("header serialization".into()))
}

/// The public, secretless inputs of an unlock: which passphrase slots exist
/// and what KDF parameters each demands.
///
/// Split out from the derivation so the expensive Argon2 work can run **out**
/// of any lock (see `broker::Daemon::derive_human_proof`): the recipe is read
/// under the lock, derived without it, and the result applied under the lock.
/// A recipe carries no passphrase and no key material.
#[derive(Clone, Debug)]
pub struct KekRecipe {
    /// `(slot index, KDF params, salt)` for each passphrase slot, in order.
    entries: Vec<(usize, KdfParams, [u8; SALT_LEN])>,
}

impl KekRecipe {
    /// Read the recipe from `env`, failing closed on any unusable slot.
    ///
    /// Enforces the KDF bounds here — before a single byte is derived — so a
    /// tampered header cannot charge its absurd cost to the caller.
    pub fn of(env: &Envelope) -> Result<Self, VaultError> {
        let mut entries = Vec::new();
        for (index, slot) in env.header.slots.iter().enumerate() {
            if slot.kind != SlotType::Passphrase {
                continue;
            }
            slot.kdf.validate()?;
            let salt: [u8; SALT_LEN] = slot
                .salt
                .0
                .as_slice()
                .try_into()
                .map_err(|_| VaultError::Corrupt("invalid slot salt length".into()))?;
            entries.push((index, slot.kdf.clone(), salt));
        }
        if entries.is_empty() {
            return Err(VaultError::Auth);
        }
        Ok(Self { entries })
    }

    /// One derivation per passphrase slot. This is the expensive step and the
    /// only one that touches the passphrase.
    pub fn derive(&self, passphrase: &[u8]) -> Result<DerivedKeks, VaultError> {
        let mut derived = Vec::with_capacity(self.entries.len());
        for (index, kdf, salt) in &self.entries {
            derived.push((
                *index,
                crypto::derive_kek(passphrase, kdf.m_kib, kdf.t, kdf.p, salt)?,
            ));
        }
        Ok(DerivedKeks { derived })
    }

    /// Slots this recipe will derive against.
    pub fn slots(&self) -> usize {
        self.entries.len()
    }
}

/// KEKs derived from one passphrase against one header. Wiped on drop.
#[derive(Clone, Debug)]
pub struct DerivedKeks {
    derived: Vec<(usize, SecretKey)>,
}

impl DerivedKeks {
    fn iter(&self) -> impl Iterator<Item = (usize, &SecretKey)> {
        self.derived.iter().map(|(i, k)| (*i, k))
    }
}

fn mek_aad(id: &str) -> Vec<u8> {
    format!("{MEK_AAD_PREFIX}{id}").into_bytes()
}

pub(crate) fn hex_id() -> Result<String, VaultError> {
    let b = crypto::random_bytes::<8>()?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass() -> &'static [u8] {
        b"correct horse battery"
    }

    fn fresh(created_at: OffsetDateTime) -> Envelope {
        Envelope::create(pass(), b"{\"v\":1}", created_at).unwrap()
    }

    fn now() -> OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    #[test]
    fn create_roundtrip_unlocks_and_returns_document() {
        let env = fresh(now());
        let bytes = env.to_bytes();
        let parsed = Envelope::parse(&bytes).unwrap();
        let keys = parsed.unlock(pass()).unwrap();
        let doc = parsed.open_document(&keys).unwrap();
        assert_eq!(doc, b"{\"v\":1}");
    }

    #[test]
    fn wrong_passphrase_is_generic_auth_without_oracle() {
        let env = fresh(now());
        let bytes = env.to_bytes();
        let parsed = Envelope::parse(&bytes).unwrap();
        let e1 = parsed.unlock(b"wrong passphrase entirely").unwrap_err();
        let e2 = parsed.unlock(b"another wrong guess!").unwrap_err();
        assert!(matches!(e1, VaultError::Auth));
        assert!(matches!(e2, VaultError::Auth));
        assert_eq!(e1.to_string(), e2.to_string());
    }

    #[test]
    fn tampered_document_is_corrupt() {
        let mut env = fresh(now());
        let keys = env.unlock(pass()).unwrap();
        let mut bytes = {
            env.reseal_document(b"{\"v\":1}", &keys).unwrap();
            env.to_bytes()
        };
        *bytes.last_mut().unwrap() ^= 1; // flip inside doc ciphertext/tag
        let parsed = Envelope::parse(&bytes).unwrap();
        let unlocked = parsed.unlock(pass()).unwrap();
        assert!(matches!(
            parsed.open_document(&unlocked),
            Err(VaultError::Corrupt(_))
        ));
    }

    #[test]
    fn tampered_dek_wrap_is_corrupt() {
        let mut env = fresh(now());
        env.header.dek.wrapped.0[0] ^= 1;
        let bytes = env.to_bytes();
        let parsed = Envelope::parse(&bytes).unwrap();
        assert!(matches!(parsed.unlock(pass()), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn tampered_slot_is_generic_auth() {
        let mut env = fresh(now());
        env.header.slots[0].wrapped_mek.0[0] ^= 1;
        let bytes = env.to_bytes();
        let parsed = Envelope::parse(&bytes).unwrap();
        assert!(matches!(parsed.unlock(pass()), Err(VaultError::Auth)));
    }

    #[test]
    fn truncated_file_fails_closed() {
        let bytes = fresh(now()).to_bytes();
        // Truncation below the structural minimum is rejected at parse...
        assert!(matches!(
            Envelope::parse(&bytes[..20]),
            Err(VaultError::Corrupt(_))
        ));
        // ...while a tail cut that still parses (the document has no length
        // prefix) must fail authentication at document open — never return
        // usable state. (unlock() itself only unwraps keys; the document is
        // authenticated separately, which is where Session::unlock lands.)
        let truncated = &bytes[..bytes.len() - 5];
        match Envelope::parse(truncated) {
            Err(VaultError::Corrupt(_)) => {}
            Ok(env) => {
                let keys = env.unlock(pass()).expect("key slots are intact");
                assert!(matches!(
                    env.open_document(&keys),
                    Err(VaultError::Corrupt(_))
                ));
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn bad_magic_is_corrupt() {
        let mut bytes = fresh(now()).to_bytes();
        bytes[0] = b'X';
        assert!(matches!(
            Envelope::parse(&bytes),
            Err(VaultError::Corrupt(_))
        ));
    }

    #[test]
    fn future_version_is_rejected() {
        let mut bytes = fresh(now()).to_bytes();
        bytes[6] = 2; // version field, little endian u32
        assert!(matches!(
            Envelope::parse(&bytes),
            Err(VaultError::Corrupt(_))
        ));
    }

    #[test]
    fn unknown_slot_type_survives_roundtrip() {
        let mut env = fresh(now());
        env.header.slots.push(Slot {
            id: "future0001".into(),
            kind: SlotType::Other("futuretype".into()),
            kdf: KdfParams::argon2id_defaults(),
            salt: B64(Zeroizing::new(vec![0u8; SALT_LEN])),
            nonce: B64(Zeroizing::new(vec![0u8; NONCE_LEN])),
            wrapped_mek: B64(Zeroizing::new(vec![0u8; KEY_LEN + TAG_LEN])),
        });
        let parsed = Envelope::parse(&env.to_bytes()).unwrap();
        assert!(
            parsed
                .header
                .slots
                .iter()
                .any(|s| s.kind == SlotType::Other("futuretype".into()))
        );
        // The known passphrase slot still unlocks.
        assert!(parsed.unlock(pass()).is_ok());
    }

    #[test]
    fn insecure_kdf_params_are_rejected() {
        let mut env = fresh(now());
        env.header.slots[0].kdf.m_kib = 8192; // below the 19456 KiB minimum
        let parsed = Envelope::parse(&env.to_bytes()).unwrap();
        assert!(matches!(
            parsed.unlock(pass()),
            Err(VaultError::InsecureParams)
        ));
    }

    #[test]
    fn header_has_one_passphrase_slot_with_argon2id() {
        let env = fresh(now());
        assert_eq!(env.header.slots.len(), 1);
        assert_eq!(env.header.slots[0].kind, SlotType::Passphrase);
        assert_eq!(env.header.slots[0].kdf.algo, ARGON2ID);
    }

    #[test]
    fn every_slot_wraps_the_mek_and_dek_wrap_is_slot_independent() {
        // Hierarchy under contract: passphrase → KEK → unwrap MEK → unwrap
        // DEK → document. Each slot wraps the MEK; the DEK wrap lives
        // separately in the header and is untouched by slot changes.
        let mut env = fresh(now());
        let keys = env.unlock(pass()).unwrap();

        // Add a second passphrase slot wrapping the SAME MEK under a second
        // passphrase.
        let pass_b: &[u8] = b"another good passphrase";
        let salt = crypto::random_bytes::<SALT_LEN>().unwrap();
        let nonce = crypto::random_bytes::<NONCE_LEN>().unwrap();
        let kek = crypto::derive_kek(pass_b, 65536, 3, 4, &salt).unwrap();
        let wrapped_mek = crypto::seal(
            kek.as_bytes(),
            &nonce,
            keys.mek.as_bytes(),
            &mek_aad("slot-b"),
        );
        env.header.slots.push(Slot {
            id: "slot-b".into(),
            kind: SlotType::Passphrase,
            kdf: KdfParams::argon2id_defaults(),
            salt: B64(Zeroizing::new(salt.to_vec())),
            nonce: B64(Zeroizing::new(nonce.to_vec())),
            wrapped_mek: B64(Zeroizing::new(wrapped_mek)),
        });
        let dek_wrap_before = env.header.dek.clone();
        // The document is sealed under the exact header bytes (AAD); any
        // header change — including adding a slot — is re-sealed by the
        // save path, as Session::save does.
        env.reseal_document(b"{\"v\":1}", &keys).unwrap();

        let parsed = Envelope::parse(&env.to_bytes()).unwrap();
        assert_eq!(parsed.header.dek.wrapped.0, dek_wrap_before.wrapped.0);
        assert_eq!(parsed.header.dek.nonce.0, dek_wrap_before.nonce.0);
        let keys_a = parsed.unlock(pass()).unwrap();
        let keys_b = parsed.unlock(pass_b).unwrap();
        assert_eq!(
            parsed.open_document(&keys_a).unwrap(),
            parsed.open_document(&keys_b).unwrap()
        );
    }

    #[test]
    fn absurd_kdf_params_are_rejected() {
        // A tampered header must not be able to request unreasonable memory,
        // iterations or lanes (OOM / DoS): maxima apply above the minima.
        let mutators: [fn(&mut KdfParams); 3] = [
            |k| k.m_kib = MAX_M_KIB + 1,
            |k| k.t = MAX_T + 1,
            |k| k.p = MAX_P + 1,
        ];
        for mutate in mutators {
            let mut env = fresh(now());
            mutate(&mut env.header.slots[0].kdf);
            let parsed = Envelope::parse(&env.to_bytes()).unwrap();
            assert!(matches!(
                parsed.unlock(pass()),
                Err(VaultError::InsecureParams)
            ));
        }
    }

    #[test]
    fn oversized_header_is_rejected() {
        let mut bytes = fresh(now()).to_bytes();
        let hlen = (MAX_HEADER_LEN as u32) + 1;
        bytes[MAGIC.len() + 4..MAGIC.len() + 8].copy_from_slice(&hlen.to_le_bytes());
        assert!(matches!(
            Envelope::parse(&bytes),
            Err(VaultError::Corrupt(_))
        ));
    }
}

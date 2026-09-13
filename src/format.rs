//! Formato file `.pwdv` v1: header fisso di 130 byte seguito da ciphertext + tag.

use crate::error::VaultError;

pub const MAGIC: [u8; 4] = *b"PWDV";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 130;

pub(crate) const KDF_ARGON2ID: u8 = 1;
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const WRAPPED_DEK_LEN: usize = 48;
const TAG_LEN: usize = 16;
/// Anche un plaintext vuoto produce almeno il tag Poly1305.
const MIN_FILE_LEN: usize = HEADER_LEN + TAG_LEN;

const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 4;
const OFF_KDF_ID: usize = 5;
pub(crate) const OFF_M_COST: usize = 6;
const OFF_T_COST: usize = 10;
const OFF_P_COST: usize = 14;
const OFF_SALT: usize = 18;
pub(crate) const OFF_DEK_NONCE: usize = 34;
const OFF_WRAPPED_DEK: usize = 58;
pub(crate) const OFF_VAULT_NONCE: usize = 106;

// Il layout è contiguo e copre esattamente HEADER_LEN: verificato a compile time.
const _: () = {
    assert!(OFF_VERSION == OFF_MAGIC + MAGIC.len());
    assert!(OFF_KDF_ID == OFF_VERSION + 1);
    assert!(OFF_M_COST == OFF_KDF_ID + 1);
    assert!(OFF_T_COST == OFF_M_COST + 4);
    assert!(OFF_P_COST == OFF_T_COST + 4);
    assert!(OFF_SALT == OFF_P_COST + 4);
    assert!(OFF_DEK_NONCE == OFF_SALT + SALT_LEN);
    assert!(OFF_WRAPPED_DEK == OFF_DEK_NONCE + NONCE_LEN);
    assert!(OFF_VAULT_NONCE == OFF_WRAPPED_DEK + WRAPPED_DEK_LEN);
    assert!(HEADER_LEN == OFF_VAULT_NONCE + NONCE_LEN);
};

/// Parametri Argon2id, salvati in chiaro nell'header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memoria in KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

/// Header v1. Il magic non è un campo: è sempre `MAGIC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub kdf_id: u8,
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub dek_nonce: [u8; NONCE_LEN],
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    pub vault_nonce: [u8; NONCE_LEN],
}

impl Header {
    /// Separa header e ciphertext. Valida magic, version, kdf_id e lunghezza
    /// minima; non va mai in panic su input arbitrario.
    pub fn parse(input: &[u8]) -> Result<(Header, &[u8]), VaultError> {
        let magic = input
            .get(OFF_MAGIC..OFF_MAGIC + MAGIC.len())
            .ok_or(VaultError::Truncated)?;
        if magic != MAGIC.as_slice() {
            return Err(VaultError::BadMagic);
        }

        let version = *input.get(OFF_VERSION).ok_or(VaultError::Truncated)?;
        if version != VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }

        if input.len() < MIN_FILE_LEN {
            return Err(VaultError::Truncated);
        }
        let header = input.get(..HEADER_LEN).ok_or(VaultError::Truncated)?;
        let ciphertext = input.get(HEADER_LEN..).ok_or(VaultError::Truncated)?;

        let kdf_id = *header.get(OFF_KDF_ID).ok_or(VaultError::Truncated)?;
        if kdf_id != KDF_ARGON2ID {
            return Err(VaultError::Kdf(format!("unsupported kdf_id {kdf_id}")));
        }

        let parsed = Header {
            version,
            kdf_id,
            kdf: KdfParams {
                m_cost: u32::from_le_bytes(field(header, OFF_M_COST)?),
                t_cost: u32::from_le_bytes(field(header, OFF_T_COST)?),
                p_cost: u32::from_le_bytes(field(header, OFF_P_COST)?),
            },
            salt: field(header, OFF_SALT)?,
            dek_nonce: field(header, OFF_DEK_NONCE)?,
            wrapped_dek: field(header, OFF_WRAPPED_DEK)?,
            vault_nonce: field(header, OFF_VAULT_NONCE)?,
        };
        Ok((parsed, ciphertext))
    }

    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        put(&mut out, OFF_MAGIC, &MAGIC);
        put(&mut out, OFF_VERSION, &[self.version]);
        put(&mut out, OFF_KDF_ID, &[self.kdf_id]);
        put(&mut out, OFF_M_COST, &self.kdf.m_cost.to_le_bytes());
        put(&mut out, OFF_T_COST, &self.kdf.t_cost.to_le_bytes());
        put(&mut out, OFF_P_COST, &self.kdf.p_cost.to_le_bytes());
        put(&mut out, OFF_SALT, &self.salt);
        put(&mut out, OFF_DEK_NONCE, &self.dek_nonce);
        put(&mut out, OFF_WRAPPED_DEK, &self.wrapped_dek);
        put(&mut out, OFF_VAULT_NONCE, &self.vault_nonce);
        out
    }
}

fn field<const N: usize>(buf: &[u8], off: usize) -> Result<[u8; N], VaultError> {
    buf.get(off..off + N)
        .and_then(|s| s.try_into().ok())
        .ok_or(VaultError::Truncated)
}

// Gli offset sono costanti verificate a compile time, quindi il range esiste sempre.
fn put(out: &mut [u8], off: usize, bytes: &[u8]) {
    if let Some(dst) = out.get_mut(off..off + bytes.len()) {
        dst.copy_from_slice(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            version: VERSION,
            kdf_id: KDF_ARGON2ID,
            kdf: KdfParams {
                m_cost: 0x0102_0304,
                t_cost: 0x0506_0708,
                p_cost: 0x090a_0b0c,
            },
            salt: [0x11; 16],
            dek_nonce: [0x22; 24],
            wrapped_dek: [0x33; 48],
            vault_nonce: [0x44; 24],
        }
    }

    fn sample_file() -> Vec<u8> {
        let mut file = sample().to_bytes().to_vec();
        file.extend_from_slice(&[0xee; TAG_LEN + 5]);
        file
    }

    #[test]
    fn layout_matches_spec_table() {
        let b = sample().to_bytes();
        assert_eq!(&b[0..4], b"PWDV");
        assert_eq!(b[4], 1);
        assert_eq!(b[5], 1);
        assert_eq!(&b[6..10], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&b[10..14], &[0x08, 0x07, 0x06, 0x05]);
        assert_eq!(&b[14..18], &[0x0c, 0x0b, 0x0a, 0x09]);
        assert_eq!(&b[18..34], &[0x11; 16]);
        assert_eq!(&b[34..58], &[0x22; 24]);
        assert_eq!(&b[58..106], &[0x33; 48]);
        assert_eq!(&b[106..130], &[0x44; 24]);
    }

    #[test]
    fn roundtrip_and_ciphertext_split() {
        let file = sample_file();
        let (h, ct) = Header::parse(&file).unwrap();
        assert_eq!(h, sample());
        assert_eq!(ct, &file[130..]);
    }

    #[test]
    fn default_kdf_params() {
        let p = KdfParams::default();
        assert_eq!((p.m_cost, p.t_cost, p.p_cost), (65536, 3, 4));
    }

    #[test]
    fn every_short_length_is_err() {
        let file = sample_file();
        for len in 0..MIN_FILE_LEN {
            assert!(Header::parse(&file[..len]).is_err(), "len {len}");
        }
        assert!(Header::parse(&file[..MIN_FILE_LEN]).is_ok());
    }

    #[test]
    fn bad_magic() {
        let mut file = sample_file();
        file[0] ^= 0x01;
        assert!(matches!(Header::parse(&file), Err(VaultError::BadMagic)));
    }

    #[test]
    fn bad_version() {
        let mut file = sample_file();
        file[4] = 2;
        assert!(matches!(
            Header::parse(&file),
            Err(VaultError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn bad_kdf_id() {
        let mut file = sample_file();
        file[5] = 2;
        assert!(matches!(Header::parse(&file), Err(VaultError::Kdf(_))));
    }
}

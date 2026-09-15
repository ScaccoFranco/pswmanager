//! Core crittografico: password → Argon2id → KEK; la KEK cifra la DEK; la DEK
//! cifra il vault. Il cambio password ri-cifra solo la DEK.

use std::io;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::VaultError;
use crate::format::{
    Header, KdfParams, HEADER_LEN, KDF_ARGON2ID, NONCE_LEN, OFF_DEK_NONCE, OFF_M_COST,
    OFF_VAULT_NONCE, VERSION, WRAPPED_DEK_LEN,
};
use crate::key::Key32;

const ARGON2_ALGORITHM: Algorithm = Algorithm::Argon2id;
const ARGON2_VERSION: Version = Version::V0x13;

/// Limiti superiori sui parametri KDF. Nel file sono in chiaro e vengono usati
/// prima di qualsiasi verifica: senza limiti un header manomesso può chiedere
/// ad Argon2 terabyte di memoria (abort del processo) o ore di calcolo.
const MAX_M_COST: u32 = 1 << 20; // KiB = 1 GiB
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 64;

/// AAD wrap/unwrap DEK: magic, version, kdf_id, parametri KDF, salt.
const DEK_AAD_LEN: usize = OFF_DEK_NONCE;
/// AAD vault: magic, version, kdf_id, vault_nonce.
const VAULT_AAD_LEN: usize = OFF_M_COST + (HEADER_LEN - OFF_VAULT_NONCE);
const _: () = assert!(DEK_AAD_LEN == 34 && VAULT_AAD_LEN == 30);

pub fn derive_kek(
    password: &[u8],
    salt: &[u8; 16],
    params: &KdfParams,
) -> Result<Key32, VaultError> {
    if params.m_cost > MAX_M_COST || params.t_cost > MAX_T_COST || params.p_cost > MAX_P_COST {
        return Err(VaultError::Kdf("KDF parameters above allowed limits".into()));
    }
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(ARGON2_ALGORITHM, ARGON2_VERSION, argon2_params);

    let mut kek = Zeroizing::new([0u8; 32]);
    hash_into(&argon2, password, salt, &mut *kek)?;
    Ok(Key32::from_bytes(*kek))
}

/// `hash_password_into` libera la matrice di Argon2 senza azzerarla, e dai
/// blocchi finali si ricalcola l'output: la allochiamo noi, azzerata al drop.
fn hash_into(
    argon2: &Argon2<'_>,
    password: &[u8],
    salt: &[u8],
    out: &mut [u8],
) -> Result<(), VaultError> {
    let mut memory = Zeroizing::new(vec![Block::default(); argon2.params().block_count()]);
    argon2
        .hash_password_into_with_memory(password, salt, out, memory.as_mut_slice())
        .map_err(|e| VaultError::Kdf(e.to_string()))
}

/// Chiave di un vault aperto: la DEK e i primi 106 byte dell'header (magic,
/// version, kdf_id, parametri KDF, salt, dek_nonce, wrapped_dek), che restano
/// uguali finché non cambia la password. Permette di ricifrare il vault con
/// [`reseal`] senza master password e senza Argon2.
/// Niente `Debug`/`Display`/`Clone`: contiene la DEK, azzerata al drop.
#[derive(ZeroizeOnDrop)]
pub struct VaultKey {
    dek: Key32,
    header: [u8; OFF_VAULT_NONCE],
}

impl VaultKey {
    fn new(dek: Key32, header: &[u8; HEADER_LEN]) -> Self {
        let mut prefix = [0u8; OFF_VAULT_NONCE];
        for (dst, src) in prefix.iter_mut().zip(header.iter()) {
            *dst = *src;
        }
        VaultKey {
            dek,
            header: prefix,
        }
    }

    /// Vero se `file` è stato scritto con questa chiave: stessi parametri KDF,
    /// salt e DEK cifrata. Un cambio password o un nuovo `seal` lo rendono falso.
    pub fn matches(&self, file: &[u8]) -> bool {
        file.get(..OFF_VAULT_NONCE) == Some(self.header.as_slice())
    }
}

pub fn seal(password: &[u8], plaintext: &[u8], params: KdfParams) -> Result<Vec<u8>, VaultError> {
    seal_with_key(password, plaintext, params).map(|(_, file)| file)
}

/// Come [`seal`], ma restituisce anche la chiave per ricifrare con [`reseal`].
pub fn seal_with_key(
    password: &[u8],
    plaintext: &[u8],
    params: KdfParams,
) -> Result<(VaultKey, Vec<u8>), VaultError> {
    let dek = Key32::random()?;
    let vault_nonce = random_array()?;
    let header = wrap_dek(password, &dek, params, vault_nonce)?;
    let file = assemble(&header, &dek, &vault_nonce, plaintext)?;
    Ok((VaultKey::new(dek, &header), file))
}

/// Ricifra il vault con la DEK già sbloccata: header invariato fino a
/// wrapped_dek, vault_nonce nuovo da `OsRng`. Nessuna derivazione.
pub fn reseal(key: &VaultKey, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let vault_nonce: [u8; NONCE_LEN] = random_array()?;
    let mut header = [0u8; HEADER_LEN];
    for (dst, src) in header
        .iter_mut()
        .zip(key.header.iter().chain(vault_nonce.iter()))
    {
        *dst = *src;
    }
    assemble(&header, &key.dek, &vault_nonce, plaintext)
}

/// `header ++ ciphertext`: il vault cifrato dalla DEK sotto l'AAD del vault.
fn assemble(
    header: &[u8; HEADER_LEN],
    dek: &Key32,
    vault_nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let ciphertext = encrypt(dek, vault_nonce, &vault_aad(header), plaintext)?;
    let mut file = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    file.extend_from_slice(header);
    file.extend_from_slice(&ciphertext);
    Ok(file)
}

pub fn open(password: &[u8], file: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    open_with_key(password, file).map(|(_, plaintext)| plaintext)
}

/// Come [`open`], ma restituisce anche la chiave per ricifrare con [`reseal`].
pub fn open_with_key(
    password: &[u8],
    file: &[u8],
) -> Result<(VaultKey, Zeroizing<Vec<u8>>), VaultError> {
    let (header, ciphertext) = Header::parse(file)?;
    let header_bytes = raw_header(file)?;
    let dek = unwrap_dek(password, &header, header_bytes)?;
    let plaintext = decrypt(&dek, &header.vault_nonce, &vault_aad(header_bytes), ciphertext)?;
    Ok((VaultKey::new(dek, header_bytes), plaintext))
}

pub fn change_master(
    old: &[u8],
    new: &[u8],
    file: &[u8],
    params: KdfParams,
) -> Result<Vec<u8>, VaultError> {
    let (header, ciphertext) = Header::parse(file)?;
    let header_bytes = raw_header(file)?;
    let dek = unwrap_dek(old, &header, header_bytes)?;
    // Verifica anche il tag del vault: un ciphertext corrotto non va
    // ri-autorizzato sotto una nuova password.
    decrypt(&dek, &header.vault_nonce, &vault_aad(header_bytes), ciphertext)?;

    let new_header = wrap_dek(new, &dek, params, header.vault_nonce)?;
    let mut out = Vec::with_capacity(file.len());
    out.extend_from_slice(&new_header);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// Header nuovo con salt e dek_nonce freschi e la DEK cifrata dalla KEK di `password`.
fn wrap_dek(
    password: &[u8],
    dek: &Key32,
    params: KdfParams,
    vault_nonce: [u8; NONCE_LEN],
) -> Result<[u8; HEADER_LEN], VaultError> {
    let mut header = Header {
        version: VERSION,
        kdf_id: KDF_ARGON2ID,
        kdf: params,
        salt: random_array()?,
        dek_nonce: random_array()?,
        wrapped_dek: [0u8; WRAPPED_DEK_LEN],
        vault_nonce,
    };
    let kek = derive_kek(password, &header.salt, &header.kdf)?;
    // L'AAD copre header[0..34], che non include wrapped_dek: si può calcolare prima.
    let aad = dek_aad(&header.to_bytes());
    let wrapped = encrypt(&kek, &header.dek_nonce, &aad, dek.as_bytes())?;
    header.wrapped_dek = wrapped.try_into().map_err(|_| encryption_failed())?;
    Ok(header.to_bytes())
}

/// Deriva la KEK dai parametri del file e decifra la DEK.
fn unwrap_dek(
    password: &[u8],
    header: &Header,
    header_bytes: &[u8; HEADER_LEN],
) -> Result<Key32, VaultError> {
    // Parametri KDF e salt non sono ancora autenticati: se vengono rifiutati il
    // file è manomesso o corrotto, e deve essere indistinguibile da un tag errato.
    let kek = derive_kek(password, &header.salt, &header.kdf)
        .map_err(|_| VaultError::AuthFailed)?;
    let dek = decrypt(&kek, &header.dek_nonce, &dek_aad(header_bytes), &header.wrapped_dek)?;
    let dek: &[u8; 32] = dek.as_slice().try_into().map_err(|_| VaultError::AuthFailed)?;
    Ok(Key32::from_bytes(*dek))
}

/// I 130 byte di header così come sono nel file: le AAD si calcolano su questi,
/// non su una ricostruzione.
fn raw_header(file: &[u8]) -> Result<&[u8; HEADER_LEN], VaultError> {
    file.first_chunk().ok_or(VaultError::Truncated)
}

/// AAD di wrap/unwrap della DEK: `header[0..34]`.
fn dek_aad(header: &[u8; HEADER_LEN]) -> [u8; DEK_AAD_LEN] {
    let mut aad = [0u8; DEK_AAD_LEN];
    for (dst, src) in aad.iter_mut().zip(header.iter()) {
        *dst = *src;
    }
    aad
}

/// AAD del vault: `header[0..6] ++ header[106..130]`. Unica fonte per seal e open.
/// Esclude parametri KDF e salt, così il cambio password non tocca il ciphertext:
/// sono comunque autenticati dall'unwrap della DEK.
fn vault_aad(header: &[u8; HEADER_LEN]) -> [u8; VAULT_AAD_LEN] {
    let prefix = header.iter().take(OFF_M_COST);
    let suffix = header.iter().skip(OFF_VAULT_NONCE);
    let mut aad = [0u8; VAULT_AAD_LEN];
    for (dst, src) in aad.iter_mut().zip(prefix.chain(suffix)) {
        *dst = *src;
    }
    aad
}

fn encrypt(
    key: &Key32,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    XChaCha20Poly1305::new(key.as_bytes().into())
        .encrypt(nonce.into(), Payload { msg: plaintext, aad })
        .map_err(|_| encryption_failed())
}

/// Decifra in place su un buffer già `Zeroizing`: il plaintext non esiste mai fuori.
fn decrypt(
    key: &Key32,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    XChaCha20Poly1305::new(key.as_bytes().into())
        .decrypt_in_place(nonce.into(), aad, &mut *buf)
        .map_err(|_| VaultError::AuthFailed)?;
    Ok(buf)
}

/// XChaCha20-Poly1305 fallisce in cifratura solo con input oltre ~256 GiB.
fn encryption_failed() -> VaultError {
    VaultError::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        "input too large to encrypt",
    ))
}

fn random_array<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut out = [0u8; N];
    OsRng
        .try_fill_bytes(&mut out)
        .map_err(|e| VaultError::Io(e.into()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{AssociatedData, ParamsBuilder};

    const FAST: KdfParams = KdfParams {
        m_cost: 8192,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn aad_ranges_match_spec() {
        let header: [u8; HEADER_LEN] = std::array::from_fn(|i| i as u8);
        assert_eq!(dek_aad(&header).as_slice(), &header[0..34]);
        assert_eq!(
            vault_aad(&header).to_vec(),
            [&header[0..6], &header[106..130]].concat()
        );
    }

    /// RFC 9106 §5.3. derive_kek non accetta secret né associated data, quindi il
    /// vettore verifica la configurazione (Argon2id, v0x13) e `hash_into`.
    #[test]
    fn argon2id_rfc9106_vector() {
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(AssociatedData::new(&[0x04; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let secret = [0x03; 8];
        let argon2 =
            Argon2::new_with_secret(&secret, ARGON2_ALGORITHM, ARGON2_VERSION, params).unwrap();
        let mut tag = [0u8; 32];
        hash_into(&argon2, &[0x01; 32], &[0x02; 16], &mut tag).unwrap();
        let expected = [
            0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
            0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
            0x6b, 0x01, 0xe6, 0x59,
        ];
        assert_eq!(tag, expected);
    }

    #[test]
    fn seal_open_roundtrip() {
        for plaintext in [&b""[..], b"x", &[0xab; 4096]] {
            let file = seal(b"pw", plaintext, FAST).unwrap();
            assert_eq!(file.len(), HEADER_LEN + plaintext.len() + 16);
            assert_eq!(open(b"pw", &file).unwrap().as_slice(), plaintext);
        }
    }

    #[test]
    fn wrong_password_is_auth_failed() {
        let file = seal(b"pw", b"secret", FAST).unwrap();
        assert!(matches!(open(b"pW", &file), Err(VaultError::AuthFailed)));
    }

    #[test]
    fn change_master_rewraps_dek_only() {
        let file = seal(b"old", b"secret", FAST).unwrap();
        let changed = change_master(b"old", b"new", &file, FAST).unwrap();

        assert_eq!(&changed[106..], &file[106..]);
        assert_ne!(&changed[18..34], &file[18..34], "salt");
        assert_ne!(&changed[34..58], &file[34..58], "dek_nonce");
        assert_eq!(open(b"new", &changed).unwrap().as_slice(), b"secret");
        assert!(matches!(open(b"old", &changed), Err(VaultError::AuthFailed)));
    }

    #[test]
    fn change_master_rejects_corrupted_vault() {
        let mut file = seal(b"old", b"secret", FAST).unwrap();
        *file.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            change_master(b"old", b"new", &file, FAST),
            Err(VaultError::AuthFailed)
        ));
    }

    /// Parametri fuori limite o rifiutati da Argon2 → AuthFailed, senza eseguire
    /// Argon2 (m_cost = u32::MAX chiederebbe 4 TiB).
    #[test]
    fn hostile_kdf_params_are_auth_failed() {
        let file = seal(b"pw", b"secret", FAST).unwrap();
        for (offset, value) in [(6, u32::MAX), (10, u32::MAX), (14, u32::MAX), (10, 0), (14, 0)] {
            let mut bad = file.clone();
            bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(
                matches!(open(b"pw", &bad), Err(VaultError::AuthFailed)),
                "offset {offset} value {value}"
            );
        }
    }

    #[test]
    fn seal_rejects_params_above_limits() {
        let params = KdfParams {
            m_cost: MAX_M_COST + 1,
            ..FAST
        };
        assert!(matches!(seal(b"pw", b"x", params), Err(VaultError::Kdf(_))));
    }

    #[test]
    fn reseal_keeps_key_header_and_draws_a_fresh_nonce() {
        let (key, file) = seal_with_key(b"pw", b"first", FAST).unwrap();
        let a = reseal(&key, b"second").unwrap();
        let b = reseal(&key, b"second").unwrap();

        assert_eq!(&a[..106], &file[..106]);
        assert_eq!(&b[..106], &file[..106]);
        assert_ne!(&a[106..130], &file[106..130]);
        assert_ne!(&a[106..130], &b[106..130]);
        assert_ne!(&a[130..], &b[130..]);
        assert_eq!(open(b"pw", &a).unwrap().as_slice(), b"second");
        assert!(key.matches(&a) && key.matches(&file));
    }

    #[test]
    fn key_from_open_reseals_under_the_same_password() {
        let file = seal(b"pw", b"secret", FAST).unwrap();
        let (key, plaintext) = open_with_key(b"pw", &file).unwrap();
        assert_eq!(plaintext.as_slice(), b"secret");

        let resealed = reseal(&key, b"updated").unwrap();
        assert_eq!(open(b"pw", &resealed).unwrap().as_slice(), b"updated");
        assert!(matches!(open(b"other", &resealed), Err(VaultError::AuthFailed)));
    }

    #[test]
    fn resealed_file_detects_tampering() {
        let (key, _) = seal_with_key(b"pw", b"secret", FAST).unwrap();
        let file = reseal(&key, b"secret").unwrap();
        for offset in [0, 4, 5, 8, 20, 40, 80, 110, 129, 130, file.len() - 1] {
            let mut bad = file.clone();
            bad[offset] ^= 0x01;
            assert!(open(b"pw", &bad).is_err(), "offset {offset}");
        }
    }

    #[test]
    fn key_does_not_match_after_password_change_or_truncation() {
        let (key, file) = seal_with_key(b"old", b"secret", FAST).unwrap();
        let changed = change_master(b"old", b"new", &file, FAST).unwrap();
        assert!(!key.matches(&changed));
        assert!(!key.matches(&file[..50]));
        assert!(!key.matches(&[]));
    }
}

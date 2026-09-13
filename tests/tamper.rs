//! Test di sicurezza sul formato `.pwdv`. Gli offset sono scritti a mano dalla
//! tabella di CLAUDE.md, non presi dalle costanti del crate: un errore di layout
//! nell'implementazione deve far fallire i test, non propagarsi in essi.

use std::ops::Range;
use std::panic::catch_unwind;

use pwdv::crypto::{change_master, open, seal};
use pwdv::error::VaultError;
use pwdv::format::KdfParams;

/// Parametri ridotti per tenere bassi i tempi. Solo nei test.
const FAST: KdfParams = KdfParams {
    m_cost: 8192,
    t_cost: 1,
    p_cost: 1,
};

const PW: &[u8] = b"correct horse battery staple";
const PLAINTEXT: &[u8] = br#"{"version":1,"entries":[{"name":"mail","password":"hunter2"}]}"#;

fn flip(file: &[u8], byte: usize, bit: u8) -> Vec<u8> {
    let mut out = file.to_vec();
    out[byte] ^= 1 << bit;
    out
}

/// Tutti i campi autenticati che seguono magic/version/kdf_id.
fn tamperable_fields(file_len: usize) -> Vec<(&'static str, Range<usize>)> {
    let tag = file_len - 16;
    vec![
        ("m_cost", 6..10),
        ("t_cost", 10..14),
        ("p_cost", 14..18),
        ("salt", 18..34),
        ("dek_nonce", 34..58),
        ("wrapped_dek", 58..106),
        ("vault_nonce", 106..130),
        ("ciphertext", 130..tag),
        ("tag", tag..file_len),
    ]
}

/// Flippa un bit nel primo byte, in quello centrale e nell'ultimo del campo:
/// ogni variante deve dare AuthFailed. Sui parametri KDF (u32 LE) il bit 1 del
/// primo byte produce valori ancora validi, quindi Argon2 gira e fallisce il
/// tag; gli altri due producono valori enormi, respinti prima di Argon2.
fn assert_tamper_rejected(file: &[u8], name: &str, range: Range<usize>) {
    let targets = [
        (range.start, 1),
        (range.start + range.len() / 2, 4),
        (range.end - 1, 7),
    ];
    for (byte, bit) in targets {
        let result = open(PW, &flip(file, byte, bit)).map(drop);
        assert!(
            matches!(result, Err(VaultError::AuthFailed)),
            "{name}: byte {byte} bit {bit} -> {result:?}"
        );
    }
}

#[test]
fn roundtrip() {
    let large: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    for plaintext in [&b""[..], b"x", PLAINTEXT, &large] {
        let file = seal(PW, plaintext, FAST).unwrap();

        assert_eq!(file.len(), 130 + plaintext.len() + 16);
        assert_eq!(&file[0..6], b"PWDV\x01\x01");
        assert_eq!(
            &file[6..18],
            &[0x00, 0x20, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0],
            "parametri KDF in chiaro, u32 LE"
        );
        assert_eq!(open(PW, &file).unwrap().as_slice(), plaintext);
    }
}

#[test]
fn roundtrip_with_default_params() {
    let file = seal(PW, PLAINTEXT, KdfParams::default()).unwrap();
    assert_eq!(
        &file[6..18],
        &[0x00, 0x00, 0x01, 0x00, 3, 0, 0, 0, 4, 0, 0, 0],
        "m_cost 65536, t_cost 3, p_cost 4"
    );
    assert_eq!(open(PW, &file).unwrap().as_slice(), PLAINTEXT);
}

#[test]
fn plaintext_does_not_appear_in_file() {
    let file = seal(PW, PLAINTEXT, FAST).unwrap();
    assert!(!file.windows(PLAINTEXT.len()).any(|w| w == PLAINTEXT));
    assert!(!file.windows(7).any(|w| w == b"hunter2"));
}

#[test]
fn wrong_password_is_auth_failed() {
    let file = seal(PW, PLAINTEXT, FAST).unwrap();
    let mut one_bit_off = PW.to_vec();
    one_bit_off[0] ^= 0x01;
    let mut extended = PW.to_vec();
    extended.push(b'!');

    for wrong in [&b""[..], &one_bit_off, &PW[..PW.len() - 1], &extended] {
        let result = open(wrong, &file).map(drop);
        assert!(matches!(result, Err(VaultError::AuthFailed)), "{result:?}");
    }
    assert!(open(PW, &file).is_ok());
}

#[test]
fn tampering_any_authenticated_field_is_auth_failed() {
    let file = seal(PW, PLAINTEXT, FAST).unwrap();
    assert!(open(PW, &file).is_ok(), "il file intatto deve aprirsi");

    let fields = tamperable_fields(file.len());
    // La tabella copre senza buchi tutto ciò che segue kdf_id, fino a fine file.
    assert_eq!(fields[0].1.start, 6);
    assert_eq!(fields[fields.len() - 1].1.end, file.len());
    for pair in fields.windows(2) {
        assert_eq!(pair[0].1.end, pair[1].1.start, "{} / {}", pair[0].0, pair[1].0);
    }
    assert!(fields.iter().all(|(_, r)| r.len() >= 3));

    for (name, range) in fields {
        assert_tamper_rejected(&file, name, range);
    }
}

#[test]
fn altered_version_is_unsupported() {
    let file = seal(PW, PLAINTEXT, FAST).unwrap();
    for version in (0..=u8::MAX).filter(|&v| v != 1) {
        let mut bad = file.clone();
        bad[4] = version;
        let result = open(PW, &bad).map(drop);
        assert!(
            matches!(result, Err(VaultError::UnsupportedVersion(v)) if v == version),
            "version {version} -> {result:?}"
        );
    }
}

#[test]
fn altered_magic_is_bad_magic() {
    let file = seal(PW, PLAINTEXT, FAST).unwrap();
    for byte in 0..4 {
        for bit in 0..8 {
            let result = open(PW, &flip(&file, byte, bit)).map(drop);
            assert!(
                matches!(result, Err(VaultError::BadMagic)),
                "byte {byte} bit {bit} -> {result:?}"
            );
        }
    }
}

#[test]
fn truncated_file_is_err_never_panic() {
    let file = seal(PW, PLAINTEXT, FAST).unwrap();
    for len in 0..=130 {
        let prefix = &file[..len];
        let opened = catch_unwind(|| open(PW, prefix).map(drop));
        assert!(
            matches!(opened, Ok(Err(VaultError::Truncated))),
            "open, len {len}: {opened:?}"
        );
        let changed = catch_unwind(|| change_master(PW, b"new", prefix, FAST).map(drop));
        assert!(
            matches!(changed, Ok(Err(VaultError::Truncated))),
            "change_master, len {len}: {changed:?}"
        );
    }
}

#[test]
fn two_seals_share_no_salt_nonce_or_ciphertext() {
    let a = seal(PW, PLAINTEXT, FAST).unwrap();
    let b = seal(PW, PLAINTEXT, FAST).unwrap();

    assert_eq!(&a[0..18], &b[0..18], "stessi magic, version, kdf_id, parametri");
    for (name, range) in [
        ("salt", 18..34),
        ("dek_nonce", 34..58),
        ("wrapped_dek", 58..106),
        ("vault_nonce", 106..130),
        ("ciphertext", 130..a.len()),
    ] {
        assert_ne!(&a[range.clone()], &b[range], "{name}");
    }
    assert_eq!(open(PW, &a).unwrap().as_slice(), PLAINTEXT);
    assert_eq!(open(PW, &b).unwrap().as_slice(), PLAINTEXT);
}

#[test]
fn change_master_rewraps_without_touching_vault() {
    let file = seal(b"old", PLAINTEXT, FAST).unwrap();
    let stronger = KdfParams {
        m_cost: 16384,
        ..FAST
    };

    for params in [FAST, stronger] {
        let changed = change_master(b"old", b"new", &file, params).unwrap();

        assert_eq!(changed.len(), file.len());
        assert_eq!(&changed[106..], &file[106..], "vault_nonce e ciphertext intatti");
        assert_eq!(&changed[0..6], &file[0..6]);
        assert_eq!(&changed[6..10], &params.m_cost.to_le_bytes());
        assert_ne!(&changed[18..34], &file[18..34], "salt nuovo");
        assert_ne!(&changed[34..58], &file[34..58], "dek_nonce nuovo");

        assert_eq!(open(b"new", &changed).unwrap().as_slice(), PLAINTEXT);
        let old = open(b"old", &changed).map(drop);
        assert!(matches!(old, Err(VaultError::AuthFailed)), "{old:?}");
    }

    let wrong_old = change_master(b"wrong", b"new", &file, FAST).map(drop);
    assert!(matches!(wrong_old, Err(VaultError::AuthFailed)), "{wrong_old:?}");
}

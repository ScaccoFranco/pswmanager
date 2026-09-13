//! Lettura e scrittura del vault su disco. Ogni scrittura è atomica (file
//! temporaneo nella stessa directory, `sync_all`, `rename`) e il file
//! precedente viene conservato in `<vault>.bak`.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::VaultError;
use crate::format::KdfParams;
use crate::vault::{VaultData, DATA_VERSION};

pub fn load(path: &Path, password: &[u8]) -> Result<VaultData, VaultError> {
    let file = fs::read(path)?;
    let json = crypto::open(password, &file)?;
    let data: VaultData = serde_json::from_slice(&json).map_err(|_| VaultError::Malformed)?;
    // Uno schema sconosciuto verrebbe troncato al primo salvataggio: meglio rifiutarlo.
    if data.version != DATA_VERSION {
        return Err(VaultError::Malformed);
    }
    Ok(data)
}

pub fn save(path: &Path, password: &[u8], data: &VaultData) -> Result<(), VaultError> {
    save_with_params(path, password, data, KdfParams::default())
}

/// Cambia la master password ri-cifrando solo la DEK: il ciphertext del vault
/// resta identico.
pub fn change_password(path: &Path, old: &[u8], new: &[u8]) -> Result<(), VaultError> {
    change_password_with_params(path, old, new, KdfParams::default())
}

fn save_with_params(
    path: &Path,
    password: &[u8],
    data: &VaultData,
    params: KdfParams,
) -> Result<(), VaultError> {
    let json = to_json(data)?;
    let file = crypto::seal(password, &json, params)?;
    replace(path, &file)
}

fn change_password_with_params(
    path: &Path,
    old: &[u8],
    new: &[u8],
    params: KdfParams,
) -> Result<(), VaultError> {
    let current = fs::read(path)?;
    let file = crypto::change_master(old, new, &current, params)?;
    replace(path, &file)
}

/// Una `Vec` che cresce rialloca e libera i buffer vecchi senza azzerarli, e
/// qui conterrebbero password: prima si misura il JSON, poi lo si scrive in
/// un buffer della capacità esatta.
fn to_json(data: &VaultData) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, data).map_err(|e| VaultError::Io(e.into()))?;
    let mut json = Zeroizing::new(Vec::with_capacity(counter.0));
    serde_json::to_writer(&mut *json, data).map_err(|e| VaultError::Io(e.into()))?;
    Ok(json)
}

struct ByteCounter(usize);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Mette `bytes` al posto di `path`, salvando prima il contenuto attuale in `.bak`.
fn replace(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    match fs::read(path) {
        Ok(previous) => write_atomic(&backup_path(path), &previous)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    write_atomic(path, bytes)
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".bak");
    PathBuf::from(name)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let tmp = temp_path(path)?;
    let result = write_then_rename(&tmp, path, bytes);
    if result.is_err() {
        // Best effort: il temporaneo può non esistere o essere già stato rinominato.
        let _ = fs::remove_file(&tmp);
    }
    Ok(result?)
}

fn write_then_rename(tmp: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = create_private(tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(tmp, path)?;
    sync_parent_dir(path)
}

/// `.<nome>.<casuale>.tmp` nella stessa directory: `rename` resta atomico solo
/// all'interno dello stesso filesystem.
fn temp_path(path: &Path) -> Result<PathBuf, VaultError> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "vault path has no file name")
    })?;
    let mut suffix = [0u8; 8];
    OsRng
        .try_fill_bytes(&mut suffix)
        .map_err(|e| VaultError::Io(e.into()))?;

    let mut tmp = OsString::from(".");
    tmp.push(name);
    tmp.push(format!(".{:016x}.tmp", u64::from_le_bytes(suffix)));
    Ok(path.with_file_name(tmp))
}

fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Rende persistente il `rename` stesso, non solo il contenuto del file.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Entry;

    const FAST: KdfParams = KdfParams {
        m_cost: 8192,
        t_cost: 1,
        p_cost: 1,
    };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("pwdv-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }

        fn vault(&self) -> PathBuf {
            self.0.join("vault.pwdv")
        }

        fn listing(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(&self.0)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn data(passwords: &[&str]) -> VaultData {
        let mut data = VaultData::default();
        for (i, pw) in passwords.iter().enumerate() {
            data.entries.push(Entry::new(
                format!("entry{i}"),
                format!("user{i}"),
                pw.to_string(),
                (i % 2 == 0).then(|| format!("https://site{i}.example")),
                None,
            ));
        }
        data
    }

    fn passwords(data: &VaultData) -> Vec<&str> {
        data.entries.iter().map(|e| e.password.as_str()).collect()
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = TempDir::new("roundtrip");
        let original = data(&["plain", "qu\"ote\\slash", "unicodè ✓", ""]);
        save_with_params(&dir.vault(), b"pw", &original, FAST).unwrap();

        let loaded = load(&dir.vault(), b"pw").unwrap();
        assert_eq!(loaded.version, DATA_VERSION);
        assert_eq!(passwords(&loaded), passwords(&original));
        for (a, b) in loaded.entries.iter().zip(&original.entries) {
            assert_eq!((&a.name, &a.username, &a.url, &a.notes), (&b.name, &b.username, &b.url, &b.notes));
            assert_eq!((a.created, a.modified), (b.created, b.modified));
        }
    }

    #[test]
    fn save_keeps_previous_file_as_bak_and_no_temp_files() {
        let dir = TempDir::new("bak");
        let vault = dir.vault();
        save_with_params(&vault, b"pw", &data(&["first"]), FAST).unwrap();
        assert_eq!(dir.listing(), ["vault.pwdv"]);

        let first = fs::read(&vault).unwrap();
        save_with_params(&vault, b"pw", &data(&["second"]), FAST).unwrap();

        assert_eq!(dir.listing(), ["vault.pwdv", "vault.pwdv.bak"]);
        assert_eq!(fs::read(backup_path(&vault)).unwrap(), first);
        assert_eq!(passwords(&load(&backup_path(&vault), b"pw").unwrap()), ["first"]);
        assert_eq!(passwords(&load(&vault, b"pw").unwrap()), ["second"]);
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("perm");
        let vault = dir.vault();
        save_with_params(&vault, b"pw", &data(&["a"]), FAST).unwrap();
        save_with_params(&vault, b"pw", &data(&["b"]), FAST).unwrap();
        for path in [vault.clone(), backup_path(&vault)] {
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", path.display());
        }
    }

    #[test]
    fn load_with_wrong_password_is_auth_failed() {
        let dir = TempDir::new("wrongpw");
        save_with_params(&dir.vault(), b"pw", &data(&["a"]), FAST).unwrap();
        assert!(matches!(load(&dir.vault(), b"nope"), Err(VaultError::AuthFailed)));
    }

    #[test]
    fn load_missing_file_is_not_found() {
        let dir = TempDir::new("missing");
        assert!(matches!(
            load(&dir.vault(), b"pw"),
            Err(VaultError::Io(e)) if e.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn change_password_rewraps_and_backs_up() {
        let dir = TempDir::new("passwd");
        let vault = dir.vault();
        save_with_params(&vault, b"old", &data(&["secret"]), FAST).unwrap();
        let before = fs::read(&vault).unwrap();

        change_password_with_params(&vault, b"old", b"new", FAST).unwrap();
        let after = fs::read(&vault).unwrap();

        assert_eq!(&after[106..], &before[106..]);
        assert_eq!(fs::read(backup_path(&vault)).unwrap(), before);
        assert_eq!(passwords(&load(&vault, b"new").unwrap()), ["secret"]);
        assert!(matches!(load(&vault, b"old"), Err(VaultError::AuthFailed)));
        assert_eq!(dir.listing(), ["vault.pwdv", "vault.pwdv.bak"]);
    }

    #[test]
    fn change_password_with_wrong_old_leaves_files_untouched() {
        let dir = TempDir::new("passwd-wrong");
        let vault = dir.vault();
        save_with_params(&vault, b"old", &data(&["secret"]), FAST).unwrap();
        let before = fs::read(&vault).unwrap();

        let result = change_password_with_params(&vault, b"wrong", b"new", FAST);
        assert!(matches!(result, Err(VaultError::AuthFailed)));
        assert_eq!(fs::read(&vault).unwrap(), before);
        assert_eq!(dir.listing(), ["vault.pwdv"]);
    }

    #[test]
    fn load_rejects_malformed_json_and_unknown_schema() {
        let dir = TempDir::new("malformed");
        let vault = dir.vault();
        for plaintext in [&b"not json"[..], br#"{"version":2,"entries":[]}"#] {
            fs::write(&vault, crypto::seal(b"pw", plaintext, FAST).unwrap()).unwrap();
            assert!(matches!(load(&vault, b"pw"), Err(VaultError::Malformed)));
        }
    }

    #[test]
    fn to_json_never_reallocates() {
        let many: Vec<String> = (0..200).map(|i| format!("password-{i}-\"esc\"")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let json = to_json(&data(&refs)).unwrap();
        assert_eq!(json.capacity(), json.len());
    }
}

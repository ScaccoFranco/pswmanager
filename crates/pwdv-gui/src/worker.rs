//! Operazioni che derivano la chiave con Argon2id, eseguite fuori dal thread
//! della UI. Ognuna gira su un thread dedicato e consegna il risultato su un
//! canale: la UI lo interroga con `try_recv()` a ogni frame.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use pwdv_core::crypto::VaultKey;
use pwdv_core::error::VaultError;
use pwdv_core::store;
use pwdv_core::vault::VaultData;
use zeroize::Zeroizing;

/// Nome del thread worker, visibile in `top -H` e in `/proc/<pid>/task/*/comm`.
const THREAD_NAME: &str = "pwdv-kdf";

/// Vault aperto: la chiave per i salvataggi successivi e il contenuto.
pub type Outcome = Result<(VaultKey, VaultData), VaultError>;

/// Apre il vault in `path`. La password è spostata nel thread e azzerata lì,
/// subito dopo la derivazione.
pub fn spawn_unlock(path: PathBuf, password: Zeroizing<String>) -> Receiver<Outcome> {
    spawn(move || {
        let result = store::load_with_key(&path, password.as_bytes());
        drop(password);
        result
    })
}

/// Crea in `path` un vault vuoto e lo restituisce già aperto. La password è
/// spostata nel thread e azzerata lì, subito dopo la derivazione.
pub fn spawn_create(path: PathBuf, password: Zeroizing<String>) -> Receiver<Outcome> {
    spawn(move || {
        let data = VaultData::default();
        let result = store::create(&path, password.as_bytes(), &data);
        drop(password);
        result.map(|key| (key, data))
    })
}

fn spawn<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, VaultError> + Send + 'static,
) -> Receiver<Result<T, VaultError>> {
    let (tx, rx) = mpsc::channel();
    let spawn_failed = tx.clone();
    let spawned = thread::Builder::new()
        .name(THREAD_NAME.to_owned())
        .spawn(move || {
            // Se la UI ha già chiuso il canale il risultato torna indietro
            // nell'errore e viene droppato qui: chiave e voci si azzerano da sole.
            let _ = tx.send(job());
        });
    if let Err(e) = spawned {
        // Il job non è partito ed è già stato droppato, password compresa.
        let _ = spawn_failed.send(Err(VaultError::Io(e)));
    }
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("pwdv-gui-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }

        fn vault(&self) -> PathBuf {
            self.0.join("vault.pwdv")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn pw(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    #[test]
    fn job_runs_on_the_named_worker_thread() {
        let rx = spawn(|| {
            let current = thread::current();
            Ok((current.id(), current.name().map(str::to_owned)))
        });
        let (id, name) = rx.recv().unwrap().unwrap();
        assert_ne!(id, thread::current().id());
        assert_eq!(name.as_deref(), Some(THREAD_NAME));
    }

    #[test]
    fn create_then_unlock_with_default_kdf() {
        let dir = TempDir::new("roundtrip");
        let path = dir.vault();

        let (_, created) = spawn_create(path.clone(), pw("correct horse")).recv().unwrap().unwrap();
        assert!(created.entries.is_empty());

        let (_, opened) = spawn_unlock(path.clone(), pw("correct horse")).recv().unwrap().unwrap();
        assert!(opened.entries.is_empty());

        let wrong = spawn_unlock(path, pw("wrong")).recv().unwrap();
        assert!(matches!(wrong, Err(VaultError::AuthFailed)));
    }

    #[test]
    fn create_refuses_to_overwrite_an_existing_file() {
        let dir = TempDir::new("exists");
        let path = dir.vault();
        fs::write(&path, b"not a vault").unwrap();

        let result = spawn_create(path.clone(), pw("pw")).recv().unwrap();
        assert!(matches!(result, Err(VaultError::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists));
        assert_eq!(fs::read(&path).unwrap(), b"not a vault");
    }
}

//! Contenuto in chiaro del vault, serializzato in JSON prima della cifratura.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Versione dello schema JSON, distinta dalla versione del formato file.
pub const DATA_VERSION: u32 = 1;

/// Una voce del vault. Niente `Debug`/`Clone`: contiene la password.
/// Tutti i campi sono azzerati al drop.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// Secondi dall'epoch Unix.
    pub created: u64,
    /// Secondi dall'epoch Unix.
    pub modified: u64,
}

impl Entry {
    pub fn new(
        name: String,
        username: String,
        password: String,
        url: Option<String>,
        notes: Option<String>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Entry {
            name,
            username,
            password,
            url,
            notes,
            created: now,
            modified: now,
        }
    }
}

/// Niente `Debug`: contiene tutte le password.
#[derive(Serialize, Deserialize)]
pub struct VaultData {
    pub version: u32,
    pub entries: Vec<Entry>,
}

impl Default for VaultData {
    fn default() -> Self {
        VaultData {
            version: DATA_VERSION,
            entries: Vec::new(),
        }
    }
}

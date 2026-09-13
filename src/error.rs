use thiserror::Error;

/// Errori del vault. I messaggi non contengono mai segreti.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("not a pwdv file")]
    BadMagic,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u8),
    #[error("file truncated")]
    Truncated,
    /// Volutamente non distingue password errata da file manomesso.
    #[error("authentication failed: wrong password or corrupted file")]
    AuthFailed,
    /// Il vault si è aperto ma il contenuto non è JSON valido o ha una versione
    /// di schema sconosciuta. Non porta il messaggio di serde_json, che può
    /// citare frammenti del contenuto (cioè password).
    #[error("vault contents are malformed or of an unsupported version")]
    Malformed,
    #[error("key derivation error: {0}")]
    Kdf(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

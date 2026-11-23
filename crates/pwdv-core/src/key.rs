use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::VaultError;
use crate::hardening;

/// Chiave simmetrica di 32 byte (KEK o DEK). Azzerata al drop.
/// Niente `Debug`/`Display`/`Clone`/`Copy`: i byte escono solo da `as_bytes`.
///
/// I byte stanno nell'heap, a un indirizzo che non cambia quando la chiave
/// viene spostata, e quelle pagine sono bloccate in RAM prima di scriverci
/// (`hardening::lock_bytes`, ADR 0009). `zeroize` non implementa `Zeroize`
/// per `Box<[u8; 32]>`, quindi l'azzeramento è nel `Drop` qui sotto invece
/// che in `#[derive(ZeroizeOnDrop)]`.
pub struct Key32(Box<[u8; 32]>);

impl Key32 {
    /// Buffer a zero, già bloccato in RAM.
    pub(crate) fn locked_zeroed() -> Self {
        let key = Key32(Box::new([0u8; 32]));
        hardening::lock_bytes(key.0.as_slice());
        key
    }

    /// Chiave casuale da `OsRng`, scritta direttamente nel buffer finale.
    /// Un guasto dell'RNG di sistema diventa `Err`, non un panic.
    pub fn random() -> Result<Self, VaultError> {
        let mut key = Self::locked_zeroed();
        OsRng
            .try_fill_bytes(key.0.as_mut_slice())
            .map_err(|e| VaultError::Io(e.into()))?;
        Ok(key)
    }

    /// Copia `bytes` nel buffer bloccato. L'originale resta al chiamante,
    /// che deve azzerarlo (per esempio tenendolo in `Zeroizing`).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut key = Self::locked_zeroed();
        key.0.copy_from_slice(bytes);
        key
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Per scrivere la chiave direttamente nel buffer bloccato (Argon2id).
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl Drop for Key32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Key32 {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Una DEK rimasta a zero non verrebbe notata dai test di formato: salt e
    /// nonce diversi bastano a rendere diversi i file.
    #[test]
    fn random_keys_are_filled_and_distinct() {
        let a = Key32::random().unwrap();
        let b = Key32::random().unwrap();
        assert_ne!(a.as_bytes(), &[0u8; 32]);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::ZeroizeOnDrop;

use crate::error::VaultError;

/// Chiave simmetrica di 32 byte (KEK o DEK). Azzerata al drop.
/// Niente `Debug`/`Display`/`Clone`/`Copy`: i byte escono solo da `as_bytes`.
#[derive(ZeroizeOnDrop)]
pub struct Key32([u8; 32]);

impl Key32 {
    /// Chiave casuale da `OsRng`, scritta direttamente nel buffer finale.
    /// Un guasto dell'RNG di sistema diventa `Err`, non un panic.
    pub fn random() -> Result<Self, VaultError> {
        let mut key = Key32([0u8; 32]);
        OsRng
            .try_fill_bytes(&mut key.0)
            .map_err(|e| VaultError::Io(e.into()))?;
        Ok(key)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Key32(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

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

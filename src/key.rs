use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::ZeroizeOnDrop;

/// Chiave simmetrica di 32 byte (KEK o DEK). Azzerata al drop.
/// Niente `Debug`/`Display`/`Clone`/`Copy`: i byte escono solo da `as_bytes`.
#[derive(ZeroizeOnDrop)]
pub struct Key32([u8; 32]);

impl Key32 {
    /// Chiave casuale da `OsRng`, scritta direttamente nel buffer finale.
    pub fn random() -> Self {
        let mut key = Key32([0u8; 32]);
        OsRng.fill_bytes(&mut key.0);
        key
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Key32(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

//! Regole per le nuove master password (NIST SP 800-63B rev. 4, §3.1.1.2).
//!
//! Valgono solo quando una master password viene scelta (creazione del vault,
//! cambio password), mai allo sblocco: un vault creato prima di queste regole
//! deve restare apribile.

/// Lunghezza minima di una nuova master password, in caratteri Unicode.
/// SP 800-63B chiede almeno 15 caratteri per una password usata come unico
/// fattore di autenticazione, come la master password del vault.
pub const MIN_MASTER_CHARS: usize = 15;

/// Vero se `password` è abbastanza lunga per diventare la master password.
/// Conta i caratteri Unicode (code point), non i byte: "è" vale uno, come
/// chiede SP 800-63B. Nessuna regola di composizione, per scelta dello standard.
pub fn master_long_enough(password: &str) -> bool {
    password.chars().nth(MIN_MASTER_CHARS - 1).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_at_least_min_chars() {
        assert!(!master_long_enough(""));
        assert!(!master_long_enough(&"a".repeat(MIN_MASTER_CHARS - 1)));
        assert!(master_long_enough(&"a".repeat(MIN_MASTER_CHARS)));
        assert!(master_long_enough(&"a".repeat(MIN_MASTER_CHARS + 100)));
    }

    #[test]
    fn counts_unicode_chars_not_bytes() {
        // 14 caratteri da 2 byte: 28 byte, ma ancora troppo corta.
        assert!(!master_long_enough(&"è".repeat(MIN_MASTER_CHARS - 1)));
        assert!(master_long_enough(&"è".repeat(MIN_MASTER_CHARS)));
        // Spazi ammessi e contati: una frase va bene.
        assert!(master_long_enough("correct horse b"));
    }
}

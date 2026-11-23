//! Regole sulle master password (NIST SP 800-63B rev. 4, §3.1.1.2).
//!
//! La lunghezza minima vale solo quando una master password viene scelta
//! (creazione del vault, cambio password), mai allo sblocco: un vault creato
//! prima di queste regole deve restare apribile. La normalizzazione NFKC si
//! applica in `crypto` prima di Argon2id, vedi ADR 0005.

use unicode_normalization::{is_nfkc, UnicodeNormalization};
use zeroize::Zeroizing;

/// Massimo rapporto tra byte UTF-8 in uscita e in ingresso di NFKC, per un
/// singolo carattere. La composizione unisce caratteri e non allunga mai: il
/// limite vale anche per le stringhe. Ricavato dal test
/// `nfkc_expansion_bound_holds_for_every_char`, che prova ogni code point: il
/// caso peggiore è U+FDFA, 3 byte che diventano 33.
const MAX_NFKC_EXPANSION: usize = 11;

/// Forma NFKC di `password`, se è diversa dai byte ricevuti. `None` se i byte
/// non sono UTF-8 valido (si usano così come sono) o sono già in NFKC (nessuna
/// copia). Il risultato è deterministico: creazione e sblocco scelgono sempre
/// la stessa forma per la stessa password.
///
/// La capacità è riservata tutta prima di scrivere: una `String` che cresce
/// rialloca e libera il buffer vecchio senza azzerarlo. Restano i buffer
/// interni di `unicode-normalization`, liberati senza azzeramento.
pub(crate) fn nfkc(password: &[u8]) -> Option<Zeroizing<String>> {
    let text = std::str::from_utf8(password).ok()?;
    if is_nfkc(text) {
        return None;
    }
    let mut out = Zeroizing::new(String::new());
    out.try_reserve_exact(text.len().checked_mul(MAX_NFKC_EXPANSION)?)
        .ok()?;
    for c in text.nfkc() {
        // Irraggiungibile se MAX_NFKC_EXPANSION è corretto. Se non lo fosse,
        // meglio i byte originali (scelta comunque deterministica) che una
        // riallocazione che lascia copie della password in memoria.
        if out.len() + c.len_utf8() > out.capacity() {
            return None;
        }
        out.push(c);
    }
    Some(out)
}

/// Lunghezza minima di una nuova master password, in caratteri Unicode.
/// SP 800-63B chiede almeno 15 caratteri per una password usata come unico
/// fattore di autenticazione, come la master password del vault.
pub const MIN_MASTER_CHARS: usize = 15;

/// Password comuni di almeno 15 caratteri, minuscole, una per riga: da SecLists,
/// `xato-net-10-million-passwords-1000000.txt` (licenza MIT, vedi
/// `data/LICENSE-SecLists`). Le più corte sono già escluse dalla lunghezza minima.
const COMMON_PASSWORDS: &str = include_str!("../data/common-passwords.txt");

/// Parole legate al contesto (SP 800-63B: "the name of the service").
const CONTEXT_WORDS: [&[u8]; 1] = [b"pwdv"];

/// Perché una password non può diventare la master password. Nessuna variante
/// porta con sé la password o parti di essa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weakness {
    /// Meno di [`MIN_MASTER_CHARS`] caratteri.
    TooShort,
    /// Nell'elenco di password comuni o compromesse (senza distinzione tra
    /// maiuscole e minuscole).
    Common,
    /// Un blocco ripetuto: "aaaa…", "abcabc…", "passwordpassword".
    Repetitive,
    /// Caratteri consecutivi: "abcdef…", "987654…", "1234567890123…".
    Sequential,
    /// Contiene il nome del programma.
    ContextWord,
}

/// Controlla una password scelta come nuova master password (NIST SP 800-63B
/// rev. 4, §3.1.1.2): lunghezza minima, elenco di password comuni, ripetizioni,
/// sequenze, parole di contesto. Nessuna regola di composizione, per scelta
/// dello standard. Da non usare allo sblocco: i vault esistenti restano apribili.
///
/// I controlli dopo la lunghezza lavorano sulla forma NFKC, la stessa che
/// arriva ad Argon2id: "ｐａｓｓｗｏｒｄ" a larghezza piena vale "password".
pub fn check_new_master(password: &str) -> Result<(), Weakness> {
    if !long_enough(password) {
        return Err(Weakness::TooShort);
    }
    let normalized = nfkc(password.as_bytes());
    let text = normalized.as_ref().map_or(password, |n| n.as_str());
    if is_common(text) {
        Err(Weakness::Common)
    } else if is_repetitive(text) {
        Err(Weakness::Repetitive)
    } else if is_sequential(text) {
        Err(Weakness::Sequential)
    } else if has_context_word(text) {
        Err(Weakness::ContextWord)
    } else {
        Ok(())
    }
}

/// Conta i caratteri Unicode (code point), non i byte: "è" vale uno, come
/// chiede SP 800-63B.
fn long_enough(password: &str) -> bool {
    password.chars().nth(MIN_MASTER_CHARS - 1).is_some()
}

/// Confronto carattere per carattere, senza creare copie minuscole della password.
fn is_common(password: &str) -> bool {
    COMMON_PASSWORDS
        .lines()
        .any(|line| line.chars().eq(password.chars().flat_map(char::to_lowercase)))
}

/// Vero se la password è un blocco più corto ripetuto per intero almeno due volte.
fn is_repetitive(password: &str) -> bool {
    let len = password.chars().count();
    (1..=len / 2)
        .filter(|period| len.is_multiple_of(*period))
        .any(|period| {
            password
                .chars()
                .zip(password.chars().skip(period))
                .all(|(a, b)| a == b)
        })
}

/// Vero se ogni carattere segue il precedente di +1 o -1, sempre nello stesso
/// verso. Tra le cifre "9" → "0" vale +1 e "0" → "9" vale -1, come sulla tastiera.
fn is_sequential(password: &str) -> bool {
    let step = |(a, b): (char, char)| -> i64 {
        match (a, b) {
            ('9', '0') => 1,
            ('0', '9') => -1,
            _ => i64::from(u32::from(b)) - i64::from(u32::from(a)),
        }
    };
    let mut steps = password.chars().zip(password.chars().skip(1)).map(step);
    match steps.next() {
        Some(first) if first == 1 || first == -1 => steps.all(|s| s == first),
        _ => false,
    }
}

fn has_context_word(password: &str) -> bool {
    CONTEXT_WORDS.iter().any(|word| {
        password
            .as_bytes()
            .windows(word.len())
            .any(|window| window.eq_ignore_ascii_case(word))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_at_least_min_chars() {
        assert!(!long_enough(""));
        assert!(!long_enough(&"a".repeat(MIN_MASTER_CHARS - 1)));
        assert!(long_enough(&"a".repeat(MIN_MASTER_CHARS)));
        assert!(long_enough(&"a".repeat(MIN_MASTER_CHARS + 100)));
        assert_eq!(check_new_master("short"), Err(Weakness::TooShort));
    }

    #[test]
    fn counts_unicode_chars_not_bytes() {
        // 14 caratteri da 2 byte: 28 byte, ma ancora troppo corta.
        assert!(!long_enough(&"è".repeat(MIN_MASTER_CHARS - 1)));
        assert!(long_enough(&"è".repeat(MIN_MASTER_CHARS)));
        // Spazi ammessi e contati: una frase va bene.
        assert!(long_enough("correct horse b"));
    }

    #[test]
    fn good_passphrases_pass() {
        assert_eq!(check_new_master("vela rossa sul lago di sera"), Ok(()));
        assert_eq!(check_new_master("caff\u{e8} lungo e amaro"), Ok(()));
        assert_eq!(check_new_master("Tr0ttola-Lenta-42!"), Ok(()));
    }

    #[test]
    fn common_list_is_well_formed() {
        let lines: Vec<&str> = COMMON_PASSWORDS.lines().collect();
        assert!(lines.len() > 10_000);
        assert!(lines.iter().all(|l| long_enough(l)));
        assert!(lines
            .iter()
            .all(|l| l.bytes().all(|b| (0x20..0x7f).contains(&b) && !b.is_ascii_uppercase())));
    }

    #[test]
    fn rejects_common_passwords_ignoring_case_and_width() {
        // Voci presenti in data/common-passwords.txt.
        assert_eq!(check_new_master("1qaz2wsx3edc4rfv"), Err(Weakness::Common));
        assert_eq!(check_new_master("123456789QWERTY"), Err(Weakness::Common));
        // Cifre e lettere a larghezza piena: NFKC le riporta all'ASCII.
        assert_eq!(
            check_new_master("１２３４５６７８９ｑｗｅｒｔｙ"),
            Err(Weakness::Common)
        );
    }

    #[test]
    fn rejects_repetitions() {
        assert_eq!(check_new_master(&"x".repeat(20)), Err(Weakness::Repetitive));
        assert_eq!(check_new_master(&"xyz".repeat(6)), Err(Weakness::Repetitive));
        assert_eq!(check_new_master("trottolatrottola"), Err(Weakness::Repetitive));
        // Una ripetizione parziale non basta.
        assert_eq!(check_new_master("trottolatrottolaX"), Ok(()));
    }

    #[test]
    fn rejects_sequences() {
        // "abcdefghijklmnop" è già nell'elenco comune: si parte da "b".
        assert_eq!(check_new_master("bcdefghijklmnopq"), Err(Weakness::Sequential));
        assert_eq!(check_new_master("ponmlkjihgfedcba"), Err(Weakness::Sequential));
        assert_eq!(check_new_master("4567890123456789"), Err(Weakness::Sequential));
        assert_eq!(check_new_master("9876543210987654"), Err(Weakness::Sequential));
        // Verso che cambia: non è una sequenza.
        assert_eq!(check_new_master("abcdefgfedcbabcd"), Ok(()));
    }

    #[test]
    fn rejects_context_words() {
        assert_eq!(
            check_new_master("la mia PWDV di casa"),
            Err(Weakness::ContextWord)
        );
        assert_eq!(
            check_new_master("ｐｗｄｖ è la mia password"),
            Err(Weakness::ContextWord)
        );
    }

    #[test]
    fn length_is_checked_first() {
        // "pwdv" è corta: il motivo è la lunghezza, non la parola di contesto.
        assert_eq!(check_new_master("pwdv"), Err(Weakness::TooShort));
    }

    #[test]
    fn nfkc_leaves_ascii_and_invalid_utf8_alone() {
        assert!(nfkc(b"plain ascii password").is_none());
        assert!(nfkc(b"").is_none());
        assert!(nfkc(&[0xff, 0xfe, b'a']).is_none());
        // Già in forma composta (NFC = NFKC qui): nessuna copia.
        assert!(nfkc("caffè".as_bytes()).is_none());
    }

    #[test]
    fn nfkc_unifies_equivalent_spellings() {
        // "e" + accento combinante → "è" precomposto (U+00E8).
        let decomposed = nfkc("caffe\u{300}".as_bytes()).unwrap();
        assert_eq!(decomposed.as_str(), "caff\u{e8}");
        // Compatibilità: legatura "ﬁ" (U+FB01) → "fi", "Ａ" a larghezza piena → "A".
        assert_eq!(nfkc("\u{fb01}".as_bytes()).unwrap().as_str(), "fi");
        assert_eq!(nfkc("\u{ff21}".as_bytes()).unwrap().as_str(), "A");
    }

    #[test]
    fn nfkc_expansion_bound_holds_for_every_char() {
        let mut worst = (1usize, 1usize, '\0');
        for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let out: usize = std::iter::once(c).nfkc().map(char::len_utf8).sum();
            let inp = c.len_utf8();
            if out * worst.1 > worst.0 * inp {
                worst = (out, inp, c);
            }
        }
        let (out, inp, c) = worst;
        assert!(
            out <= inp * MAX_NFKC_EXPANSION,
            "U+{:04X}: {out} byte da {inp}",
            u32::from(c)
        );
        // Il limite è stretto: se le tabelle Unicode cambiano, va rivisto.
        assert!(
            out > inp * (MAX_NFKC_EXPANSION - 1),
            "U+{:04X}: {out}/{inp}",
            u32::from(c)
        );
    }
}

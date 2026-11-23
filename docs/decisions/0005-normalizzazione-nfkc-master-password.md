# 0005 — Normalizzazione NFKC della master password
- **Data**: 2026-11-23
- **Stato**: accettata

## Contesto
Lo stesso testo Unicode può avere sequenze di byte diverse: "è" precomposta (U+00E8)
oppure "e" + accento combinante (U+0065 U+0300); la legatura "ﬁ" contro "fi"; lettere a
larghezza piena. Sistemi operativi, tastiere e metodi di input diversi producono forme
diverse. Argon2id lavora sui byte: senza normalizzazione la stessa password digitata su
un altro sistema non apre il vault. Il problema diventa concreto con il target
multipiattaforma. NIST SP 800-63B raccomanda di applicare NFKC o NFKD prima dell'hash
(riferimento da verificare sul testo ufficiale).

## Decisione
- Nuova dipendenza `unicode-normalization` 0.1.26 (autorizzata esplicitamente), solo in `pwdv-core`.
- `policy::nfkc(&[u8])` restituisce la forma NFKC se i byte sono UTF-8 valido e non sono
  già in NFKC, altrimenti `None` (si usano i byte così come sono). Le password ASCII e
  quelle già in NFC senza caratteri di compatibilità non cambiano.
- **Password nuove** (`wrap_dek`: creazione, `seal`, cambio password): sempre NFKC.
- **Sblocco** (`unwrap_dek`): prima la forma NFKC; se è diversa dai byte digitati e non
  apre, secondo tentativo con i byte originali. Così i vault creati prima di questa
  decisione restano apribili.
- `derive_kek` resta sui byte grezzi: il vettore RFC 9106 continua a valere.
- Il buffer di uscita viene riservato tutto prima di scrivere (capacità = 11 × input,
  il caso peggiore misurato su tutti i code point: U+FDFA, 3 → 33 byte), così non
  rialloca lasciando copie non azzerate. Un test controlla il limite su ogni carattere.

## Alternative considerate
- **Nuova versione del formato** (header v2 = "password normalizzata"): più pulita a
  lungo termine, ma tocca formato e regole AAD, che sono vincoli non derogabili.
- **NFKC senza fallback**: più semplice, ma un vault esistente con una password non in
  NFKC diventerebbe illeggibile senza preavviso.
- **NFKD**: equivalente per l'uguaglianza; NFKC produce stringhe più corte e coincide con
  quello che la maggior parte delle tastiere genera già.
- **Normalizzare in CLI e GUI** invece che nel core: due punti da tenere allineati e
  nessuna garanzia per chi usa il core direttamente.

## Conseguenze
- La stessa password apre il vault da qualunque sistema o tastiera, se il vault è stato
  creato (o la password cambiata) dopo questa decisione.
- Una password sbagliata con caratteri non in NFKC costa due derivazioni Argon2id
  invece di una. L'errore resta `AuthFailed`, indistinguibile da un file manomesso.
- Un vault "legacy" con password non in NFKC si apre solo con la forma originale finché
  non si cambia la password (`pwdv passwd`); dopo, vale la forma normalizzata.
- Il fallback va mantenuto finché possono esistere vault legacy.
- `unicode-normalization` usa buffer interni che liberano la password senza azzerarla
  (README §9).
- La lunghezza minima (ADR 0004) si conta sui caratteri digitati, prima della
  normalizzazione: "e" + accento combinante vale 2.

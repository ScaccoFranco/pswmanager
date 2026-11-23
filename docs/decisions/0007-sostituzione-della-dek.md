# 0007 — Sostituzione esplicita della DEK (`pwdv rekey`)
- **Data**: 2026-11-23
- **Stato**: accettata

## Contesto
Per l'invariante dei due livelli di chiave (ADR 0002), `pwdv passwd` ricifra solo la DEK.
Chi possiede una copia vecchia del file e la password di allora ricava la DEK e, finché
questa non cambia, decifra anche il vault attuale. NIST SP 800-57 parte 1 prevede che
le chiavi abbiano una durata di validità e possano essere sostituite (da verificare il
paragrafo).

Analizzando il codice è emerso che la DEK **già cambia** a ogni salvataggio della CLI:
`store::save` (`pwdv add`, `pwdv rm`) passa da `crypto::seal`, che genera DEK, salt e
nonce nuovi. Non cambia dopo `passwd` né nei salvataggi della GUI (`save_with_key` →
`reseal`). La rotazione quindi esisteva, ma come effetto collaterale non documentato.

## Decisione
- Nuova funzione `store::rekey(path, password)`: `crypto::open` con la password attuale,
  poi `crypto::seal` sullo stesso plaintext, byte per byte, con i parametri KDF predefiniti.
  Scrittura con `replace`: atomica, il file precedente diventa `.bak`.
- Nuovo comando CLI `pwdv rekey`: chiede solo la master password attuale. Non usa
  `unlock()` per evitare una derivazione Argon2id in più.
- `passwd` resta un puro re-wrap: l'invariante di `CLAUDE.md` non cambia.
- Il `.bak` viene mantenuto: contiene la DEK precedente, ma cifrata con la password
  attuale, quindi non aiuta chi conosce solo la password vecchia.
- Nessuna modifica alla GUI in questo step.

## Alternative considerate
- **Far ruotare la DEK anche a `passwd`**: viola l'invariante "cambio password = solo
  re-wrap" e rende il cambio password più lento su vault grandi.
- **`rekey` che chiede anche una nuova password**: unisce due operazioni; tenerle
  separate rende ognuna più semplice da verificare e da testare.
- **Rotazione automatica periodica**: richiede di salvare uno stato (data dell'ultima
  rotazione) e fa riscrivere il file senza azione dell'utente.

## Conseguenze
- Procedura documentata per una password compromessa: `pwdv passwd`, poi `pwdv rekey`.
- Un test (`rekey_makes_an_old_copy_and_old_password_useless`) riproduce l'attacco:
  header vecchio con DEK vecchia + vault attuale si apre dopo `passwd` e non più dopo `rekey`.
- Una GUI aperta durante `rekey` riceve `Conflict` al salvataggio successivo e non
  sovrascrive il vault ricifrato.
- `rekey` aggiorna anche i parametri Argon2id di un vault vecchio ai valori predefiniti e
  normalizza in NFKC una password "legacy" (ADR 0005).
- La GUI non offre ancora né il cambio password né `rekey`.

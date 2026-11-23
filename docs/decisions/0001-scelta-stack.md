# 0001 — Scelta dello stack
- **Data**: 2026-11-23 (ricostruita a posteriori dal codice e dal README)
- **Stato**: accettata

## Contesto
Serve un password manager personale, locale, senza server né sincronizzazione, con una
CLI per script e terminale e una GUI per l'uso quotidiano. Il requisito dominante è la
sicurezza: niente crittografia fatta a mano, segreti azzerati in memoria, nessun panic su
input malformato.

## Decisione
- **Rust 2021**, workspace `cargo` con tre crate: `pwdv-core` (libreria), `pwdv-cli`
  (binario `pwdv`), `pwdv-gui` (binario `pwdv-gui`). Dipendenze in un solo verso verso il core.
- **Crittografia RustCrypto**: `argon2` 0.5, `chacha20poly1305` 0.10, `zeroize` 1,
  `rand` 0.8 (`OsRng`). Dettagli in [0002](0002-formato-file-e-due-livelli-di-chiave.md).
- **Archiviazione**: un unico file binario cifrato; contenuto in chiaro serializzato in
  JSON con `serde`/`serde_json`. Errori con `thiserror`.
- **CLI**: `clap` 4 (derive) e `rpassword` 7 (password solo da terminale, mai come argomenti).
- **GUI**: `eframe`/`egui` + `arboard`, vedi [0003](0003-gui-eframe-egui.md).
- **Nessuna dipendenza aggiuntiva** senza richiesta esplicita; nessuna libreria di rete.

## Alternative considerate
(da verificare — non documentate in origine)
- Linguaggi con GC (Go, Python): azzeramento della memoria poco controllabile.
- Database (SQLite/SQLCipher): eccessivo per poche centinaia di voci e aggiunge superficie d'attacco.
- Formati esistenti (KeePass KDBX): più complessi da implementare correttamente senza
  dipendenze di terze parti meno verificate.

## Conseguenze
- Il core è testabile da solo e non trascina dipendenze grafiche nella CLI.
- Un solo file da copiare per il backup; nessun accesso concorrente coordinato (vedi
  ARCHITECTURE, debito tecnico).
- Il target dichiarato è multipiattaforma, ma alcune parti sono oggi solo Unix/Linux
  (`0600`, sync della directory, `install.sh`, hint del clipboard).

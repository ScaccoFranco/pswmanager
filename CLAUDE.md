# pwdv — password manager cifrato (Rust)

## Scopo

Vault locale cifrato, CLI (`pwdv`) e GUI (`pwdv-gui`) sullo stesso file `.pwdv`.
Nessuna sincronizzazione, nessun server, nessuna rete. Per uso personale.

## Direzione

- Obiettivi attuali: generatore di password nella GUI; tema chiaro/scuro (senza persistenza su disco).
- Target: multipiattaforma (Linux, macOS, Windows). Oggi solo Linux è coperto: non introdurre nuove dipendenze da Unix senza `#[cfg]` e alternativa.
- Non-obiettivi: sincronizzazione, cloud, account, funzioni di rete, telemetria, recupero della master password.
- Priorità nei trade-off: sicurezza > correttezza > semplicità > UX > performance.

## Comandi

- Build: `cargo build --release` (in debug Argon2 è molto lento)
- Test: `cargo test --workspace`
- Lint: `cargo clippy --workspace --all-targets -- -D warnings` · format: `cargo fmt`
- Run: `cargo run --release -p pwdv-gui` · `cargo run --release -p pwdv-cli -- --help`
- Install (Linux): `./install.sh` / `./uninstall.sh`

## Struttura

```
crates/pwdv-core/   libreria: format, crypto, hardening, key, policy, vault, store, error (+ tests/tamper.rs, data/ = elenco password comuni)
crates/pwdv-cli/    binario `pwdv`: init, add, get, list, rm, passwd, rekey, gen
crates/pwdv-gui/    binario `pwdv-gui`: app, unlock, worker, main_view, security, window, theme
packaging/linux/    .desktop e icona per install.sh
docs/               ARCHITECTURE.md, CRYPTO-INVENTORY.md, decisions/ (ADR), audit/
.github/workflows/  CI (fmt, clippy, test, cargo audit)
prompts/            prompt di lavoro (ignorato da git)
```

## Stack

- Rust 2021, `cargo` workspace singolo
- `argon2` 0.5 (feature `zeroize`), `chacha20poly1305` 0.10, `zeroize` 1 (feature `zeroize_derive`), `rand` 0.8, `thiserror` 1
- Vault store e CLI: `serde` 1 (feature `derive`), `serde_json` 1, `clap` 4 (feature `derive`), `rpassword` 7
- Password: `unicode-normalization` 0.1.26 (NFKC, solo in `pwdv-core`)
- Processo: `libc` 0.2 (solo `cfg(unix)`, in `pwdv-core::hardening`: core dump disattivati e `mlock` dei segreti, ADR 0008 e 0009)
- GUI: `eframe` 0.36 (senza `persistence`), `arboard` 3.6 (feature `wayland-data-control`)
- Nessuna dipendenza aggiuntiva senza richiesta esplicita

## Invarianti crittografici — NON modificabili

- KDF: **Argon2id**, Version::V0x13. Default: `m_cost = 65536` KiB, `t_cost = 3`, `p_cost = 4`. Parametri salvati nell'header in chiaro.
- AEAD: **XChaCha20-Poly1305**. Nonce 24 byte sempre da `OsRng`, mai riusati, mai derivati da contatore.
- **Due livelli di chiave**: master password → Argon2id → KEK (32B). KEK cifra una DEK casuale (32B). DEK cifra il vault. Cambio password = solo re-wrap della DEK, il ciphertext del vault non viene riscritto.
- Nessuna primitiva implementata a mano. Nessun uso di MD5/SHA1, CBC, ECB, AEAD senza tag.
- L'hash della master password non viene mai salvato su disco.

## Formato file `.pwdv` v1

Tabella degli offset: @docs/ARCHITECTURE.md (sezione "Dati e persistenza"). `HEADER_LEN = 130`;
offset chiave: salt 18, dek_nonce 34, wrapped_dek 58, vault_nonce 106, ciphertext 130.

**AAD (regole esatte, non derogabili):**

- wrap/unwrap DEK: `header[0..34]` (magic, version, kdf_id, parametri KDF, salt)
- seal/open vault: `header[0..6] ++ header[106..130]` (30 byte: magic, version, kdf_id, vault_nonce)

I parametri KDF e il salt sono esclusi dall'AAD del vault per consentire il cambio password senza ricifrare i dati. Sono già autenticati dallo unwrap della DEK.

**Password → Argon2id:** la password passa per NFKC (`policy::nfkc`) in `wrap_dek` e `unwrap_dek`, mai in `derive_kek`. Allo sblocco, se la forma NFKC è diversa e non apre, si riprova con i byte originali (vault pre-NFKC). Non rimuovere il fallback: renderebbe illeggibili quei vault. Vedi ADR 0005.

## Vincoli di codice

- Zero `unwrap()`, `expect()`, `panic!()`, indexing con slicing non controllato nel codice di libreria. Ammessi solo nei test.
- Tipi chiave: azzerati al drop (`#[derive(ZeroizeOnDrop)]`, o `Drop` manuale + marker `ZeroizeOnDrop` se il campo non implementa `Zeroize`, come `Key32`), nessun `Debug`, `Display`, `Clone`, `Serialize`. Accesso ai byte solo via metodo esplicito.
- Plaintext restituito sempre come `Zeroizing<Vec<u8>>`.
- Nessun `unsafe` senza commento che ne giustifichi la necessità.
- Nessun segreto in log, messaggi di errore o `Debug`. Gli errori di autenticazione non distinguono "password sbagliata" da "file manomesso".
- Input troncato o malformato → `Err`, mai panic.
- Scrittura su disco atomica: file temporaneo nella stessa directory, `sync_all()`, poi `rename`.

## GUI — vincoli

- Framework: `eframe`/`egui` 0.28+. Feature `persistence` **disabilitata**: nessuno stato di widget o memoria egui viene scritto su disco.
- `pwdv-core` non dipende da eframe, egui, arboard o da qualsiasi crate grafico. Dipendenza in una sola direzione: gui → core.
- La derivazione Argon2id non viene mai eseguita sul thread della UI. Thread separato + canale, spinner durante l'attesa.
- Buffer della master password: `String` dedicata, dopo l'invio `zeroize()` e poi `clear()`. Mai solo `clear()`.
- Nessuna struct che contiene password decifrate deriva `Debug`, `Serialize` o `Clone`.
- Nessun segreto in titolo finestra, tooltip, log, messaggi di errore, o nel testo di un widget non mascherato.
- Auto-lock: alla scadenza del timer la DEK e i dati del vault vengono zeroizzati e lo stato torna a `Locked` (nel codice: `AppState::Unlocking`). Non è sufficiente cambiare schermata.
- Gli errori mostrati all'utente non distinguono password sbagliata da file manomesso.
- Fuori scope, da dichiarare nel README: protezione da screenshot, keylogger, screen recording e clipboard manager di terze parti.

## Test obbligatori

Ogni step si chiude con `cargo test --workspace` e `cargo clippy --workspace --all-targets -- -D warnings` verdi.

I vettori noti per Argon2id vanno copiati da RFC 9106. **Non inventare valori attesi**: se un vettore non è disponibile, lascia il test `#[ignore]` con un commento, non scrivere byte plausibili.

## Workflow

- Report dopo ogni step: file toccati, funzioni aggiunte, output di `cargo test`.
- Non anticipare step successivi.
- Non aggiungere feature non richieste.

## Regole per Claude

- Mai `git commit` o `git push` senza richiesta esplicita.
- Prima di modifiche strutturali leggi @docs/ARCHITECTURE.md.
- Dopo aver aggiunto/rimosso una tecnologia o cambiato come comunicano i componenti, aggiorna docs/ARCHITECTURE.md (o usa /aggiorna-architettura).
- Decisioni non banali → nuovo ADR in docs/decisions/ (da `TEMPLATE.md`).
- Messaggi utente: CLI in inglese, GUI in italiano. Commenti nel codice in italiano.

## Riferimenti

- Architettura: @docs/ARCHITECTURE.md
- Decisioni: docs/decisions/
- Inventario crittografico (chiavi, algoritmi, migrazione): docs/CRYPTO-INVENTORY.md — da aggiornare a ogni modifica di crypto, format o key
- Guida utente e modello di minaccia: README.md

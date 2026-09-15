# pwdv — password manager cifrato (Rust)

Vault locale cifrato, CLI. Nessuna sincronizzazione, nessun server.

## Stack

- Rust 2021, `cargo` workspace singolo
- `argon2` 0.5 (feature `zeroize`), `chacha20poly1305` 0.10, `zeroize` 1 (feature `zeroize_derive`), `rand` 0.8, `thiserror` 1
- Vault store e CLI: `serde` 1 (feature `derive`), `serde_json` 1, `clap` 4 (feature `derive`), `rpassword` 7
- Nessuna dipendenza aggiuntiva senza richiesta esplicita

## Invarianti crittografici — NON modificabili

- KDF: **Argon2id**, Version::V0x13. Default: `m_cost = 65536` KiB, `t_cost = 3`, `p_cost = 4`. Parametri salvati nell'header in chiaro.
- AEAD: **XChaCha20-Poly1305**. Nonce 24 byte sempre da `OsRng`, mai riusati, mai derivati da contatore.
- **Due livelli di chiave**: master password → Argon2id → KEK (32B). KEK cifra una DEK casuale (32B). DEK cifra il vault. Cambio password = solo re-wrap della DEK, il ciphertext del vault non viene riscritto.
- Nessuna primitiva implementata a mano. Nessun uso di MD5/SHA1, CBC, ECB, AEAD senza tag.
- L'hash della master password non viene mai salvato su disco.

## Formato file `.pwdv` v1

| offset | len | campo |
|---|---|---|
| 0 | 4 | magic `PWDV` |
| 4 | 1 | version = 1 |
| 5 | 1 | kdf_id = 1 (Argon2id) |
| 6 | 4 | m_cost KiB, u32 LE |
| 10 | 4 | t_cost, u32 LE |
| 14 | 4 | p_cost, u32 LE |
| 18 | 16 | salt |
| 34 | 24 | dek_nonce |
| 58 | 48 | wrapped_dek (32B DEK + 16B tag) |
| 106 | 24 | vault_nonce |
| 130 | .. | ciphertext + tag Poly1305 |

`HEADER_LEN = 130`.

**AAD (regole esatte, non derogabili):**

- wrap/unwrap DEK: `header[0..34]` (magic, version, kdf_id, parametri KDF, salt)
- seal/open vault: `header[0..6] ++ header[106..130]` (30 byte: magic, version, kdf_id, vault_nonce)

I parametri KDF e il salt sono esclusi dall'AAD del vault per consentire il cambio password senza ricifrare i dati. Sono già autenticati dallo unwrap della DEK.

## Vincoli di codice

- Zero `unwrap()`, `expect()`, `panic!()`, indexing con slicing non controllato nel codice di libreria. Ammessi solo nei test.
- Tipi chiave: `#[derive(ZeroizeOnDrop)]`, nessun `Debug`, `Display`, `Clone`, `Serialize`. Accesso ai byte solo via metodo esplicito.
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
- Auto-lock: alla scadenza del timer la DEK e i dati del vault vengono zeroizzati e lo stato torna a `Locked`. Non è sufficiente cambiare schermata.
- Gli errori mostrati all'utente non distinguono password sbagliata da file manomesso.
- Fuori scope, da dichiarare nel README: protezione da screenshot, keylogger, screen recording e clipboard manager di terze parti.

## Test obbligatori

Ogni step si chiude con `cargo test` e `cargo clippy -- -D warnings` verdi.

I vettori noti per Argon2id vanno copiati da RFC 9106. **Non inventare valori attesi**: se un vettore non è disponibile, lascia il test `#[ignore]` con un commento, non scrivere byte plausibili.

## Workflow

- Report dopo ogni step: file toccati, funzioni aggiunte, output di `cargo test`.
- Non anticipare step successivi.
- Non aggiungere feature non richieste.
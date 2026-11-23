# 0009 — Blocco in RAM dei segreti e prerequisiti di piattaforma
- **Data**: 2026-11-23
- **Stato**: accettata

## Contesto
L'audit `docs/audit/2026-11-23-completo.md` (rilievo M2) ha rilevato che le pagine con
chiavi e password possono finire nello swap o nell'immagine di ibernazione. Ci sono
due riferimenti:
- **OWASP ASVS 5.0, 11.7.1 (L3)**: "full memory encryption is in use that protects
  sensitive data while it is in use". È una funzione della piattaforma (hardware e
  sistema operativo), non qualcosa che un'applicazione può realizzare da sola.
- **CWE-591**: individuare i dati da proteggere dallo swap e usare i meccanismi della
  piattaforma (`mlock`, `VirtualLock`), controllando il valore di ritorno.

## Decisione
Si applicano entrambi i livelli.
- **Piattaforma (ASVS 11.7.1)**: il README (§1, "Prerequisiti del sistema") richiede
  swap cifrato o in RAM, ibernazione cifrata o disattivata e, se disponibile, la
  cifratura della memoria.
- **Codice (CWE-591)**: `pwdv_core::hardening::lock_bytes` / `lock_string` bloccano in
  RAM, **prima** di scriverci il segreto:
  - `Key32` (KEK e DEK): i byte sono passati da `[u8; 32]` in linea a `Box<[u8; 32]>`,
    con un indirizzo stabile. La KEK è scritta da Argon2id direttamente nel buffer
    bloccato, senza copie sullo stack;
  - l'uscita di `policy::nfkc`;
  - GUI: i due buffer del modulo della master password (capacità fissa) e la copia
    passata al worker;
  - CLI: la stringa di `rpassword`, dopo la lettura perché la alloca la libreria.
- **Se il blocco fallisce** il programma continua: il fallimento viene registrato
  (`memory_lock_failed()`), la GUI mostra un avviso nelle schermate di sblocco e
  creazione e la CLI lo scrive su stderr all'uscita.
- **Mai `munlock`**: il blocco vale per pagina e non tiene un conteggio. Sbloccare la
  pagina di un segreto liberato esporrebbe un altro segreto nella stessa pagina. Le
  pagine restano bloccate fino all'uscita, entro `RLIMIT_MEMLOCK` (8 MiB predefiniti su
  Linux, molto più di quanto serve).
- Windows: `VirtualLock` richiederebbe una dipendenza (`windows-sys`) non ancora
  approvata. Per ora il blocco risulta fallito e l'utente vede l'avviso.

## Alternative considerate
- **Solo prerequisiti documentati**: copre tutto se il sistema è configurato bene, ma
  lascia CWE-591 senza misure nel codice.
- **Solo `mlock`**: non soddisfa ASVS 11.7.1, non copre l'ibernazione né le copie nelle
  librerie.
- **Allocatore dedicato con pagine bloccate** per tutte le voci del vault: copertura
  maggiore, ma molto codice `unsafe` e un'intrusione in serde e nelle `String` di egui.
- **Bloccare il programma se `mlock` fallisce**: renderebbe pwdv inutilizzabile con
  limiti bassi o su Windows, senza proteggere dalle copie non bloccabili.
- **Una pagina dedicata per ogni chiave**, per poter usare `munlock`: più codice
  `unsafe` (allocazione manuale) senza un beneficio pratico.

## Conseguenze
- DEK, KEK e master password (nei buffer controllati da pwdv) non vanno nello swap.
- `Key32` non usa più `#[derive(ZeroizeOnDrop)]`: `zeroize` non implementa `Zeroize` per
  `Box<[u8; 32]>`, quindi azzera con un `Drop` manuale più il marker `ZeroizeOnDrop`.
- Restano esposti allo swap, e coperti solo dai prerequisiti: le voci del vault, le
  copie in egui, winit e arboard, la memoria di Argon2id, il testo cifrato decifrato
  in `Zeroizing<Vec<u8>>` prima del parsing JSON.
- Test: `tests/hardening.rs` controlla `VmLck` > 0 su Linux.

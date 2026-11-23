# 0008 — Disattivazione dei core dump all'avvio
- **Data**: 2026-11-23
- **Stato**: accettata

## Contesto
L'audit `docs/audit/2026-11-23-completo.md` (rilievo M1, ASVS 11.7.2) ha rilevato che un
crash di CLI o GUI a vault aperto può scrivere su disco l'intera memoria del processo,
con DEK e voci in chiaro. Su Linux con `systemd-coredump` i dump finiscono in
`/var/lib/systemd/coredump/` e restano lì per giorni. Sulla macchina di sviluppo
`ulimit -c` vale `unlimited`.

## Decisione
- Nuovo modulo `pwdv_core::hardening` con `disable_core_dumps()`, chiamata come prima
  istruzione del `main` di `pwdv` e `pwdv-gui`.
- Unix: `setrlimit(RLIMIT_CORE, 0)`. Linux in più: `prctl(PR_SET_DUMPABLE, 0)`, necessario
  perché con `core_pattern` che inizia con `|` (il caso di `systemd-coredump`) il kernel
  ignora `RLIMIT_CORE`.
- Windows: nessuna operazione, documentato nel README.
- Se la chiamata fallisce, il programma termina con un errore: priorità alla sicurezza.
- Nuova dipendenza `libc` 0.2 (autorizzata esplicitamente), solo
  `[target.'cfg(unix)'.dependencies]` di `pwdv-core`; era già presente come dipendenza
  indiretta. Due blocchi `unsafe` commentati: la libreria standard non espone queste
  chiamate.

## Alternative considerate
- **`rustix`** (API senza `unsafe`, già nell'albero tramite eframe): richiede feature in
  più e un'API meno diretta per due sole chiamate.
- **Solo documentazione** (`ulimit`/`coredump.conf` a livello di sistema): dipende dalla
  configurazione dell'utente e lascia aperto il rilievo.
- **Funzione duplicata in CLI e GUI**: due copie del codice `unsafe` da mantenere.

## Conseguenze
- Un crash di pwdv non lascia segreti su disco, ma non lascia nemmeno un dump da
  analizzare: per il debug serve togliere temporaneamente la chiamata.
- `PR_SET_DUMPABLE = 0` rende anche `/proc/<pid>/mem` e `ptrace` inaccessibili agli altri
  processi dello stesso utente (non a root).
- Non copre lo swap né l'ibernazione (rilievo M2, separato).

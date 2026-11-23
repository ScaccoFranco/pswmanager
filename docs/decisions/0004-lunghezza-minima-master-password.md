# 0004 — Lunghezza minima della master password
- **Data**: 2026-11-23
- **Stato**: accettata, estesa da 0006 (`master_long_enough` è diventata `check_new_master`)

## Contesto
Fino a questa decisione bastava una master password non vuota. NIST SP 800-63B rev. 4
(§3.1.1.2) chiede almeno 15 caratteri per una password usata come unico fattore di
autenticazione, e sconsiglia regole di composizione (maiuscole, simboli…). La master
password di pwdv è l'unico fattore e protegge un file che un attaccante può attaccare
offline senza limiti di tentativi: la lunghezza è la difesa principale insieme ad Argon2id.
(Il riferimento al paragrafo e il valore 15 sono da verificare sul testo ufficiale.)

## Decisione
- `pwdv_core::policy::MIN_MASTER_CHARS = 15`, contati in caratteri Unicode (code point), spazi inclusi.
- La regola vive nel core (`policy::master_long_enough`) e viene applicata da:
  - CLI: `pwdv init` e `pwdv passwd` (`prompt_new`);
  - GUI: schermata di creazione del vault, prima del controllo di conferma.
- **Mai allo sblocco**: i vault creati con password più corte restano apribili.
- Nessuna regola di composizione. Il core non la impone in `store::create` /
  `store::change_password`, che continuano ad accettare byte arbitrari.

## Alternative considerate
- Solo un avviso con conferma: lascia passare password deboli per distrazione.
- Minimo di 8 caratteri (SP 800-63B per password con secondo fattore): non applicabile, pwdv non ha un secondo fattore.
- Imporla in `store`: richiederebbe di cambiare l'API in byte e i test esistenti, senza
  benefici reali visto che core, CLI e GUI sono nello stesso workspace.

## Conseguenze
- Chi ha un vault con password corta non è obbligato a cambiarla; a un futuro `passwd`
  dovrà sceglierne una di almeno 15 caratteri.
- Restano aperti, rispetto a SP 800-63B: normalizzazione Unicode prima della derivazione
  e controllo contro password note. Entrambi richiedono nuove dipendenze.

# 0006 — Rifiuto di password comuni, ripetute o prevedibili
- **Data**: 2026-11-23
- **Stato**: accettata

## Contesto
NIST SP 800-63B (rev. 4, §3.1.1.2) chiede di confrontare una nuova password con un
elenco di valori comuni, attesi o compromessi: password trafugate, parole del
dizionario, caratteri ripetuti o in sequenza, parole legate al contesto (per esempio il
nome del servizio). Con la lunghezza minima di 15 caratteri (ADR 0004) le password
comuni più corte sono già escluse, ma ne restano di lunghe e molto diffuse
(`1qaz2wsx3edc4rfv`, `123456789qwerty`).

## Decisione
- **Elenco incorporato, nessuna nuova dipendenza.** `crates/pwdv-core/data/common-passwords.txt`
  viene incluso nel binario con `include_str!`. Sorgente: SecLists,
  `Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt`
  (sha256 `424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51`, scaricato il
  2026-11-23), licenza MIT in `data/LICENSE-SecLists`.
- **Filtro**: solo righe ASCII stampabile di almeno 15 caratteri, convertite in minuscolo,
  ordinate e senza duplicati (`LC_ALL=C sort -u`): 10.898 voci, circa 190 KB.
- `policy::check_new_master(&str) -> Result<(), Weakness>`, nell'ordine:
  1. `TooShort`: meno di 15 caratteri digitati;
  2. `Common`: la forma NFKC, senza distinguere maiuscole e minuscole, è nell'elenco;
  3. `Repetitive`: un blocco più corto ripetuto per intero (`xxxx…`, `abcabc…`);
  4. `Sequential`: ogni carattere segue il precedente di +1 o -1 nello stesso verso, con
     `9→0` e `0→9` come passi tra cifre;
  5. `ContextWord`: contiene `pwdv`, senza distinguere maiuscole e minuscole.
- Il confronto non crea copie della password: avviene carattere per carattere.
- `Weakness` non porta con sé la password; CLI (in inglese) e GUI (in italiano)
  traducono la variante in un messaggio.
- Come per la lunghezza: solo password nuove (`init`, `passwd`, creazione nella GUI), mai allo sblocco.

## Alternative considerate
- **`zxcvbn`** (stima dell'entropia con dizionari e pattern della tastiera): più completo,
  ma porta molte dipendenze transitive e dati di dimensione maggiore. Si può rivalutare
  con una richiesta esplicita.
- **Verifica online con Have I Been Pwned** (k-anonymity): esclusa, pwdv non ha
  funzioni di rete per scelta.
- **Elenco completo da 1.000.000 di voci**: inutile, quasi tutte sono più corte di 15
  caratteri e già rifiutate; aumenterebbe il binario di circa 8 MB.
- **Ricerca binaria sull'elenco ordinato**: non serve, il controllo avviene una volta
  per password scelta e la scansione lineare di circa 11.000 righe è istantanea.

## Conseguenze
- I binari `pwdv` e `pwdv-gui` crescono di circa 190 KB.
- L'elenco è statico: non copre violazioni successive alla raccolta xato-net (pubblicata
  intorno al 2015, da verificare) e va aggiornato a mano, ripetendo il filtro descritto sopra.
- I controlli su ripetizioni e sequenze sono volutamente semplici: non riconoscono
  sequenze della tastiera (`qwertyuiop…`) se non sono nell'elenco, né ripetizioni
  parziali (`trottolatrottolaX` passa).
- La parola di contesto `pwdv` rifiuta anche frasi lunghe che la contengono, come da
  standard: il messaggio spiega il motivo.

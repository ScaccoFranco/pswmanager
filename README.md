# pwdv — password manager locale cifrato

**pwdv** conserva le tue password in un unico file cifrato sul tuo computer. Non c'è
nessun server, nessuna sincronizzazione e nessun account: il file è tuo, e senza la
master password nessuno (nemmeno tu) può leggerlo.

Il progetto offre due programmi che usano lo stesso formato di file:

| Programma | Binario | A cosa serve |
|---|---|---|
| Interfaccia grafica | `pwdv-gui` | Uso quotidiano: lista delle voci, ricerca, copia, modifica, blocco automatico |
| Riga di comando | `pwdv` | Script, terminale, generazione di password casuali |

> **Stato del progetto:** in sviluppo. Il formato del file (v1) è stabile. Nella GUI
> mancano ancora il generatore di password (disponibile nella CLI con `pwdv gen`),
> il tema chiaro/scuro e alcune scorciatoie da tastiera.

---

## Indice

1. [Cosa protegge e cosa no](#1-cosa-protegge-e-cosa-no)
2. [Tecnologie usate](#2-tecnologie-usate)
3. [Come funziona la cifratura](#3-come-funziona-la-cifratura)
4. [Installazione](#4-installazione)
5. [Tutorial: interfaccia grafica](#5-tutorial-interfaccia-grafica)
6. [Tutorial: riga di comando](#6-tutorial-riga-di-comando)
7. [Blocco automatico e clipboard in dettaglio](#7-blocco-automatico-e-clipboard-in-dettaglio)
8. [Backup e recupero](#8-backup-e-recupero)
9. [Limiti noti](#9-limiti-noti)
10. [Sviluppo](#10-sviluppo)

---

## 1. Cosa protegge e cosa no

### Protegge da

- **Furto o copia del file del vault.** Senza la master password il contenuto è
  illeggibile. Ogni tentativo di indovinarla costa una derivazione Argon2id da 64 MiB,
  il che rende lenti e costosi gli attacchi a forza bruta, a patto che la master
  password sia robusta.
- **Manomissione del file.** Qualunque byte modificato, troncato o aggiunto viene
  rilevato: il vault non si apre. Il messaggio di errore è volutamente lo stesso di una
  password sbagliata ("Password errata o file danneggiato"), così non rivela quale dei
  due casi si è verificato.
- **Password lasciate a video o nel clipboard.** La GUI si blocca da sola dopo un
  periodo di inattività, maschera le password (e le rinasconde dopo 10 secondi se le
  mostri) e svuota il clipboard 20 secondi dopo una copia.
- **Salvataggi interrotti.** Ogni scrittura è atomica: un'interruzione di corrente non
  lascia un file a metà.

### Non protegge da

- **Programmi malevoli sul tuo computer** che girano con il tuo utente: keylogger,
  registrazione o cattura dello schermo, lettura della memoria dei processi.
- **Gestori del clipboard di terze parti** che ignorano l'indicazione "non conservare
  nella cronologia" (vedi [sezione 7](#72-clipboard)).
- **Screenshot e screen recording** fatti mentre una password è visibile.
- **Una master password debole o riutilizzata.** La cifratura è forte quanto la
  password che la protegge.
- **Una master password dimenticata.** Non esiste recupero, per costruzione.
- **La memoria scritta su disco dal sistema operativo** (swap, ibernazione): pwdv non
  impedisce che le pagine di memoria del processo finiscano nello swap.

### Rete

pwdv non ha funzioni di rete: niente sincronizzazione, telemetria o aggiornamenti
automatici. Tra le dipendenze in `Cargo.lock` non ci sono librerie HTTP, TLS o runtime
di rete. L'unica comunicazione verso altri processi è locale: il compositor grafico
(Wayland/X11), il clipboard e, se attivo, il servizio di accessibilità del desktop
(AT-SPI), che permette ai lettori di schermo di leggere il testo mostrato dall'interfaccia.

---

## 2. Tecnologie usate

pwdv è scritto in **Rust** (edizione 2021) ed è organizzato come workspace `cargo` con
tre crate. La dipendenza va in un solo verso: CLI e GUI usano il core, il core non sa
nulla di interfacce grafiche.

```
crates/
├── pwdv-core/   libreria: formato del file, crittografia, lettura e scrittura del vault
├── pwdv-cli/    binario `pwdv`: interfaccia a riga di comando
└── pwdv-gui/    binario `pwdv-gui`: interfaccia grafica
```

### Crittografia (pwdv-core)

| Libreria | Versione | Uso |
|---|---|---|
| [`argon2`](https://crates.io/crates/argon2) | 0.5 | Derivazione della chiave dalla master password con **Argon2id** (RFC 9106) |
| [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) | 0.10 | Cifratura autenticata **XChaCha20-Poly1305** |
| [`rand`](https://crates.io/crates/rand) | 0.8 | Chiavi, salt e nonce casuali da `OsRng`, il generatore del sistema operativo |
| [`zeroize`](https://crates.io/crates/zeroize) | 1 | Azzeramento della memoria che ha contenuto chiavi e password |

Scelte di progetto:

- **Nessuna primitiva scritta a mano**: solo implementazioni della famiglia RustCrypto.
  Niente MD5, SHA-1, CBC, ECB o cifratura senza autenticazione.
- **Argon2id** è l'algoritmo raccomandato da RFC 9106 per derivare chiavi da password:
  richiede molta memoria, quindi un attacco con GPU o hardware dedicato costa molto di più.
- **XChaCha20-Poly1305** usa nonce da 24 byte: sono abbastanza lunghi da poter essere
  scelti a caso a ogni cifratura senza rischio pratico di ripeterli. pwdv non li deriva
  mai da un contatore.
- Le chiavi sono tipi dedicati che si azzerano quando non servono più, non si possono
  copiare per sbaglio e non si possono stampare nei log.

### Archiviazione (pwdv-core)

| Libreria | Versione | Uso |
|---|---|---|
| [`serde`](https://crates.io/crates/serde) + [`serde_json`](https://crates.io/crates/serde_json) | 1 | Il contenuto del vault è un documento JSON, cifrato prima di essere scritto |
| [`thiserror`](https://crates.io/crates/thiserror) | 1 | Tipi di errore; i messaggi non contengono mai segreti |

### Riga di comando (pwdv-cli)

| Libreria | Versione | Uso |
|---|---|---|
| [`clap`](https://crates.io/crates/clap) | 4 | Parsing di comandi e opzioni |
| [`rpassword`](https://crates.io/crates/rpassword) | 7 | Lettura delle password dal terminale senza mostrarle |

### Interfaccia grafica (pwdv-gui)

| Libreria | Versione | Uso |
|---|---|---|
| [`eframe`](https://crates.io/crates/eframe) / [`egui`](https://crates.io/crates/egui) | 0.36 | Interfaccia grafica immediate-mode; renderer OpenGL (`glow`), supporto Wayland e X11, accessibilità (`accesskit`) |
| [`arboard`](https://crates.io/crates/arboard) | 3.6 | Accesso al clipboard di sistema; su Wayland tramite il protocollo *data-control* |

Scelte di progetto:

- La funzione `persistence` di eframe è **disattivata**: la GUI non scrive su disco né
  lo stato dei widget né la posizione della finestra.
- La derivazione Argon2id, che richiede qualche centinaio di millisecondi (diversi
  secondi in una build di debug), gira su un **thread separato**: la finestra resta
  reattiva e mostra uno spinner.
- Dopo lo sblocco la GUI tiene in memoria la chiave dei dati (DEK), non la master
  password: i salvataggi non richiedono di nuovo Argon2.

---

## 3. Come funziona la cifratura

### Due livelli di chiave

```
master password ──Argon2id(salt, parametri)──▶ KEK (32 byte)
                                                 │ cifra
                                                 ▼
                              DEK casuale (32 byte), salvata cifrata nell'header
                                                 │ cifra
                                                 ▼
                                   contenuto del vault (JSON)
```

- La **KEK** (*key encryption key*) viene ricalcolata dalla master password a ogni
  sblocco e non viene mai salvata.
- La **DEK** (*data encryption key*) è casuale e cifra i dati. Nel file c'è solo la sua
  versione cifrata con la KEK.
- **Cambiare la master password** significa solo ricifrare la DEK con una nuova KEK: i
  dati del vault non vengono riscritti.
- L'hash della master password non viene mai salvato.

### Parametri di Argon2id

| Parametro | Valore predefinito |
|---|---|
| Memoria (`m_cost`) | 65536 KiB (64 MiB) |
| Iterazioni (`t_cost`) | 3 |
| Parallelismo (`p_cost`) | 4 |
| Salt | 16 byte casuali |
| Output | 32 byte |

I parametri sono scritti in chiaro nell'header, così un vault creato con parametri
diversi resta apribile. Per difendersi da un file costruito ad arte, pwdv rifiuta valori
oltre 1 GiB di memoria, 64 iterazioni o 64 thread.

### Formato del file `.pwdv` (versione 1)

| Offset | Lunghezza | Campo |
|---|---|---|
| 0 | 4 | magic `PWDV` |
| 4 | 1 | versione = 1 |
| 5 | 1 | algoritmo KDF = 1 (Argon2id) |
| 6 | 4 | `m_cost` in KiB, u32 little-endian |
| 10 | 4 | `t_cost`, u32 little-endian |
| 14 | 4 | `p_cost`, u32 little-endian |
| 18 | 16 | salt |
| 34 | 24 | nonce della DEK |
| 58 | 48 | DEK cifrata (32 byte + 16 byte di tag) |
| 106 | 24 | nonce del vault |
| 130 | … | contenuto cifrato + tag Poly1305 |

L'header è lungo 130 byte. Nessun campo è modificabile senza essere scoperto:

- la cifratura della DEK autentica `header[0..34]` (magic, versione, KDF, parametri, salt);
- la cifratura del vault autentica `header[0..6]` più `header[106..130]` (magic,
  versione, KDF, nonce del vault).

Parametri KDF e salt sono esclusi dall'autenticazione del vault proprio per permettere
il cambio password senza ricifrare i dati; sono comunque protetti, perché se cambiano la
DEK non si decifra più.

### Il contenuto in chiaro

Dopo la decifratura il vault è un documento JSON:

```json
{
  "version": 1,
  "entries": [
    {
      "name": "GitHub",
      "username": "mario.rossi",
      "password": "…",
      "url": "https://github.com",
      "notes": "account personale",
      "created": 1789419784,
      "modified": 1789420917
    }
  ]
}
```

`created` e `modified` sono secondi dall'epoch Unix. Un file con uno schema di versione
sconosciuta viene rifiutato, per non perdere dati al primo salvataggio.

### Scrittura su disco

- Ogni salvataggio scrive un file temporaneo nella stessa cartella, lo sincronizza su
  disco (`sync_all`) e poi lo rinomina al posto del vault: un'interruzione non lascia
  mai un file a metà.
- Prima di ogni salvataggio la versione precedente viene conservata in `<vault>.bak`.
- I file creati hanno permessi `0600` (leggibili solo dal tuo utente).

---

## 4. Installazione

### Requisiti

- **Rust 1.95 o successivo** (versione minima richiesta da eframe 0.36), installabile con
  [rustup](https://rustup.rs).
- Per la GUI: un desktop Linux con **Wayland** o **X11** e un driver **OpenGL**
  funzionante.

### Compilazione

```sh
git clone <url-del-repository> pswmanager
cd pswmanager
cargo build --release
```

I binari compilati sono `target/release/pwdv` (CLI) e `target/release/pwdv-gui` (GUI).

> Usa la build **release**: in una build di debug Argon2 è molto più lento e ogni
> sblocco richiede diversi secondi.

### Installazione nel sistema (facoltativa)

```sh
cargo install --path crates/pwdv-cli   # installa `pwdv`
cargo install --path crates/pwdv-gui   # installa `pwdv-gui`
```

I binari finiscono in `~/.cargo/bin`, che rustup aggiunge normalmente al `PATH`.

---

## 5. Tutorial: interfaccia grafica

Avvia la GUI:

```sh
pwdv-gui
# oppure, dalla cartella del progetto:
cargo run --release -p pwdv-gui
```

### 5.1 Scegli il file del vault

La prima schermata mostra il percorso del vault, per default `~/.vault.pwdv` (lo stesso
della CLI). Puoi scriverne un altro, poi premi **Apri** o **Invio**.

- Se il file esiste, passi alla schermata di sblocco.
- Se non esiste, passi alla creazione di un nuovo vault.

### 5.2 Crea un nuovo vault

1. Scegli una **master password** e scrivila nel primo campo.
2. Premi **Invio** e riscrivila nel campo di conferma.
3. Premi **Invio** o **Crea vault**.

> **La master password non è recuperabile.** Se la dimentichi, i dati del vault sono
> persi per sempre: non esiste nessuna procedura di reset. Scegline una lunga (una frase
> di più parole va benissimo) e che non usi altrove.

Durante la creazione vedi uno spinner e il messaggio "Creazione del vault in corso…": è
Argon2id al lavoro.

### 5.3 Sblocca il vault

Scrivi la master password e premi **Invio** o **Sblocca**.

- Con una password errata compare "Password errata o file danneggiato."
- Dal terzo tentativo sbagliato consecutivo il pulsante resta disattivato per un
  momento: 1 secondo, poi 2, poi 4 secondi a ogni nuovo errore. Il blocco non è mai
  permanente e il conteggio si azzera al primo sblocco riuscito.
- **Cambia vault** riporta alla scelta del file.

### 5.4 La schermata principale

- **In alto** c'è il menu **Vault**.
- **A sinistra** ci sono il campo di ricerca, l'elenco delle voci in ordine alfabetico
  (nome in evidenza, username sotto: le password non compaiono mai nell'elenco) e il
  pulsante **Nuova voce**.
- **A destra** c'è il dettaglio della voce selezionata.

Se il vault è vuoto, a destra trovi il pulsante **Crea la prima voce**.

### 5.5 Aggiungi una voce

1. Premi **Nuova voce** (o **Crea la prima voce**).
2. Compila i campi: **Nome** e **Password** sono obbligatori; **Username**, **URL** e
   **Note** sono facoltativi. Il nome deve essere diverso da quello delle altre voci.
3. Premi **Salva**.

Il vault viene salvato su disco subito. **Salva** resta disattivato finché mancano i
campi obbligatori, e sotto i pulsanti un messaggio spiega cosa manca.

### 5.6 Cerca

Scrivi nel campo **Cerca**: l'elenco si filtra a ogni carattere. La ricerca guarda nome,
username e URL (mai note o password), non distingue maiuscole e minuscole e accetta
lettere non consecutive, purché in ordine: `gthb` trova "GitHub". Più parole separate da
spazi devono comparire tutte: `git rossi` trova la voce GitHub dell'utente mario.rossi.

### 5.7 Guarda e copia una password

Seleziona una voce. Nel dettaglio:

- la password è mascherata con un numero fisso di pallini, così non se ne intuisce la
  lunghezza;
- **Mostra** la rivela; il pulsante diventa **Nascondi (10 s)** e dopo 10 secondi la
  password torna mascherata da sola;
- **Copia**, accanto a username e password, mette il valore nel clipboard. Accanto
  compare "Copiato · si cancella tra N s": dopo 20 secondi il clipboard viene svuotato.

### 5.8 Modifica una voce

Seleziona la voce e premi **Modifica**. Cambia i campi e premi **Salva**, oppure
**Annulla** per scartare le modifiche. **Salva** è disattivato finché non cambi qualcosa.
Durante la modifica l'elenco è bloccato, per non cambiare voce con una modifica in sospeso.

### 5.9 Elimina una voce

Seleziona la voce e premi **Elimina**. Per confermare devi **digitare il nome esatto**
della voce: il pulsante **Elimina** del dialog si attiva solo allora. L'eliminazione non
si può annullare.

### 5.10 Blocca il vault

- **Ctrl+L**, oppure il menu **Vault → Blocca**.
- **Automaticamente** dopo 5 minuti senza usare tastiera o mouse nella finestra. La
  durata si cambia dal menu **Vault** (1, 2, 5, 10, 15 o 30 minuti).

Quando il vault si blocca, pwdv salva le modifiche in sospeso, svuota il clipboard,
cancella dalla memoria chiave e voci e torna alla richiesta della master password.

### 5.11 Se un salvataggio non riesce

Se il disco è pieno, la cartella non è scrivibile o c'è un altro errore, in alto compare
un avviso rosso che **resta** finché il problema non è risolto: "Salvataggio non
riuscito. … Le modifiche sono solo in memoria." La modifica non va persa: risolvi il
problema e premi **Riprova**.

Se nel frattempo un altro programma ha riscritto il file del vault (per esempio la CLI),
la GUI rifiuta di salvare invece di sovrascriverlo, perché cancellerebbe quelle modifiche.
Non usare CLI e GUI sullo stesso vault nello stesso momento.

### 5.12 Uso da tastiera

| Tasto | Effetto |
|---|---|
| **Invio** | Conferma nei campi password, nel campo percorso e nel dialog di eliminazione |
| **Tab** / **Maiusc+Tab** | Sposta il focus tra campi, righe dell'elenco e pulsanti |
| **Spazio** o **Invio** | Attiva il pulsante o la riga che ha il focus |
| **Ctrl+L** | Blocca il vault |
| **Frecce** + **Invio** | Scelgono una voce in un menu aperto |

---

## 6. Tutorial: riga di comando

Tutti i comandi usano per default il vault `~/.vault.pwdv`; con `--vault <PATH>` ne
scegli un altro. Le password si inseriscono sempre dal terminale, senza eco: non passano
mai come argomenti, quindi non finiscono nella cronologia della shell. I messaggi della
CLI sono in inglese.

### Crea un vault

```sh
pwdv init
# New master password:
# Confirm:
# created /home/mario/.vault.pwdv
```

### Aggiungi una voce

```sh
pwdv add GitHub --username mario.rossi --url https://github.com --notes "account personale"
# Master password:
# Password for 'GitHub':
# added 'GitHub'
```

`--username` è obbligatorio; `--url` e `--notes` sono facoltativi. Il nome deve essere
unico e la password non può essere vuota.

### Elenca le voci

```sh
pwdv list
```

Stampa nome, username e URL separati da tabulazioni, in ordine alfabetico. Le password
non vengono mai mostrate.

### Leggi una voce

```sh
pwdv get GitHub
```

Attenzione: `get` stampa la password **in chiaro** nel terminale.

### Elimina una voce

```sh
pwdv rm GitHub
```

### Cambia la master password

```sh
pwdv passwd
```

Chiede la password attuale e poi due volte la nuova. Viene ricifrata solo la DEK, e il
file `.bak` viene eliminato perché si aprirebbe ancora con la vecchia password.

### Genera una password casuale

```sh
pwdv gen                          # 20 caratteri, tutte le classi
pwdv gen -l 32                    # 32 caratteri
pwdv gen -l 12 -c lower,digits    # solo minuscole e cifre
```

Classi disponibili: `lower`, `upper`, `digits`, `symbols`. I caratteri sono estratti in
modo uniforme da `OsRng`. `gen` non richiede un vault.

---

## 7. Blocco automatico e clipboard in dettaglio

### 7.1 Blocco automatico

| Aspetto | Comportamento |
|---|---|
| Durata predefinita | 5 minuti |
| Cambio durata | Menu **Vault** (1–30 minuti), valida fino alla chiusura del programma |
| Durata iniziale da ambiente | `PWDV_AUTOLOCK_SECONDS=<secondi>`, tra 10 e 86400 |
| Cosa azzera il timer | Qualunque input di tastiera, mouse o touch nella finestra |
| Cosa non lo azzera | Il focus che torna alla finestra, il puntatore che esce |
| Sospensione del computer | Il tempo passato in sospensione conta: al risveglio il vault è già bloccato se il tempo è scaduto |
| Modifiche in sospeso | Una bozza valida viene salvata prima del blocco; una bozza incompleta (senza nome o password) va persa |
| Errore di salvataggio al blocco | Il vault si blocca comunque e la schermata di sblocco lo segnala |

La durata scelta nel menu non viene salvata: per cambiarla in modo permanente usa la
variabile d'ambiente, ad esempio nel file che avvia il programma:

```sh
PWDV_AUTOLOCK_SECONDS=120 pwdv-gui
```

### 7.2 Clipboard

Quando premi **Copia**:

1. Il valore va nel clipboard di sistema marcato con il tipo MIME
   `x-kde-passwordManagerHint`, la convenzione con cui su Linux si chiede ai gestori
   della cronologia degli appunti di non conservarlo (la rispettano, ad esempio, KDE e
   la cronologia di omarchy).
2. Dopo **20 secondi** pwdv svuota il clipboard, ma **solo se contiene ancora quel
   valore**: se nel frattempo hai copiato altro da un'altra applicazione, non lo tocca.
3. Una nuova copia sostituisce la precedente e fa ripartire i 20 secondi.
4. Il clipboard viene svuotato subito anche **al blocco** del vault e **alla chiusura**
   della finestra.

Su Linux il clipboard è "posseduto" dal programma che ha copiato: pwdv serve il valore da
un proprio thread, quindi il valore sparisce anche se pwdv viene terminato bruscamente
(comportamento osservato su Hyprland con `kill -9`). Su Wayland pwdv usa il protocollo
*data-control*: il clipboard X11 di XWayland da solo non basta, perché su alcuni
compositor (ad esempio Hyprland) non arriva alle applicazioni Wayland.

Cosa pwdv **non** può garantire, come dichiarato anche nella finestra:

- un gestore della cronologia che ignora la marcatura `x-kde-passwordManagerHint` può
  conservare una copia della password;
- se il clipboard di sistema non è disponibile, i pulsanti **Copia** sono disattivati e
  la finestra spiega il motivo.

---

## 8. Backup e recupero

Il vault è **un solo file** (per default `~/.vault.pwdv`). Per farne un backup basta
copiarlo:

```sh
cp ~/.vault.pwdv /percorso/del/backup/vault-$(date +%F).pwdv
```

Consigli:

- **Tieni almeno una copia su un altro supporto** (disco esterno, chiavetta) e verifica
  ogni tanto che si apra: `pwdv list --vault /percorso/del/backup/vault-AAAA-MM-GG.pwdv`.
- **Il backup è cifrato con la master password in uso al momento della copia.** Dopo un
  cambio password, i backup vecchi si aprono ancora e solo con la password vecchia.
- **Perdere la master password significa perdere i dati**, backup compresi: nessuno può
  recuperarli, nemmeno con l'accesso al file.
- Accanto al vault trovi `<vault>.bak`, la versione precedente all'ultimo salvataggio.
  Per ripristinarla chiudi pwdv e rinominala al posto del vault. Non è un sostituto dei
  backup: sta sullo stesso disco.

> **Cambio password e vecchie copie.** Il cambio password ricifra solo la DEK, che resta
> la stessa. Chi possiede una vecchia copia del file e la vecchia password può quindi
> ricavare la DEK e, finché non cambia, decifrare anche il vault attuale. Se sospetti che
> la vecchia master password sia stata scoperta, non basta cambiarla: crea un nuovo vault
> con una nuova password e trasferisci le voci.

---

## 9. Limiti noti

- **Date in UTC.** Creazione e modifica sono mostrate in UTC.
- **Copie in memoria non azzerabili.** pwdv azzera chiavi, voci, bozze e campi password
  quando non servono più: dopo il blocco, le password delle voci non risultano più nella
  memoria del processo. Restano però copie gestite da librerie esterne che pwdv non
  controlla: il testo digitato attraversa gli eventi di egui e winit; una password
  rivelata passa dalla cache del testo di egui; una password copiata viene duplicata da
  arboard per servirla al clipboard, e quella copia viene liberata senza essere azzerata.
- **Ctrl+C nei campi di testo.** Copiare con Ctrl+C il testo selezionato nei campi che
  non sono password (username, note) usa il clipboard di egui: quelle copie non sono
  marcate e non vengono cancellate. I campi password non si possono copiare.
- **Una sola istanza per vault.** Due finestre, o GUI e CLI, sullo stesso vault non si
  coordinano. La GUI rifiuta di sovrascrivere un file riscritto dalla CLI, ma due GUI
  aperte sullo stesso vault possono sovrascriversi a vicenda.
- **Generatore di password** disponibile solo nella CLI (`pwdv gen`).

---

## 10. Sviluppo

### Struttura del codice

| Crate | Moduli principali |
|---|---|
| `pwdv-core` | `format` (header v1), `crypto` (Argon2id, XChaCha20-Poly1305, KEK/DEK), `key` (chiavi da 32 byte), `vault` (voci), `store` (lettura, scrittura atomica, `.bak`), `error` |
| `pwdv-cli` | `main.rs`: comandi `init`, `add`, `get`, `list`, `rm`, `passwd`, `gen` |
| `pwdv-gui` | `app` (macchina a stati), `unlock` (sblocco e creazione), `worker` (Argon2 fuori dal thread della UI), `main_view` (elenco e dettaglio), `security` (blocco automatico e clipboard) |

### Test e controlli

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

I test comprendono il vettore Argon2id di RFC 9106, prove di manomissione su ogni campo
dell'header (`crates/pwdv-core/tests/tamper.rs`), la scrittura atomica, il timer di
blocco e la logica del clipboard (con un clipboard finto, per non toccare quello reale).

### Regole del codice

Le regole complete sono in [`CLAUDE.md`](CLAUDE.md). In sintesi:

- nel codice di libreria niente `unwrap()`, `expect()` o `panic!()`: un input troncato
  o malformato produce un errore, mai un crash;
- i tipi che contengono chiavi o password si azzerano al drop e non implementano
  `Debug`, `Clone` o `Serialize`;
- nessun segreto in log, messaggi di errore o testo non mascherato;
- nessuna nuova dipendenza senza una richiesta esplicita.

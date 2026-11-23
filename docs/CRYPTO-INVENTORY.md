# Inventario crittografico — pwdv
_Ultimo aggiornamento: 2026-11-23_

Elenco unico di chiavi, segreti, algoritmi e parametri usati da pwdv, con durata,
sostituzione e piano di migrazione. Risponde a OWASP ASVS 5.0, requisiti 11.1.1, 11.1.2
e 11.1.4 (audit `docs/audit/2026-11-23-completo.md`, rilievi B6, I2, I3). Il formato del
file è descritto in [ARCHITECTURE.md](ARCHITECTURE.md#dati-e-persistenza); le regole
non derogabili sono in `CLAUDE.md`.

## Chiavi e segreti

| Elemento | Dimensione | Origine | Uso | Dove vive | Durata e sostituzione |
|---|---|---|---|---|---|
| Master password | 15–256 caratteri ([ADR 0004](decisions/0004-lunghezza-minima-master-password.md)) | Utente | Ingresso di Argon2id, dopo NFKC ([ADR 0005](decisions/0005-normalizzazione-nfkc-master-password.md)) | Solo in memoria: buffer bloccati in RAM e azzerati dopo l'uso ([ADR 0009](decisions/0009-blocco-in-ram-dei-segreti.md)). Mai su disco, nemmeno come hash | Scelta dall'utente; nessuna scadenza (NIST SP 800-63B). Cambio: `pwdv passwd` |
| Salt | 16 byte | `OsRng` | Parametro di Argon2id | Header in chiaro (offset 18), autenticato come AAD della DEK | Nuovo a ogni `seal`, cambio password e `rekey` |
| KEK | 32 byte | Argon2id(password, salt) | Cifra la DEK | Solo in memoria (`Key32`, bloccata in RAM), per la durata di una derivazione | Derivata a ogni sblocco e azzerata subito dopo; cambia con password o salt |
| DEK | 32 byte | `OsRng` | Cifra il contenuto del vault | Su disco cifrata dalla KEK (offset 58, 48 byte con il tag); in memoria in `Key32` dentro `VaultKey` | Nuova a ogni `seal`: creazione, ogni salvataggio della CLI, `pwdv rekey` ([ADR 0007](decisions/0007-sostituzione-della-dek.md)). Invariata con `passwd` (solo re-wrap) e nei salvataggi della GUI. Azzerata al blocco |
| `dek_nonce` | 24 byte | `OsRng` | Nonce del wrap della DEK | Header (offset 34) | Nuovo a ogni wrap |
| `vault_nonce` | 24 byte | `OsRng` | Nonce della cifratura del vault | Header (offset 106) | Nuovo a ogni salvataggio (`seal` e `reseal`) |

Nessuna chiave asimmetrica, nessun certificato, nessun segreto nel codice o nella
configurazione.

## Algoritmi

| Funzione | Algoritmo e parametri | Libreria | Stato in ASVS 5.0, Appendice C | Motivazione |
|---|---|---|---|---|
| Derivazione della KEK | Argon2id, versione 0x13; `m_cost = 65536` KiB, `t_cost = 3`, `p_cost = 4`, uscita 32 byte | `argon2` 0.5 | Approvato. I parametri superano il minimo (t=2, m ≥ 19 MiB, p=1) | Seconda opzione raccomandata da RFC 9106 §4. Non è nell'elenco di NIST SP 800-132 (solo PBKDF2): rilevante solo con un requisito FIPS ([ADR 0002](decisions/0002-formato-file-e-due-livelli-di-chiave.md)) |
| Cifratura del vault | XChaCha20-Poly1305 (chiave 256 bit, nonce 192 bit, tag 128 bit); AAD `header[0..6] ++ header[106..130]` | `chacha20poly1305` 0.10 | XChaCha20 e ChaCha20-Poly1305 approvati; la combinazione XChaCha20-Poly1305 non compare nella tabella AEAD | Il nonce da 192 bit permette nonce casuali senza contatore né rischio pratico di collisione |
| Wrap della DEK | XChaCha20-Poly1305 con la KEK; AAD `header[0..34]` | `chacha20poly1305` 0.10 | L'Appendice C elenca AES-KW/KWP per il key wrapping e non tratta l'uso di un AEAD | Un AEAD con nonce casuale e AAD offre riservatezza e integrità della DEK quanto un key wrap dedicato, con una sola primitiva in tutto il progetto. Cambiarlo toccherebbe il formato |
| Generazione casuale | `OsRng` (CSPRNG del sistema operativo, tramite `getrandom`) | `rand` 0.8 | Approvato (11.5.1) | DEK, salt, nonce, generatore di password della CLI |
| Normalizzazione | Unicode NFKC | `unicode-normalization` 0.1.26 | Non è una primitiva crittografica | [ADR 0005](decisions/0005-normalizzazione-nfkc-master-password.md) |

Non usati: MD5, SHA-1, modalità CBC ed ECB, AEAD senza tag, primitive scritte a mano.

**Limiti di sicurezza dei nonce.** Con nonce casuali da 192 bit la probabilità di
collisione dopo 2^48 cifrature con la stessa chiave è circa 2^-97: trascurabile per
qualunque uso realistico.

**Limiti in lettura dei parametri KDF** (`crypto.rs`): `m_cost` ≤ 1 GiB, `t_cost` ≤ 64,
`p_cost` ≤ 64. Valori oltre i limiti sono trattati come file manomesso (`AuthFailed`).

## Protezione in memoria

- Chiavi in `Key32`: nell'heap, bloccate in RAM con `mlock`, azzerate al drop; niente
  `Debug`, `Clone` o `Serialize` ([ADR 0009](decisions/0009-blocco-in-ram-dei-segreti.md)).
- Plaintext restituito come `Zeroizing<Vec<u8>>`; voci azzerate al blocco.
- Core dump disattivati all'avvio ([ADR 0008](decisions/0008-disattivazione-core-dump.md)).
- Copie fuori dal controllo di pwdv (egui, winit, arboard, memoria di Argon2id):
  coperte solo dai prerequisiti del sistema (README §1).

## Procedure di sostituzione

| Situazione | Procedura | Effetto |
|---|---|---|
| Master password compromessa | `pwdv passwd`, poi `pwdv rekey` | Nuova KEK, poi nuova DEK: una copia vecchia del file più la password vecchia non apre più i dati attuali (ADR 0007) |
| Sospetto sulla DEK (copia vecchia del file in mani altrui) | `pwdv rekey` | Nuova DEK, salt e nonce; il `.bak` contiene la DEK precedente cifrata con la password attuale |
| Parametri Argon2id da aumentare | Cambiare `KdfParams::default()` | I vault si aggiornano al primo `seal`, `passwd` o `rekey` (tutti usano i parametri predefiniti). I parametri stanno nell'header: i file vecchi restano leggibili |

## Piano di migrazione degli algoritmi

- **Agilità del formato.** L'header contiene `version` (offset 4) e `kdf_id` (offset 5).
  Un cambio di algoritmo richiede un nuovo valore di `version` (ed eventualmente di
  `kdf_id`). Oggi un valore sconosciuto produce `UnsupportedVersion`, senza tentativi di
  lettura.
- **Procedura prevista**, da decidere con un ADR quando servirà:
  1. il codice impara a leggere v1 e v2 e scrive solo v2;
  2. il primo salvataggio, `passwd` o `rekey` converte il file;
  3. la lettura di v1 resta finché possono esistere file v1.

  È lo stesso schema già usato per il fallback NFKC (ADR 0005).
- **Motivi per migrare**: una debolezza pubblicata in XChaCha20-Poly1305 o Argon2id, un
  requisito FIPS (che imporrebbe PBKDF2 e AES-GCM o AES-KW), un nuovo valore
  raccomandato da RFC 9106 o OWASP.
- **Revisione**: verificare questo inventario a ogni audit (`/verifica-standard`).

## Impatto post-quantum (ASVS 11.1.4)

pwdv usa solo crittografia simmetrica e una funzione di derivazione delle chiavi;
nessuna crittografia asimmetrica (RSA, ECC), che è l'unica rotta dall'algoritmo di Shor.
L'algoritmo di Grover riduce al più a circa 128 bit la sicurezza delle chiavi da 256 bit,
un margine ancora adeguato. Il tag Poly1305 non è interessato in modo pratico. **Nessuna
migrazione post-quantum è necessaria.** La difesa contro un attacco offline resta la
robustezza della master password, protetta dal costo di Argon2id.

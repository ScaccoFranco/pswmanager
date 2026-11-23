# 0002 — Formato file v1 e due livelli di chiave
- **Data**: 2026-11-23 (ricostruita a posteriori)
- **Stato**: accettata

## Contesto
Il vault deve resistere a furto del file e manomissione, e il cambio della master
password deve essere economico e sicuro anche se interrotto.

## Decisione
- **KDF**: Argon2id v0x13, default `m_cost = 65536` KiB, `t_cost = 3`, `p_cost = 4`,
  salt 16 byte, output 32 byte. Parametri salvati in chiaro nell'header; in lettura si
  rifiutano valori oltre 1 GiB / 64 / 64 per non farsi bloccare da un file costruito ad arte.
- **AEAD**: XChaCha20-Poly1305 con nonce da 24 byte sempre da `OsRng`, mai da contatore.
- **Due livelli**: master password → Argon2id → KEK; la KEK cifra una DEK casuale; la DEK
  cifra il vault. Cambio password = re-wrap della DEK con nuovo salt, ciphertext invariato.
- **Header di 130 byte** (tabella in [ARCHITECTURE](../ARCHITECTURE.md#dati-e-persistenza)).
- **AAD**: DEK → `header[0..34]`; vault → `header[0..6] ++ header[106..130]`. Parametri
  KDF e salt esclusi dall'AAD del vault per permettere il cambio password senza ricifrare;
  restano autenticati dallo unwrap della DEK.
- Un solo errore di autenticazione (`AuthFailed`) per password errata e file manomesso.

## Alternative considerate
(da verificare)
- Chiave unica derivata dalla password: il cambio password richiederebbe di ricifrare tutto.
- AES-256-GCM: nonce da 12 byte, rischioso con nonce casuali e dipendente da AES-NI per prestazioni e resistenza a side channel.
- scrypt/PBKDF2: meno resistenti ad attacchi GPU/ASIC rispetto ad Argon2id.

## Conseguenze
- Il cambio password è veloce e il vault non viene riscritto.
- La DEK non cambia mai: chi ha una vecchia copia del file e la vecchia password può
  ricavare la DEK e decifrare anche il vault attuale (documentato nel README §8). Per
  revocare serve un nuovo vault.
- Questi invarianti sono vincolanti: vedi `CLAUDE.md`, sezione invarianti crittografici.

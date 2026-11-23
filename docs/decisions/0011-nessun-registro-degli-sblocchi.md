# 0011 — Nessun registro dei tentativi di sblocco
- **Data**: 2026-11-23
- **Stato**: accettata

## Contesto
OWASP ASVS 5.0, 16.3.1 (L2), chiede di registrare tutti i tentativi di autenticazione,
riusciti e falliti. pwdv non ha log (audit 2026-11-23, rilievo I4).

## Decisione
Nessun registro degli sblocchi né di altri eventi. Il requisito è considerato non
applicabile, per tre motivi:
- **Nessun destinatario**: in un servizio il log serve a chi lo amministra per scoprire
  attacchi. Qui l'unico utente è anche l'unico amministratore, e un attaccante con
  accesso al file lo attacca offline, dove nessun log di pwdv può registrarlo.
- **Un artefatto in più su disco**: un log rivelerebbe quando e quanto spesso si usa il
  vault, e andrebbe protetto a sua volta (cifrato con quale chiave, prima dello
  sblocco?).
- **Il controllo che conta esiste già**: contro i tentativi in linea c'è l'attesa
  crescente della GUI; contro quelli offline il costo di Argon2id.

## Alternative considerate
- **Log in chiaro degli eventi senza segreti**: espone metadati d'uso, non rileva gli
  attacchi offline.
- **Contatore dei tentativi falliti nel vault cifrato**: si aggiorna solo dopo uno
  sblocco riuscito e richiede di riscrivere il file a ogni sblocco; un attaccante
  offline non lo tocca.

## Conseguenze
- Nessuna traccia dei tentativi falliti: l'utente non vede se qualcuno ha provato a
  sbloccare la sua sessione in sua assenza.
- Da rivalutare se pwdv diventasse un servizio o venisse usato da più persone.

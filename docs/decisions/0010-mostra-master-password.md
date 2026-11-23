# 0010 — Pulsante "Mostra" sulla master password
- **Data**: 2026-11-23
- **Stato**: accettata

## Contesto
NIST SP 800-63B rev. 4, §3.1.1.2, raccomanda (SHOULD) di permettere all'utente di vedere
la password mentre la digita, per ridurre gli errori di battitura che spingono verso
password più corte. In ASVS 5.0 (6.2.6) è facoltativo. Fino a oggi il campo della master
password era sempre mascherato, per una regola di `CLAUDE.md` (audit 2026-11-23,
rilievo B8).

## Decisione
- Nelle schermate di sblocco e di creazione, accanto al campo della master password,
  un pulsante **Mostra** rivela il testo per 10 secondi (`unlock::REVEAL_FOR`, la stessa
  durata già usata per le voci). Durante quel tempo il pulsante diventa
  "Nascondi (N s)".
- Alla creazione rivela insieme password e conferma.
- Torna mascherata da sola alla scadenza, al secondo clic e a ogni azzeramento dei
  campi: invio, password troppo lunga o rifiutata, blocco, cambio schermata
  (`PasswordForm::wipe`).
- La regola di `CLAUDE.md` sui widget non mascherati ammette ora questa rivelazione
  temporanea e richiesta esplicitamente.

## Alternative considerate
- **Documentare l'eccezione e lasciare il campo sempre mascherato**: più protetto
  dagli sguardi e dalle registrazioni dello schermo, ma in contrasto con un SHOULD di
  NIST, e la conferma copre solo la creazione, non lo sblocco.
- **Rivelazione finché si tiene premuto**: scomoda con la tastiera e non accessibile.
- **Mostrare solo l'ultimo carattere digitato**: egui non lo supporta.

## Conseguenze
- Mentre è visibile, la master password è esposta a screenshot e registrazioni dello
  schermo (fuori dal modello di minaccia, README §1) e passa dalla cache del testo di
  egui, come le password delle voci rivelate (README §9).
- La scelta di rivelarla resta all'utente: per impostazione il campo è mascherato.

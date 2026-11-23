# 0012 — Doppia licenza: GPL-3.0-or-later e commerciale
- **Data**: 2026-11-23
- **Stato**: accettata

## Contesto
Il progetto non aveva una licenza (audit 2026-11-23, rilievo I5): il codice era "tutti i
diritti riservati". L'autore vuole che chiunque possa usare pwdv, e che chi ne trae un
guadagno commerciale lo paghi.

## Decisione
- **GPL-3.0-or-later** per tutti: testo ufficiale scaricato da
  <https://www.gnu.org/licenses/gpl-3.0.txt> il 2026-11-23 in `LICENSE`
  (sha256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`).
  Campo `license` nel workspace, ereditato dai tre crate.
- **Licenza commerciale** a pagamento, su richiesta all'autore (profilo GitHub), per chi
  vuole includere pwdv in un prodotto non GPL. Il contratto si definisce caso per caso.
- **Contributi esterni** solo con un accordo scritto che permetta all'autore di
  rilicenziarli (README §11): senza, la doppia licenza non è più possibile.
- "or-later", come raccomanda la FSF.

## Alternative considerate
- **MIT OR Apache-2.0**: chiunque potrebbe includere pwdv in un prodotto chiuso e
  venderlo senza pagare.
- **PolyForm Noncommercial**: fa pagare ogni uso commerciale, anche interno a
  un'azienda, ma non è open source e alcune distribuzioni lo escludono.
- **Business Source License 1.1**: come PolyForm, con passaggio a open source dopo una
  data. Più adatta a prodotti che evolvono rapidamente.
- **GPL-3.0-only**: più controllo sulle versioni future della GPL, ma meno diffusa.

## Conseguenze
- pwdv è open source (licenza approvata OSI). **Limite consapevole**: chi vende pwdv
  rispettando la GPL, cioè pubblicando il sorgente, non deve nulla all'autore. Paga solo
  chi vuole tenere chiuso il codice derivato.
- La doppia licenza richiede che l'autore detenga tutti i diritti sul codice:
  nessun contributo esterno senza accordo.
- Codice di terzi incluso: l'elenco SecLists (MIT), compatibile con entrambe le
  licenze. Le dipendenze Rust (verificate con `cargo metadata` il 2026-11-23: MIT,
  Apache-2.0, BSD, Zlib, ISC, BSL-1.0, Unicode-3.0) sono compatibili con la GPL-3.0.
  Apache-2.0 non è compatibile con la GPL-2.0, ma lo è con la 3.0.
- I font di egui (`epaint_default_fonts`: OFL-1.1, Ubuntu Font Licence 1.0) non sono
  codice ma dati incorporati, con licenze proprie che ne permettono la distribuzione
  insieme al programma. Una distribuzione dei binari deve includere tutti gli avvisi
  di terzi (eventualmente generati con uno strumento come `cargo-about`, da approvare).
- Vendere licenze commerciali può rendere l'autore "fabbricante" ai sensi del Cyber
  Resilience Act (obblighi dal 2027-12-11, audit NV5): da verificare prima della prima
  vendita. I contratti commerciali vanno rivisti da un legale.

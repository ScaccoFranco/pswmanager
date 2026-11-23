# 0003 — GUI con eframe/egui
- **Data**: 2026-11-23 (ricostruita a posteriori)
- **Stato**: accettata

## Contesto
Serve una GUI desktop leggera, in Rust, che non scriva stato su disco e che permetta di
controllare dove finiscono i segreti (buffer, clipboard, titolo finestra).

## Decisione
- `eframe`/`egui` 0.36, renderer `glow` (OpenGL), backend `wayland` + `x11`, `accesskit`
  per l'accessibilità. **Feature `persistence` disabilitata.**
- `arboard` 3.6 con `wayland-data-control` per il clipboard: su Hyprland il clipboard
  X11 di XWayland non arriva alle applicazioni Wayland.
- Argon2id sempre su un thread worker, risultato via `std::sync::mpsc`, spinner nella UI.
- Dopo lo sblocco la sessione tiene la DEK (`VaultKey`), non la master password.
- Finestra senza decorazioni di sistema, cornice disegnata dall'app (`window.rs`).

## Alternative considerate
(da verificare)
- GTK/Qt binding: dipendenze native pesanti, controllo minore sui buffer di testo.
- Tauri/webview: superficie d'attacco e dipendenze molto maggiori.
- Iced/Slint: possibili, egui scelto per semplicità del modello immediate-mode.

## Conseguenze
- Restano copie di testo non azzerabili dentro egui/winit/arboard (README §9).
- Nessuna preferenza persistita: es. la durata dell'auto-lock si imposta solo via
  `PWDV_AUTOLOCK_SECONDS`; un futuro tema chiaro/scuro dovrà seguire lo stesso vincolo.
- Richiede Rust ≥ 1.95 (MSRV di eframe 0.36).

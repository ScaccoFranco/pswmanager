//! Macchina a stati della GUI.

use std::io;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui;
use pwdv_core::crypto::VaultKey;
use pwdv_core::error::VaultError;
use pwdv_core::vault::VaultData;
use zeroize::{Zeroize, Zeroizing};

use crate::main_view::{self, MainView};
use crate::security::{self, Clipboard, IdleTimer, Now};
use crate::unlock::{self, FormAction, PasswordForm};
use crate::worker::{self, Outcome};

const LOCK_SHORTCUT: egui::KeyboardShortcut =
    egui::KeyboardShortcut::new(egui::Modifiers::COMMAND, egui::Key::L);

pub enum AppState {
    /// Scelta del file del vault.
    Welcome,
    /// Il file non esiste: nuova master password con conferma.
    Creating,
    /// Il file esiste: richiesta della master password. È anche lo stato
    /// "bloccato": nessuna chiave e nessuna voce in memoria.
    Unlocking,
    /// In un `Box`: la sessione (chiave e vista comprese) è molto più grande
    /// degli altri stati.
    Unlocked(Box<Session>),
    /// Errore che riprovare la password non risolve.
    Error(String),
}

/// Vault aperto. Niente `Debug`, `Clone` o `Serialize`: contiene la DEK e
/// tutte le password in chiaro, azzerate al drop.
pub struct Session {
    pub path: PathBuf,
    /// DEK del vault: i salvataggi non richiedono la master password.
    pub key: VaultKey,
    pub data: VaultData,
    /// Stato della vista, bozze comprese: vive e muore con la sessione.
    pub view: MainView,
}

impl Session {
    fn new(path: PathBuf, key: VaultKey, data: VaultData) -> Self {
        let view = MainView::new(&data);
        Session {
            path,
            key,
            data,
            view,
        }
    }
}

#[derive(Clone, Copy)]
enum LockReason {
    Manual,
    Inactivity,
}

pub struct PwdvApp {
    state: AppState,
    /// Campo percorso della schermata iniziale. Non è un segreto.
    path_input: String,
    /// File scelto nella schermata iniziale.
    path: PathBuf,
    form: PasswordForm,
    /// Derivazione in corso sul thread worker.
    pending: Option<Receiver<Outcome>>,
    welcome_focus: bool,
    /// Sopravvive ai blocchi: va svuotato anche quando la sessione non c'è più.
    clipboard: Clipboard,
    /// Durata scelta dall'utente valida fino alla chiusura: non viene salvata.
    idle: IdleTimer,
}

enum Nav {
    Stay,
    Open,
    Back,
    Submit(Zeroizing<String>),
}

impl From<FormAction> for Nav {
    fn from(action: FormAction) -> Self {
        match action {
            FormAction::Idle => Nav::Stay,
            FormAction::Submit(password) => Nav::Submit(password),
            FormAction::Back => Nav::Back,
        }
    }
}

impl Default for PwdvApp {
    fn default() -> Self {
        PwdvApp::with_clipboard(Clipboard::system())
    }
}

impl PwdvApp {
    fn with_clipboard(clipboard: Clipboard) -> Self {
        PwdvApp {
            state: AppState::Welcome,
            path_input: default_vault_path()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            path: PathBuf::new(),
            form: PasswordForm::default(),
            pending: None,
            welcome_focus: true,
            clipboard,
            idle: IdleTimer::new(security::initial_autolock(), Now::current()),
        }
    }

    fn navigate(&mut self, ctx: &egui::Context, nav: Nav) {
        match nav {
            Nav::Stay => {}
            Nav::Open => self.open(ctx),
            Nav::Back => self.back(ctx),
            Nav::Submit(password) => self.submit(password),
        }
    }

    /// Welcome → Unlocking se il file esiste, Creating se no.
    fn open(&mut self, ctx: &egui::Context) {
        let input = self.path_input.trim();
        if input.is_empty() {
            return;
        }
        let path = PathBuf::from(input);
        self.state = match path.try_exists() {
            Ok(true) => AppState::Unlocking,
            Ok(false) => AppState::Creating,
            Err(e) => AppState::Error(format!(
                "Impossibile accedere a {}.\nErrore di I/O ({e}).",
                path.display()
            )),
        };
        self.path = path;
        self.form.reset(ctx);
    }

    fn back(&mut self, ctx: &egui::Context) {
        if self.pending.is_some() {
            return;
        }
        self.state = AppState::Welcome;
        self.form.reset(ctx);
        self.welcome_focus = true;
    }

    fn submit(&mut self, password: Zeroizing<String>) {
        if self.pending.is_some() {
            return;
        }
        let path = self.path.clone();
        self.pending = match self.state {
            AppState::Creating => Some(worker::spawn_create(path, password)),
            AppState::Unlocking => Some(worker::spawn_unlock(path, password)),
            _ => None,
        };
    }

    /// Chiamata a ogni frame: il thread della UI non si blocca mai sul worker.
    fn poll(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.pending else {
            return;
        };
        let outcome = match rx.try_recv() {
            Ok(outcome) => outcome,
            Err(TryRecvError::Empty) => {
                ctx.request_repaint();
                return;
            }
            Err(TryRecvError::Disconnected) => {
                self.pending = None;
                self.state = AppState::Error("L'operazione si è interrotta in modo inatteso.".into());
                self.form.reset(ctx);
                return;
            }
        };
        self.pending = None;
        self.finish(ctx, outcome);
    }

    fn finish(&mut self, ctx: &egui::Context, outcome: Outcome) {
        match outcome {
            Ok((key, data)) => {
                self.form.succeeded(ctx);
                self.idle.touch(Now::current());
                self.state =
                    AppState::Unlocked(Box::new(Session::new(self.path.clone(), key, data)));
            }
            Err(VaultError::AuthFailed) if matches!(self.state, AppState::Unlocking) => {
                self.form.failed(Instant::now());
            }
            Err(e) => {
                let verb = match self.state {
                    AppState::Creating => "creare",
                    _ => "aprire",
                };
                self.state = AppState::Error(format!(
                    "Impossibile {verb} {}.\n{}",
                    self.path.display(),
                    describe(&e)
                ));
                self.form.reset(ctx);
            }
        }
    }

    /// Scadenze: cancellazione del clipboard e blocco per inattività. Gira in
    /// `logic`, quindi anche a finestra nascosta, grazie ai repaint richiesti qui.
    fn tick(&mut self, ctx: &egui::Context, now: Now) {
        self.clipboard.tick(now);
        if let Some(left) = self.clipboard.remaining(now) {
            ctx.request_repaint_after(left.min(Duration::from_secs(1)));
        }
        if matches!(self.state, AppState::Unlocked(_)) {
            if self.idle.expired(now) {
                self.lock(ctx, LockReason::Inactivity);
            } else {
                ctx.request_repaint_after(self.idle.remaining(now));
            }
        }
    }

    /// Salva ciò che è in sospeso, svuota il clipboard, azzera voci e DEK e
    /// torna alla richiesta della password dello stesso vault.
    fn lock(&mut self, ctx: &egui::Context, reason: LockReason) {
        let Some(saved) = self.close_session() else {
            return;
        };
        main_view::forget_secrets(ctx);
        self.state = AppState::Unlocking;
        self.form.reset(ctx);
        let mut message = match reason {
            LockReason::Manual => "Vault bloccato.".to_owned(),
            LockReason::Inactivity => "Vault bloccato per inattività.".to_owned(),
        };
        if let Err(e) = saved {
            message.push_str(&format!(" Le ultime modifiche non sono state salvate: {e}"));
        }
        self.form.show_info(message);
    }

    /// Chiude la sessione aperta, se c'è, e restituisce l'esito del
    /// salvataggio di ciò che era in sospeso. Il blocco avviene comunque:
    /// tenere in memoria la DEK per non perdere una modifica non è accettabile.
    fn close_session(&mut self) -> Option<Result<(), String>> {
        let session = match std::mem::replace(&mut self.state, AppState::Unlocking) {
            AppState::Unlocked(session) => session,
            other => {
                self.state = other;
                return None;
            }
        };
        let mut session = session;
        let saved = main_view::save_before_lock(&mut session);
        self.clipboard.clear_now();
        // Le voci si azzerano qui; la DEK al drop della sessione (`ZeroizeOnDrop`).
        session.data.entries.zeroize();
        drop(session);
        Some(saved)
    }

    /// Schermata del vault aperto: menu, scorciatoia di blocco, vista principale.
    fn unlocked_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let now = Now::current();
        if ui.input(|i| i.events.iter().any(security::is_user_input)) {
            self.idle.touch(now);
        }
        let mut lock = ui.input_mut(|i| i.consume_shortcut(&LOCK_SHORTCUT));

        let AppState::Unlocked(session) = &mut self.state else {
            return;
        };
        let idle = &mut self.idle;
        egui::Panel::top("pwdv-menu").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                if vault_menu(ui, idle, now) {
                    lock = true;
                }
            });
        });
        main_view::show(ui, session, &mut self.clipboard, now);

        if lock {
            self.lock(ctx, LockReason::Manual);
        }
    }
}

impl eframe::App for PwdvApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        self.tick(ctx, Now::current());
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if matches!(self.state, AppState::Unlocked(_)) {
            self.unlocked_ui(ui, &ctx);
            return;
        }

        let busy = self.pending.is_some();
        let nav = egui::CentralPanel::default()
            .show(ui, |ui| match &self.state {
                AppState::Welcome => {
                    welcome_screen(ui, &mut self.path_input, &mut self.welcome_focus)
                }
                AppState::Creating => {
                    unlock::create_screen(ui, &mut self.form, &self.path, busy).into()
                }
                AppState::Unlocking => {
                    unlock::unlock_screen(ui, &mut self.form, &self.path, busy).into()
                }
                AppState::Unlocked(_) => Nav::Stay,
                AppState::Error(message) => error_screen(ui, message),
            })
            .inner;
        self.navigate(&ctx, nav);
    }

    /// Alla chiusura della finestra: salva ciò che è in sospeso, azzera la
    /// sessione e svuota il clipboard.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        let _ = self.close_session();
        self.clipboard.clear_now();
    }

    /// Senza la feature `persistence` eframe non salva nulla comunque: questa è
    /// una seconda barriera se un giorno venisse abilitata per errore.
    fn persist_egui_memory(&self) -> bool {
        false
    }
}

/// Menu "Vault": blocco manuale e durata del blocco automatico. Restituisce
/// `true` se l'utente ha chiesto di bloccare.
fn vault_menu(ui: &mut egui::Ui, idle: &mut IdleTimer, now: Now) -> bool {
    let mut lock = false;
    ui.menu_button("Vault", |ui| {
        if ui.button("Blocca (Ctrl+L)").clicked() {
            lock = true;
            ui.close();
        }
        ui.separator();
        ui.weak(format!(
            "Blocco automatico dopo {} di inattività",
            format_duration(idle.timeout())
        ));
        for minutes in security::AUTOLOCK_CHOICES_MIN {
            let timeout = Duration::from_secs(minutes * 60);
            if ui
                .radio(idle.timeout() == timeout, format!("{minutes} min"))
                .clicked()
            {
                idle.set_timeout(timeout, now);
                ui.close();
            }
        }
    });
    lock
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs.is_multiple_of(60) {
        format!("{} min", secs / 60)
    } else {
        format!("{secs} s")
    }
}

fn welcome_screen(ui: &mut egui::Ui, path_input: &mut String, focus: &mut bool) -> Nav {
    let mut nav = Nav::Stay;
    unlock::form_column(ui, |ui| {
        ui.heading("pwdv");
        ui.label("Vault locale di password cifrato.");
        ui.add_space(16.0);
        ui.label("File del vault");
        let field = ui.add(egui::TextEdit::singleline(path_input).desired_width(f32::INFINITY));
        if std::mem::take(focus) {
            field.request_focus();
        }
        let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        let can_open = !path_input.trim().is_empty();
        ui.add_space(8.0);
        let clicked = ui.add_enabled(can_open, egui::Button::new("Apri")).clicked();
        if can_open && (enter || clicked) {
            nav = Nav::Open;
        }
    });
    nav
}

fn error_screen(ui: &mut egui::Ui, message: &str) -> Nav {
    let mut nav = Nav::Stay;
    unlock::form_column(ui, |ui| {
        ui.heading("Errore");
        ui.add_space(8.0);
        ui.colored_label(ui.visuals().error_fg_color, message);
        ui.add_space(16.0);
        if ui.button("Torna all'inizio").clicked() {
            nav = Nav::Back;
        }
    });
    nav
}

/// Messaggio per l'utente. Non contiene segreti e, come `VaultError`, non
/// distingue password errata da file manomesso.
pub fn describe(err: &VaultError) -> String {
    match err {
        VaultError::BadMagic => "Il file non è un vault pwdv.".to_owned(),
        VaultError::UnsupportedVersion(v) => format!("Versione del formato non supportata ({v})."),
        VaultError::Truncated => "Il file è troncato.".to_owned(),
        VaultError::AuthFailed => unlock::AUTH_FAILED.to_owned(),
        VaultError::Malformed => {
            "Il contenuto del vault non è valido o ha una versione non supportata.".to_owned()
        }
        VaultError::Conflict => "Il file del vault è stato riscritto da un altro programma \
             dopo l'apertura: salvare cancellerebbe quelle modifiche."
            .to_owned(),
        VaultError::Kdf(_) => "Errore nella derivazione della chiave.".to_owned(),
        VaultError::Io(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            "Esiste già un file in questo percorso.".to_owned()
        }
        VaultError::Io(e) => format!("Errore di I/O ({e})."),
    }
}

/// Stesso default della CLI.
fn default_vault_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".vault.pwdv"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::ClipboardBackend;
    use pwdv_core::store;
    use std::cell::RefCell;
    use std::fs;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct Shared(Rc<RefCell<Option<String>>>);

    impl ClipboardBackend for Shared {
        fn set_secret(&mut self, text: &str) -> Result<(), String> {
            *self.0.borrow_mut() = Some(text.to_owned());
            Ok(())
        }

        fn get(&mut self) -> Option<Zeroizing<String>> {
            self.0.borrow().clone().map(Zeroizing::new)
        }

        fn clear(&mut self) -> Result<(), String> {
            *self.0.borrow_mut() = None;
            Ok(())
        }
    }

    /// App con un vault vuoto appena creato e già aperto (KDF di default).
    fn unlocked_app(tag: &str, now: Now) -> (PwdvApp, Shared, PathBuf) {
        let dir = std::env::temp_dir().join(format!("pwdv-gui-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.pwdv");
        let data = VaultData::default();
        let key = store::create(&path, b"pw", &data).unwrap();

        let clipboard = Shared::default();
        let mut app = PwdvApp::with_clipboard(Clipboard::with_backend(Box::new(clipboard.clone())));
        app.path = path.clone();
        app.state = AppState::Unlocked(Box::new(Session::new(path, key, data)));
        app.idle = IdleTimer::new(security::DEFAULT_AUTOLOCK, now);
        (app, clipboard, dir)
    }

    #[test]
    fn inactivity_locks_the_vault_after_the_timeout() {
        let ctx = egui::Context::default();
        let now = Now::current();
        let (mut app, _clipboard, dir) = unlocked_app("idle", now);

        app.tick(&ctx, now.plus(Duration::from_secs(299)));
        assert!(matches!(app.state, AppState::Unlocked(_)));

        app.tick(&ctx, now.plus(Duration::from_secs(300)));
        assert!(matches!(app.state, AppState::Unlocking));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn manual_lock_drops_the_session_and_clears_the_clipboard() {
        let ctx = egui::Context::default();
        let now = Now::current();
        let (mut app, clipboard, dir) = unlocked_app("manual", now);
        app.clipboard.copy("segreto", now).unwrap();
        assert_eq!(clipboard.0.borrow().as_deref(), Some("segreto"));

        app.lock(&ctx, LockReason::Manual);
        assert!(matches!(app.state, AppState::Unlocking));
        assert_eq!(*clipboard.0.borrow(), None);

        // Bloccare di nuovo non fa niente: non c'è più una sessione.
        assert!(app.close_session().is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}

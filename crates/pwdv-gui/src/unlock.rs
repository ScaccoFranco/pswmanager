//! Schermate di sblocco e di creazione del vault.

use std::path::Path;
use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

/// Il campo non accetta più caratteri di così.
pub const MAX_PASSWORD_CHARS: usize = 256;
/// Capacità riservata ai buffer: 4 byte coprono qualunque carattere UTF-8.
/// Una `String` che cresce rialloca e libera il buffer vecchio senza azzerarlo;
/// con la capacità già riservata e il limite di caratteri non succede mai.
pub const PASSWORD_CAPACITY: usize = MAX_PASSWORD_CHARS * 4;

const PASSWORD_ID: &str = "pwdv-master-password";
const CONFIRM_ID: &str = "pwdv-master-confirm";

/// Unico messaggio per password errata e file manomesso.
pub const AUTH_FAILED: &str = "Password errata o file danneggiato.";

/// Cosa chiede l'utente in questo frame.
pub enum FormAction {
    Idle,
    Submit(Zeroizing<String>),
    Back,
}

/// Campi password condivisi da sblocco e creazione. Niente `Debug` né `Clone`.
pub struct PasswordForm {
    password: String,
    confirm: String,
    notice: Option<String>,
    /// Messaggio informativo, non un errore: per esempio "Vault bloccato."
    info: Option<String>,
    /// Tentativi di sblocco falliti consecutivi. Cambiare schermata non li azzera.
    failures: u32,
    retry_at: Option<Instant>,
    wants_focus: bool,
    /// Enter nel primo campo della creazione: il focus passa alla conferma
    /// solo dopo che questa ha processato il frame, altrimenti consumerebbe
    /// lo stesso Enter e perderebbe subito il focus.
    confirm_focus: bool,
}

impl Default for PasswordForm {
    fn default() -> Self {
        PasswordForm {
            password: String::with_capacity(PASSWORD_CAPACITY),
            confirm: String::with_capacity(PASSWORD_CAPACITY),
            notice: None,
            info: None,
            failures: 0,
            retry_at: None,
            wants_focus: true,
            confirm_focus: false,
        }
    }
}

impl PasswordForm {
    /// Campi azzerati e focus sulla password, per una nuova schermata.
    pub fn reset(&mut self, ctx: &egui::Context) {
        self.wipe(ctx);
        self.notice = None;
        self.info = None;
        self.wants_focus = true;
        self.confirm_focus = false;
    }

    pub fn show_info(&mut self, text: String) {
        self.info = Some(text);
    }

    /// Sblocco o creazione riusciti: si azzera anche il conteggio dei tentativi.
    pub fn succeeded(&mut self, ctx: &egui::Context) {
        self.reset(ctx);
        self.failures = 0;
        self.retry_at = None;
    }

    pub fn failed(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        self.retry_at = retry_delay(self.failures).and_then(|d| now.checked_add(d));
        self.notice = Some(AUTH_FAILED.to_owned());
        self.wants_focus = true;
    }

    fn retry_remaining(&self, now: Instant) -> Option<Duration> {
        self.retry_at
            .map(|at| at.saturating_duration_since(now))
            .filter(|d| !d.is_zero())
    }

    /// Copia la password per il worker e azzera entrambi i campi. La copia ha
    /// la capacità esatta, quindi non rialloca; il worker la azzera dopo l'uso.
    fn take_password(&mut self, ctx: &egui::Context) -> Zeroizing<String> {
        let password = Zeroizing::new(self.password.as_str().to_owned());
        self.wipe(ctx);
        self.notice = None;
        password
    }

    fn wipe(&mut self, ctx: &egui::Context) {
        wipe(&mut self.password);
        wipe(&mut self.confirm);
        forget_undo(ctx, PASSWORD_ID);
        forget_undo(ctx, CONFIRM_ID);
    }
}

/// Ritardo prima di poter riprovare dopo `failures` fallimenti consecutivi:
/// nessuno per i primi due, poi 1 s, 2 s e 4 s per ogni tentativo successivo.
fn retry_delay(failures: u32) -> Option<Duration> {
    match failures {
        0..=2 => None,
        3 => Some(Duration::from_secs(1)),
        4 => Some(Duration::from_secs(2)),
        _ => Some(Duration::from_secs(4)),
    }
}

/// `zeroize` azzera l'intera capacità e lascia la stringa vuota senza
/// liberarla; `clear` è ridondante ma è la regola.
fn wipe(buf: &mut String) {
    buf.zeroize();
    buf.clear();
}

/// Lo stato di undo di egui conserva copie di quanto digitato: dopo l'invio lo
/// si scarta. Quelle copie sono interne a egui e vengono liberate senza essere
/// azzerate.
pub fn forget_undo(ctx: &egui::Context, id: &str) {
    let id = egui::Id::new(id);
    if let Some(mut state) = egui::text_edit::TextEditState::load(ctx, id) {
        state.clear_undoer();
        state.store(ctx, id);
    }
}

pub fn unlock_screen(
    ui: &mut egui::Ui,
    form: &mut PasswordForm,
    path: &Path,
    busy: bool,
) -> FormAction {
    let wait = form.retry_remaining(Instant::now());
    let mut action = FormAction::Idle;

    form_column(ui, |ui| {
        ui.heading("Sblocca il vault");
        ui.weak(path.display().to_string());
        ui.add_space(16.0);

        let field = ui.add_enabled(
            !busy,
            password_field(&mut form.password, PASSWORD_ID, "Master password"),
        );
        if form.wants_focus && !busy {
            field.request_focus();
            form.wants_focus = false;
        }
        let enter = submitted(ui, &field);
        let can_submit = !busy && wait.is_none() && !form.password.is_empty();
        ui.add_space(8.0);
        let clicked = ui
            .add_enabled(can_submit, egui::Button::new("Sblocca"))
            .clicked();

        if can_submit && (enter || clicked) {
            action = FormAction::Submit(form.take_password(ui.ctx()));
        } else if enter {
            form.wants_focus = true;
        }

        ui.add_space(8.0);
        if busy {
            progress(ui, "Sblocco in corso…");
        } else {
            if let Some(wait) = wait {
                ui.label(format!(
                    "Troppi tentativi falliti: riprova tra {} s.",
                    wait.as_millis().div_ceil(1000)
                ));
                ui.ctx()
                    .request_repaint_after(wait.min(Duration::from_millis(250)));
            }
            if let Some(info) = &form.info {
                ui.label(info);
            }
            notice(ui, form);
        }

        ui.add_space(16.0);
        if ui
            .add_enabled(!busy, egui::Button::new("Cambia vault"))
            .clicked()
        {
            action = FormAction::Back;
        }
    });
    action
}

pub fn create_screen(
    ui: &mut egui::Ui,
    form: &mut PasswordForm,
    path: &Path,
    busy: bool,
) -> FormAction {
    let mut action = FormAction::Idle;

    form_column(ui, |ui| {
        ui.heading("Crea un nuovo vault");
        ui.weak(format!("Nessun vault in {}.", path.display()));
        ui.add_space(12.0);
        ui.colored_label(
            ui.visuals().warn_fg_color,
            "La master password non è recuperabile: se la dimentichi, \
             i dati del vault sono persi per sempre.",
        );
        ui.add_space(12.0);

        let first = ui.add_enabled(
            !busy,
            password_field(&mut form.password, PASSWORD_ID, "Master password"),
        );
        if form.wants_focus && !busy {
            first.request_focus();
            form.wants_focus = false;
        }
        if submitted(ui, &first) {
            form.confirm_focus = true;
        }
        ui.add_space(4.0);
        let second = ui.add_enabled(
            !busy,
            password_field(&mut form.confirm, CONFIRM_ID, "Conferma master password"),
        );
        if form.confirm_focus && !busy {
            second.request_focus();
            form.confirm_focus = false;
        }
        let enter = submitted(ui, &second);
        let can_submit = !busy && !form.password.is_empty() && !form.confirm.is_empty();
        ui.add_space(8.0);
        let clicked = ui
            .add_enabled(can_submit, egui::Button::new("Crea vault"))
            .clicked();

        if can_submit && (enter || clicked) {
            if form.password == form.confirm {
                action = FormAction::Submit(form.take_password(ui.ctx()));
            } else {
                form.wipe(ui.ctx());
                form.notice = Some("Le password non coincidono.".to_owned());
                form.wants_focus = true;
            }
        } else if enter {
            form.wants_focus = true;
        }

        ui.add_space(8.0);
        if busy {
            progress(ui, "Creazione del vault in corso…");
        } else {
            notice(ui, form);
        }

        ui.add_space(16.0);
        if ui.add_enabled(!busy, egui::Button::new("Indietro")).clicked() {
            action = FormAction::Back;
        }
    });
    action
}

/// Campo sempre mascherato, senza toggle di visibilità.
fn password_field<'a>(buf: &'a mut String, id: &str, hint: &'static str) -> egui::TextEdit<'a> {
    egui::TextEdit::singleline(buf)
        .id(egui::Id::new(id))
        .password(true)
        .char_limit(MAX_PASSWORD_CHARS)
        .hint_text(hint)
        .desired_width(f32::INFINITY)
}

/// Enter in un campo a riga singola: egui gli toglie il focus nello stesso frame.
fn submitted(ui: &egui::Ui, field: &egui::Response) -> bool {
    field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
}

fn progress(ui: &mut egui::Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.spinner();
        ui.label(text);
    });
}

fn notice(ui: &mut egui::Ui, form: &PasswordForm) {
    if let Some(text) = &form.notice {
        ui.colored_label(ui.visuals().error_fg_color, text);
    }
}

/// Colonna centrata di larghezza fissa per le schermate senza vault aperto.
pub fn form_column(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    const WIDTH: f32 = 380.0;
    let width = WIDTH.min(ui.available_width());
    let side = (ui.available_width() - width) / 2.0;
    ui.add_space(ui.available_height() * 0.18);
    ui.horizontal_top(|ui| {
        ui.add_space(side);
        ui.vertical(|ui| {
            ui.set_width(width);
            add_contents(ui);
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_starts_at_the_third_failure_and_caps_at_four_seconds() {
        let secs: Vec<Option<u64>> = (0..8).map(|n| retry_delay(n).map(|d| d.as_secs())).collect();
        assert_eq!(secs, [None, None, None, Some(1), Some(2), Some(4), Some(4), Some(4)]);
        assert_eq!(retry_delay(u32::MAX), Some(Duration::from_secs(4)));
    }

    #[test]
    fn failures_block_retries_until_success() {
        let ctx = egui::Context::default();
        let mut form = PasswordForm::default();
        let now = Instant::now();

        form.failed(now);
        form.failed(now);
        assert!(form.retry_remaining(now).is_none());

        form.failed(now);
        assert_eq!(form.retry_remaining(now), Some(Duration::from_secs(1)));
        assert!(form.retry_remaining(now + Duration::from_secs(1)).is_none());

        form.failed(now);
        assert_eq!(form.retry_remaining(now), Some(Duration::from_secs(2)));

        form.reset(&ctx);
        assert_eq!(form.failures, 4, "cambiare schermata non azzera i tentativi");

        form.succeeded(&ctx);
        assert_eq!(form.failures, 0);
        assert!(form.retry_remaining(now).is_none());
    }

    #[test]
    fn take_password_copies_then_wipes_both_fields_keeping_capacity() {
        let ctx = egui::Context::default();
        let mut form = PasswordForm::default();
        form.password.push_str("hunter2");
        form.confirm.push_str("hunter2");

        let taken = form.take_password(&ctx);
        assert_eq!(taken.as_str(), "hunter2");
        assert!(form.password.is_empty() && form.confirm.is_empty());
        assert!(form.password.capacity() >= PASSWORD_CAPACITY);
        assert!(form.confirm.capacity() >= PASSWORD_CAPACITY);
    }

    #[test]
    fn buffer_does_not_reallocate_up_to_the_char_limit() {
        let mut form = PasswordForm::default();
        let before = form.password.as_ptr();
        form.password.extend(std::iter::repeat_n('𝄞', MAX_PASSWORD_CHARS));
        assert_eq!(form.password.as_ptr(), before);
    }
}

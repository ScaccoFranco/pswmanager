//! Schermate di sblocco e di creazione del vault.

use std::path::Path;
use std::time::{Duration, Instant};

use eframe::egui;
use pwdv_core::{hardening, policy};
use zeroize::{Zeroize, Zeroizing};

use crate::theme::{self, WideButton};

/// Lunghezza massima di una password, uguale a quella della CLI.
pub const MAX_PASSWORD_CHARS: usize = policy::MAX_MASTER_CHARS;
/// Il campo della master password accetta un carattere oltre il limite: egui
/// tronca il testo incollato in silenzio, e quel carattere in più permette di
/// accorgersene e rifiutare la password con un messaggio invece di inviarne
/// una versione troncata.
const MASTER_FIELD_CHARS: usize = MAX_PASSWORD_CHARS + 1;
/// Capacità riservata ai buffer: 4 byte coprono qualunque carattere UTF-8.
/// Una `String` che cresce rialloca e libera il buffer vecchio senza azzerarlo;
/// con la capacità già riservata e il limite di caratteri non succede mai.
pub const PASSWORD_CAPACITY: usize = MASTER_FIELD_CHARS * 4;

/// Mostrato quando la password supera il limite, allo sblocco e alla creazione.
fn too_long_message() -> String {
    format!(
        "La master password supera i {} caratteri e non viene troncata.",
        MAX_PASSWORD_CHARS
    )
}

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
        let password = String::with_capacity(PASSWORD_CAPACITY);
        let confirm = String::with_capacity(PASSWORD_CAPACITY);
        // Bloccati in RAM una volta sola: la capacità non cambia mai (ADR 0009).
        hardening::lock_string(&password);
        hardening::lock_string(&confirm);
        PasswordForm {
            password,
            confirm,
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
        let mut password = Zeroizing::new(String::with_capacity(self.password.len()));
        hardening::lock_string(&password);
        password.push_str(&self.password);
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
        path_line(ui, path);
        memory_lock_warning(ui);
        ui.add_space(16.0);
        theme::field_label(ui, "Master password");

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
            .add_wide(can_submit, theme::primary_button("Sblocca"))
            .clicked();

        if can_submit && (enter || clicked) {
            if policy::too_long(&form.password) {
                // Nessun tentativo: non conta per l'attesa dopo gli errori.
                form.wipe(ui.ctx());
                form.notice = Some(too_long_message());
                form.wants_focus = true;
            } else {
                action = FormAction::Submit(form.take_password(ui.ctx()));
            }
        } else if enter {
            form.wants_focus = true;
        }

        ui.add_space(8.0);
        if busy {
            progress(ui, "Sblocco in corso…");
        } else {
            if let Some(wait) = wait {
                ui.colored_label(
                    theme::WARN,
                    format!(
                        "Troppi tentativi falliti: riprova tra {} s.",
                        wait.as_millis().div_ceil(1000)
                    ),
                );
                ui.ctx()
                    .request_repaint_after(wait.min(Duration::from_millis(250)));
            }
            if let Some(info) = &form.info {
                ui.weak(info);
            }
            notice(ui, form);
        }

        ui.add_space(8.0);
        if ui
            .add_enabled(!busy, theme::quiet_button("Cambia vault"))
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
        path_line(ui, path);
        memory_lock_warning(ui);
        ui.add_space(12.0);
        theme::callout(
            ui,
            theme::WARN,
            theme::WARN_DIM,
            "La master password non è recuperabile: se la dimentichi, \
             i dati del vault sono persi per sempre.",
        );
        ui.add_space(12.0);
        theme::field_label(ui, "Master password");

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
        ui.weak(format!(
            "Almeno {} caratteri: una frase di più parole va benissimo.",
            policy::MIN_MASTER_CHARS
        ));
        ui.add_space(4.0);
        theme::field_label(ui, "Conferma");
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
            .add_wide(can_submit, theme::primary_button("Crea vault"))
            .clicked();

        if can_submit && (enter || clicked) {
            match new_master_problem(&form.password, &form.confirm) {
                None => action = FormAction::Submit(form.take_password(ui.ctx())),
                Some(problem) => {
                    form.wipe(ui.ctx());
                    form.notice = Some(problem);
                    form.wants_focus = true;
                }
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

        ui.add_space(8.0);
        if ui
            .add_enabled(!busy, theme::quiet_button("Indietro"))
            .clicked()
        {
            action = FormAction::Back;
        }
    });
    action
}

/// Perché la nuova master password non è accettabile, se non lo è. Il
/// messaggio non contiene la password né la sua lunghezza.
fn new_master_problem(password: &str, confirm: &str) -> Option<String> {
    use policy::Weakness::*;
    if let Err(weakness) = policy::check_new_master(password) {
        Some(match weakness {
            TooShort => format!(
                "La master password deve avere almeno {} caratteri.",
                policy::MIN_MASTER_CHARS
            ),
            TooLong => too_long_message(),
            Common => "Questa password compare in un elenco di password comuni o \
                       trafugate: scegline un'altra."
                .to_owned(),
            Repetitive => "La master password non può essere un blocco ripetuto.".to_owned(),
            Sequential => {
                "La master password non può essere una sequenza come abcd o 1234.".to_owned()
            }
            ContextWord => "La master password non può contenere la parola \"pwdv\".".to_owned(),
        })
    } else if password != confirm {
        Some("Le password non coincidono.".to_owned())
    } else {
        None
    }
}

/// Campo sempre mascherato, senza toggle di visibilità.
fn password_field<'a>(buf: &'a mut String, id: &str, hint: &'static str) -> egui::TextEdit<'a> {
    egui::TextEdit::singleline(buf)
        .id(egui::Id::new(id))
        .password(true)
        .char_limit(MASTER_FIELD_CHARS)
        .hint_text(hint)
        .margin(FIELD_MARGIN)
        .desired_width(f32::INFINITY)
}

/// Margine interno dei campi dei moduli: più ariosi dei campi compatti di egui.
pub const FIELD_MARGIN: egui::Margin = egui::Margin::symmetric(8, 7);

/// Percorso del vault su una riga: se non ci sta viene troncato e il
/// percorso completo compare al passaggio del mouse. Non è un segreto.
fn path_line(ui: &mut egui::Ui, path: &Path) {
    let text = egui::RichText::new(path.display().to_string())
        .small()
        .monospace()
        .color(theme::TEXT_WEAK);
    ui.add(egui::Label::new(text).truncate());
}

/// Avviso se il sistema non ha permesso di bloccare in RAM chiavi e
/// password (ADR 0009): possono finire nello swap.
fn memory_lock_warning(ui: &mut egui::Ui) {
    if hardening::memory_lock_failed() {
        ui.add_space(8.0);
        theme::callout(
            ui,
            theme::WARN,
            theme::WARN_DIM,
            "Il sistema non ha permesso di bloccare in RAM chiavi e password: \
             potrebbero essere scritte nello swap. Usa uno swap cifrato \
             (vedi README, sezione 1).",
        );
    }
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

/// Riquadro centrato di larghezza fissa per le schermate senza vault aperto.
pub fn form_column(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    const WIDTH: f32 = 420.0;
    let width = WIDTH.min(ui.available_width());
    let side = (ui.available_width() - width) / 2.0;
    ui.add_space(ui.available_height() * 0.16);
    ui.horizontal_top(|ui| {
        ui.add_space(side);
        let card = theme::card();
        let inner = width - card.total_margin().sum().x;
        card.show(ui, |ui| {
            ui.vertical(|ui| {
                ui.set_width(inner);
                add_contents(ui);
            });
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_starts_at_the_third_failure_and_caps_at_four_seconds() {
        let secs: Vec<Option<u64>> = (0..8)
            .map(|n| retry_delay(n).map(|d| d.as_secs()))
            .collect();
        assert_eq!(
            secs,
            [
                None,
                None,
                None,
                Some(1),
                Some(2),
                Some(4),
                Some(4),
                Some(4)
            ]
        );
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
        assert_eq!(
            form.failures, 4,
            "cambiare schermata non azzera i tentativi"
        );

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
    fn new_master_must_pass_policy_then_match() {
        let short = "a".repeat(policy::MIN_MASTER_CHARS - 1);
        let ok = "vela rossa sul lago di sera";

        let too_short = new_master_problem(&short, &short).unwrap();
        assert!(too_short.contains("almeno"));
        // La password si controlla per prima: niente indizi sulla conferma.
        assert_eq!(new_master_problem(&short, "x"), Some(too_short));

        let common = new_master_problem("1qaz2wsx3edc4rfv", "1qaz2wsx3edc4rfv").unwrap();
        assert!(common.contains("comuni"));
        assert!(
            !common.contains("1qaz"),
            "il messaggio non cita la password"
        );
        let repeated = "x".repeat(20);
        assert!(new_master_problem(&repeated, &repeated)
            .unwrap()
            .contains("ripetuto"));

        assert_eq!(
            new_master_problem(ok, "x").as_deref(),
            Some("Le password non coincidono.")
        );
        assert_eq!(new_master_problem(ok, ok), None);
    }

    #[test]
    fn buffer_does_not_reallocate_up_to_the_char_limit() {
        let mut form = PasswordForm::default();
        let before = form.password.as_ptr();
        form.password
            .extend(std::iter::repeat_n('𝄞', MASTER_FIELD_CHARS));
        assert_eq!(form.password.as_ptr(), before);
    }

    #[test]
    fn new_master_over_the_limit_is_rejected_not_truncated() {
        let long = "a".repeat(MASTER_FIELD_CHARS);
        assert_eq!(new_master_problem(&long, &long), Some(too_long_message()));
        assert!(policy::too_long(&long));
        assert!(!policy::too_long(&long[..MAX_PASSWORD_CHARS]));
    }
}

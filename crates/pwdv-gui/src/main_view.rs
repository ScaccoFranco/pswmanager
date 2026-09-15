//! Vista principale: lista delle voci a sinistra, dettaglio a destra.

use std::cmp::Ordering;
use std::mem::take;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;
use pwdv_core::store;
use pwdv_core::vault::{Entry, VaultData};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::app::{self, Session};
use crate::security::{Clipboard, Now};
use crate::unlock::{self, MAX_PASSWORD_CHARS, PASSWORD_CAPACITY};

const LIST_WIDTH: f32 = 300.0;
/// Larghezza dei campi del modulo: in una `Grid` la larghezza infinita non ha limite.
const FIELD_WIDTH: f32 = 380.0;
const ROW_HEIGHT: f32 = 40.0;
/// Dopo quanto una password rivelata torna mascherata.
const REVEAL_FOR: Duration = Duration::from_secs(10);
/// Sempre lo stesso numero di pallini: la lunghezza della password non trapela.
const MASK: &str = "••••••••••";
const PASSWORD_ID: &str = "pwdv-entry-password";
/// Cosa pwdv può e non può garantire sul clipboard (vedi il report dello step 8).
const CLIPBOARD_NOTE: &str = "Il clipboard viene svuotato allo scadere, al blocco e alla chiusura, \
     solo se contiene ancora il valore copiato. La copia è marcata come da non conservare \
     nella cronologia degli appunti, ma pwdv non può controllare i programmi che ignorano \
     questa indicazione.";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Search,
    FirstEntry,
    Name,
    DeleteConfirm,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Copied {
    Username,
    Password,
}

enum Mode {
    View,
    /// Modifica della voce selezionata.
    Edit(Draft),
    New(Draft),
}

struct DeleteDialog {
    index: usize,
    typed: String,
}

/// Cosa ha chiesto l'utente in questo frame; applicato dopo il disegno.
enum Action {
    None,
    Select(usize),
    New,
    Edit,
    Cancel,
    Save,
    AskDelete,
    CancelDelete,
    ConfirmDelete,
    Retry,
    Copy(Copied),
    ToggleReveal,
}

/// Stato dei pulsanti "Copia" per la voce mostrata.
struct CopyState<'a> {
    unavailable: Option<&'a str>,
    /// Campo di questa voce copiato per ultimo e secondi alla cancellazione.
    pending: Option<(Copied, u128)>,
    error: Option<String>,
}

/// Stato della vista. Vive dentro la `Session`: bozze comprese, sparisce con lei.
pub struct MainView {
    query: String,
    /// Indici in `entries` che passano il filtro, in ordine alfabetico.
    visible: Vec<usize>,
    selected: Option<usize>,
    mode: Mode,
    reveal_until: Option<Instant>,
    /// Voce e campo dell'ultima copia, per il conto alla rovescia.
    copied: Option<(usize, Copied)>,
    copy_error: Option<String>,
    delete: Option<DeleteDialog>,
    /// Ultimo salvataggio fallito: resta a video finché un salvataggio riesce.
    save_error: Option<String>,
    focus: Option<Focus>,
}

impl MainView {
    pub fn new(data: &VaultData) -> Self {
        let mut view = MainView {
            query: String::new(),
            visible: Vec::new(),
            selected: None,
            mode: Mode::View,
            reveal_until: None,
            copied: None,
            copy_error: None,
            delete: None,
            save_error: None,
            focus: Some(if data.entries.is_empty() {
                Focus::FirstEntry
            } else {
                Focus::Search
            }),
        };
        view.refresh(&data.entries);
        view
    }

    fn refresh(&mut self, entries: &[Entry]) {
        let mut rows: Vec<(usize, &Entry)> = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| matches(&self.query, entry))
            .collect();
        rows.sort_by(|a, b| alphabetical(a.1, b.1));
        self.visible = rows.into_iter().map(|(index, _)| index).collect();
    }

    fn revealed(&self, now: Instant) -> Option<Duration> {
        self.reveal_until
            .and_then(|until| until.checked_duration_since(now))
            .filter(|left| !left.is_zero())
    }

    fn hide(&mut self) {
        self.reveal_until = None;
    }

    /// Scadenze della password rivelata e del conto alla rovescia del
    /// clipboard: finché una è attiva la UI si ridisegna anche senza input.
    fn expire(&mut self, now: Now, ctx: &egui::Context, clipboard: &Clipboard) {
        match self.revealed(now.instant) {
            Some(left) => ctx.request_repaint_after(left.min(Duration::from_millis(250))),
            None => self.reveal_until = None,
        }
        match clipboard.remaining(now) {
            Some(_) => ctx.request_repaint_after(Duration::from_millis(250)),
            None => self.copied = None,
        }
    }

    /// Torna alla visualizzazione. La bozza viene droppata, e quindi azzerata;
    /// lo stato di undo del campo password viene scartato.
    fn close_form(&mut self, ctx: &egui::Context) {
        self.mode = Mode::View;
        self.hide();
        forget_secrets(ctx);
    }
}

/// Bozza di una voce. Contiene la password: niente `Debug`/`Clone`, azzerata al drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Draft {
    name: String,
    username: String,
    password: String,
    url: String,
    notes: String,
}

impl Draft {
    fn empty() -> Self {
        Draft {
            name: String::new(),
            username: String::new(),
            password: String::with_capacity(PASSWORD_CAPACITY),
            url: String::new(),
            notes: String::new(),
        }
    }

    fn of(entry: &Entry) -> Self {
        let mut draft = Draft::empty();
        draft.name.push_str(&entry.name);
        draft.username.push_str(&entry.username);
        draft.password.push_str(&entry.password);
        draft.url.push_str(entry.url.as_deref().unwrap_or_default());
        draft.notes.push_str(entry.notes.as_deref().unwrap_or_default());
        draft
    }

    fn is_blank(&self) -> bool {
        [&self.name, &self.username, &self.password, &self.url, &self.notes]
            .iter()
            .all(|field| field.is_empty())
    }

    fn differs_from(&self, entry: &Entry) -> bool {
        self.name.trim() != entry.name
            || self.username != entry.username
            || self.password != entry.password
            || optional(&self.url) != entry.url.as_deref()
            || optional(&self.notes) != entry.notes.as_deref()
    }

    /// Perché la bozza non si può salvare, se non si può.
    fn problem(&self, entries: &[Entry], editing: Option<usize>) -> Option<&'static str> {
        let name = self.name.trim();
        if name.is_empty() {
            return Some("Il nome è obbligatorio.");
        }
        let taken = entries
            .iter()
            .enumerate()
            .any(|(index, entry)| Some(index) != editing && entry.name == name);
        if taken {
            return Some("Esiste già una voce con questo nome.");
        }
        if self.password.is_empty() {
            return Some("La password è obbligatoria.");
        }
        None
    }

    /// Voce nuova dai campi della bozza, che restano vuoti.
    fn take_entry(&mut self) -> Entry {
        let name = self.name.trim().to_owned();
        self.name.zeroize();
        Entry::new(
            name,
            take(&mut self.username),
            take(&mut self.password),
            non_empty(take(&mut self.url)),
            non_empty(take(&mut self.notes)),
        )
    }

    /// Scrive la bozza sulla voce. I valori vecchi sono azzerati prima di essere liberati.
    fn apply_to(&mut self, entry: &mut Entry) {
        let name = self.name.trim().to_owned();
        self.name.zeroize();
        replace(&mut entry.name, name);
        replace(&mut entry.username, take(&mut self.username));
        replace(&mut entry.password, take(&mut self.password));
        replace_opt(&mut entry.url, non_empty(take(&mut self.url)));
        replace_opt(&mut entry.notes, non_empty(take(&mut self.notes)));
        entry.modified = unix_now();
    }
}

pub fn show(ui: &mut egui::Ui, session: &mut Session, clipboard: &mut Clipboard, now: Now) {
    let ctx = ui.ctx().clone();
    session.view.expire(now, &ctx, clipboard);
    let mut action = Action::None;

    if let Some(error) = &session.view.save_error {
        egui::Panel::top("pwdv-save-error").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    format!("Salvataggio non riuscito. {error} Le modifiche sono solo in memoria."),
                );
                if ui.button("Riprova").clicked() {
                    action = Action::Retry;
                }
            });
            ui.add_space(4.0);
        });
    }

    // Durante modifica ed eliminazione la lista è bloccata: niente cambi di
    // selezione con una bozza aperta.
    let list_enabled = matches!(session.view.mode, Mode::View) && session.view.delete.is_none();
    egui::Panel::left("pwdv-list")
        .resizable(true)
        .default_size(LIST_WIDTH)
        .size_range(220.0..=520.0)
        .show(ui, |ui| {
            ui.add_enabled_ui(list_enabled, |ui| {
                list_panel(ui, &mut session.view, &session.data.entries, &mut action);
            });
        });

    let selected = session.view.selected;
    let copy = CopyState {
        unavailable: clipboard.unavailable(),
        pending: session
            .view
            .copied
            .filter(|(index, _)| Some(*index) == selected)
            .and_then(|(_, which)| {
                clipboard
                    .remaining(now)
                    .map(|left| (which, left.as_millis().div_ceil(1000)))
            }),
        error: session.view.copy_error.clone(),
    };
    egui::CentralPanel::default().show(ui, |ui| {
        detail_panel(ui, &mut session.view, &session.data.entries, now.instant, &copy, &mut action);
    });
    if let Some(dialog) = &mut session.view.delete {
        delete_dialog(&ctx, dialog, &session.data.entries, &mut session.view.focus, &mut action);
    }

    apply(action, session, clipboard, &ctx, now);
}

/// Prima di un blocco. Una bozza valida con modifiche viene confermata come
/// con "Salva"; se ci sono modifiche non ancora su disco (quella bozza o un
/// salvataggio fallito) si salva. Una bozza non valida non è salvabile e va
/// persa. In caso di errore il blocco avviene comunque: lo decide il chiamante.
pub fn save_before_lock(session: &mut Session) -> Result<(), String> {
    let committed = commit(
        &mut session.view.mode,
        session.view.selected,
        &mut session.data.entries,
    )
    .is_some();
    if committed || session.view.save_error.is_some() {
        store::save_with_key(&session.path, &session.key, &session.data)
            .map_err(|e| app::describe(&e))?;
    }
    Ok(())
}

/// Stato di egui che conserva copie di password: l'undo del campo password.
pub fn forget_secrets(ctx: &egui::Context) {
    unlock::forget_undo(ctx, PASSWORD_ID);
}

fn apply(
    action: Action,
    session: &mut Session,
    clipboard: &mut Clipboard,
    ctx: &egui::Context,
    now: Now,
) {
    match action {
        Action::None => {}
        Action::Select(index) => {
            session.view.selected = Some(index);
            session.view.hide();
        }
        Action::New => {
            session.view.mode = Mode::New(Draft::empty());
            session.view.hide();
            session.view.focus = Some(Focus::Name);
        }
        Action::Edit => {
            if let Some(entry) = session.view.selected.and_then(|i| session.data.entries.get(i)) {
                session.view.mode = Mode::Edit(Draft::of(entry));
                session.view.hide();
                session.view.focus = Some(Focus::Name);
            }
        }
        Action::Cancel => session.view.close_form(ctx),
        Action::Save => {
            let view = &mut session.view;
            if let Some(index) = commit(&mut view.mode, view.selected, &mut session.data.entries) {
                view.close_form(ctx);
                view.selected = Some(index);
                view.refresh(&session.data.entries);
                persist(session);
            }
        }
        Action::AskDelete => {
            if let Some(index) = session.view.selected {
                session.view.delete = Some(DeleteDialog {
                    index,
                    typed: String::new(),
                });
                session.view.hide();
                session.view.focus = Some(Focus::DeleteConfirm);
            }
        }
        Action::CancelDelete => session.view.delete = None,
        Action::ConfirmDelete => {
            if let Some(dialog) = session.view.delete.take() {
                if dialog.index < session.data.entries.len() {
                    // La voce rimossa si azzera al drop.
                    session.data.entries.remove(dialog.index);
                    session.view.selected = None;
                    session.view.copied = None;
                    session.view.refresh(&session.data.entries);
                    if session.data.entries.is_empty() {
                        session.view.focus = Some(Focus::FirstEntry);
                    }
                    persist(session);
                }
            }
        }
        Action::Retry => persist(session),
        Action::Copy(which) => {
            let Some(index) = session.view.selected else {
                return;
            };
            let Some(entry) = session.data.entries.get(index) else {
                return;
            };
            let text = match which {
                Copied::Username => &entry.username,
                Copied::Password => &entry.password,
            };
            match clipboard.copy(text, now) {
                Ok(()) => {
                    session.view.copied = Some((index, which));
                    session.view.copy_error = None;
                }
                Err(e) => session.view.copy_error = Some(format!("Copia non riuscita: {e}.")),
            }
        }
        Action::ToggleReveal => {
            session.view.reveal_until = match session.view.revealed(now.instant) {
                Some(_) => None,
                None => now.instant.checked_add(REVEAL_FOR),
            };
        }
    }
}

/// Applica la bozza ai dati e restituisce l'indice della voce salvata, oppure
/// `None` se non c'è niente di valido da salvare.
fn commit(mode: &mut Mode, selected: Option<usize>, entries: &mut Vec<Entry>) -> Option<usize> {
    match mode {
        Mode::New(draft) => {
            if draft.is_blank() || draft.problem(entries, None).is_some() {
                return None;
            }
            entries.push(draft.take_entry());
            Some(entries.len().saturating_sub(1))
        }
        Mode::Edit(draft) => {
            let index = selected?;
            if draft.problem(entries, Some(index)).is_some() {
                return None;
            }
            let entry = entries.get_mut(index)?;
            if !draft.differs_from(entry) {
                return None;
            }
            draft.apply_to(entry);
            Some(index)
        }
        Mode::View => None,
    }
}

/// Unico punto che scrive il vault. Se fallisce, i dati restano in memoria e
/// l'errore resta a video fino al prossimo salvataggio riuscito.
fn persist(session: &mut Session) {
    session.view.save_error = store::save_with_key(&session.path, &session.key, &session.data)
        .err()
        .map(|e| app::describe(&e));
}

fn list_panel(ui: &mut egui::Ui, view: &mut MainView, entries: &[Entry], action: &mut Action) {
    ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
        ui.add_space(8.0);
        let new = ui.add_sized([ui.available_width(), 28.0], egui::Button::new("Nuova voce"));
        if new.clicked() {
            *action = Action::New;
        }
        ui.add_space(8.0);

        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.add_space(8.0);
            let search = ui.add(
                egui::TextEdit::singleline(&mut view.query)
                    .hint_text("Cerca")
                    .desired_width(f32::INFINITY),
            );
            if take_focus(&mut view.focus, Focus::Search) {
                search.request_focus();
            }
            if search.changed() {
                view.refresh(entries);
            }
            ui.add_space(8.0);

            if entries.is_empty() {
                ui.weak("Nessuna voce.");
            } else if view.visible.is_empty() {
                ui.weak("Nessun risultato.");
            } else {
                // Solo le righe visibili vengono disegnate.
                egui::ScrollArea::vertical().auto_shrink(false).show_rows(
                    ui,
                    ROW_HEIGHT,
                    view.visible.len(),
                    |ui, rows| {
                        for &index in view.visible.get(rows).unwrap_or_default() {
                            let Some(entry) = entries.get(index) else {
                                continue;
                            };
                            if entry_row(ui, entry, view.selected == Some(index)).clicked() {
                                *action = Action::Select(index);
                            }
                        }
                    },
                );
            }
        });
    });
}

/// Nome in evidenza, username sotto. Mai la password.
fn entry_row(ui: &mut egui::Ui, entry: &Entry, selected: bool) -> egui::Response {
    let size = egui::vec2(ui.available_width(), ROW_HEIGHT);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, selected, &entry.name)
    });
    if ui.is_rect_visible(rect) {
        let visuals = ui.style().interact_selectable(&response, selected);
        if selected || response.hovered() || response.has_focus() {
            ui.painter()
                .rect_filled(rect, visuals.corner_radius, visuals.weak_bg_fill);
        }
        let inner = rect.shrink2(egui::vec2(8.0, 4.0));
        let painter = ui.painter_at(inner);
        painter.text(
            inner.left_top(),
            egui::Align2::LEFT_TOP,
            &entry.name,
            egui::FontId::proportional(14.0),
            visuals.text_color(),
        );
        painter.text(
            inner.left_bottom(),
            egui::Align2::LEFT_BOTTOM,
            &entry.username,
            egui::FontId::proportional(12.0),
            ui.visuals().weak_text_color(),
        );
    }
    response
}

fn detail_panel(
    ui: &mut egui::Ui,
    view: &mut MainView,
    entries: &[Entry],
    now: Instant,
    copy: &CopyState<'_>,
    action: &mut Action,
) {
    let revealed = view.revealed(now);
    let selected = view.selected;
    match &mut view.mode {
        Mode::New(draft) => edit_form(ui, draft, entries, None, revealed, &mut view.focus, action),
        Mode::Edit(draft) => {
            edit_form(ui, draft, entries, selected, revealed, &mut view.focus, action);
        }
        Mode::View => match selected.and_then(|i| entries.get(i)) {
            Some(entry) => entry_details(ui, entry, revealed, copy, action),
            None if entries.is_empty() => empty_state(ui, &mut view.focus, action),
            None => placeholder(ui, "Seleziona una voce dalla lista."),
        },
    }
}

fn entry_details(
    ui: &mut egui::Ui,
    entry: &Entry,
    revealed: Option<Duration>,
    copy: &CopyState<'_>,
    action: &mut Action,
) {
    ui.horizontal(|ui| {
        ui.heading(&entry.name);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Elimina").clicked() {
                *action = Action::AskDelete;
            }
            if ui.button("Modifica").clicked() {
                *action = Action::Edit;
            }
        });
    });
    ui.separator();
    ui.add_space(4.0);

    egui::Grid::new("pwdv-detail")
        .num_columns(2)
        .spacing([16.0, 10.0])
        .show(ui, |ui| {
            ui.weak("Username");
            ui.horizontal(|ui| {
                ui.label(or_dash(&entry.username));
                copy_button(ui, Copied::Username, copy, action);
            });
            ui.end_row();

            ui.weak("Password");
            ui.horizontal(|ui| {
                if revealed.is_some() {
                    ui.monospace(&entry.password);
                } else {
                    ui.label(MASK);
                }
                reveal_button(ui, revealed, action);
                copy_button(ui, Copied::Password, copy, action);
            });
            ui.end_row();

            ui.weak("URL");
            ui.label(or_dash(entry.url.as_deref().unwrap_or_default()));
            ui.end_row();

            ui.weak("Note");
            ui.label(or_dash(entry.notes.as_deref().unwrap_or_default()));
            ui.end_row();

            ui.weak("Creata");
            ui.label(format_timestamp(entry.created));
            ui.end_row();

            ui.weak("Modificata");
            ui.label(format_timestamp(entry.modified));
            ui.end_row();
        });

    ui.add_space(16.0);
    ui.set_max_width(560.0);
    if let Some(reason) = copy.unavailable {
        ui.colored_label(
            ui.visuals().warn_fg_color,
            format!("Clipboard di sistema non disponibile ({reason}): i pulsanti Copia sono disattivati."),
        );
    }
    if let Some(error) = &copy.error {
        ui.colored_label(ui.visuals().error_fg_color, error);
    }
    if copy.pending.is_some() {
        ui.weak(CLIPBOARD_NOTE);
    }
}

fn edit_form(
    ui: &mut egui::Ui,
    draft: &mut Draft,
    entries: &[Entry],
    editing: Option<usize>,
    revealed: Option<Duration>,
    focus: &mut Option<Focus>,
    action: &mut Action,
) {
    ui.set_max_width(560.0);
    ui.heading(if editing.is_some() {
        "Modifica voce"
    } else {
        "Nuova voce"
    });
    ui.separator();
    ui.add_space(4.0);

    egui::Grid::new("pwdv-edit")
        .num_columns(2)
        .spacing([16.0, 8.0])
        .show(ui, |ui| {
            ui.label("Nome");
            let name = ui.add(egui::TextEdit::singleline(&mut draft.name).desired_width(FIELD_WIDTH));
            if take_focus(focus, Focus::Name) {
                name.request_focus();
            }
            ui.end_row();

            ui.label("Username");
            ui.add(egui::TextEdit::singleline(&mut draft.username).desired_width(FIELD_WIDTH));
            ui.end_row();

            ui.label("Password");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut draft.password)
                        .id(egui::Id::new(PASSWORD_ID))
                        .password(revealed.is_none())
                        .char_limit(MAX_PASSWORD_CHARS)
                        .desired_width(260.0),
                );
                reveal_button(ui, revealed, action);
            });
            ui.end_row();

            ui.label("URL");
            ui.add(egui::TextEdit::singleline(&mut draft.url).desired_width(FIELD_WIDTH));
            ui.end_row();

            ui.label("Note");
            ui.add(
                egui::TextEdit::multiline(&mut draft.notes)
                    .desired_rows(4)
                    .desired_width(FIELD_WIDTH),
            );
            ui.end_row();
        });

    ui.add_space(12.0);
    let changed = match editing {
        Some(index) => entries.get(index).is_some_and(|entry| draft.differs_from(entry)),
        None => !draft.is_blank(),
    };
    let problem = draft.problem(entries, editing);
    ui.horizontal(|ui| {
        let save = egui::Button::new("Salva");
        if ui.add_enabled(changed && problem.is_none(), save).clicked() {
            *action = Action::Save;
        }
        if ui.button("Annulla").clicked() {
            *action = Action::Cancel;
        }
    });
    match (changed, problem) {
        (true, Some(problem)) => {
            ui.colored_label(ui.visuals().warn_fg_color, problem);
        }
        (false, _) if editing.is_some() => {
            ui.weak("Nessuna modifica da salvare.");
        }
        _ => {}
    }
}

fn reveal_button(ui: &mut egui::Ui, revealed: Option<Duration>, action: &mut Action) {
    let label = match revealed {
        Some(left) => format!("Nascondi ({} s)", left.as_millis().div_ceil(1000)),
        None => "Mostra".to_owned(),
    };
    if ui.button(label).clicked() {
        *action = Action::ToggleReveal;
    }
}

/// Pulsante "Copia" con il conto alla rovescia della cancellazione accanto.
fn copy_button(ui: &mut egui::Ui, which: Copied, copy: &CopyState<'_>, action: &mut Action) {
    let button = egui::Button::new("Copia");
    if ui.add_enabled(copy.unavailable.is_none(), button).clicked() {
        *action = Action::Copy(which);
    }
    if let Some((pending, secs)) = copy.pending {
        if pending == which {
            ui.weak(format!("Copiato · si cancella tra {secs} s"));
        }
    }
}

fn empty_state(ui: &mut egui::Ui, focus: &mut Option<Focus>, action: &mut Action) {
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() * 0.3);
        ui.heading("Il vault è vuoto");
        ui.label("Aggiungi la prima voce per iniziare.");
        ui.add_space(12.0);
        let button = ui.button("Crea la prima voce");
        if take_focus(focus, Focus::FirstEntry) {
            button.request_focus();
        }
        if button.clicked() {
            *action = Action::New;
        }
    });
}

fn placeholder(ui: &mut egui::Ui, text: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() * 0.3);
        ui.weak(text);
    });
}

/// Conferma modale: bisogna digitare il nome esatto della voce.
fn delete_dialog(
    ctx: &egui::Context,
    dialog: &mut DeleteDialog,
    entries: &[Entry],
    focus: &mut Option<Focus>,
    action: &mut Action,
) {
    let Some(entry) = entries.get(dialog.index) else {
        *action = Action::CancelDelete;
        return;
    };
    let modal = egui::Modal::new(egui::Id::new("pwdv-delete")).show(ctx, |ui| {
        ui.set_width(380.0);
        ui.heading("Eliminare la voce?");
        ui.add_space(8.0);
        ui.label(format!(
            "L'operazione non si può annullare. Per confermare digita il nome della voce: «{}»",
            entry.name
        ));
        ui.add_space(8.0);
        let field = ui.add(egui::TextEdit::singleline(&mut dialog.typed).desired_width(f32::INFINITY));
        if take_focus(focus, Focus::DeleteConfirm) {
            field.request_focus();
        }
        let confirmed = dialog.typed == entry.name;
        let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let text = egui::RichText::new("Elimina").color(ui.visuals().error_fg_color);
            let clicked = ui.add_enabled(confirmed, egui::Button::new(text)).clicked();
            if confirmed && (clicked || enter) {
                *action = Action::ConfirmDelete;
            }
            if ui.button("Annulla").clicked() {
                *action = Action::CancelDelete;
            }
        });
    });
    if modal.should_close() && matches!(action, Action::None) {
        *action = Action::CancelDelete;
    }
}

fn take_focus(focus: &mut Option<Focus>, which: Focus) -> bool {
    let hit = *focus == Some(which);
    if hit {
        *focus = None;
    }
    hit
}

/// Ogni parola della ricerca deve comparire in nome, username o url, con le
/// lettere nell'ordine giusto ma non per forza vicine ("gthb" trova "GitHub").
/// Maiuscole e minuscole sono indifferenti. Note e password non si cercano.
fn matches(query: &str, entry: &Entry) -> bool {
    query.split_whitespace().all(|term| {
        fuzzy(term, &entry.name)
            || fuzzy(term, &entry.username)
            || entry.url.as_deref().is_some_and(|url| fuzzy(term, url))
    })
}

fn fuzzy(term: &str, text: &str) -> bool {
    let mut text = lowercase(text);
    lowercase(term).all(|c| text.any(|t| t == c))
}

fn lowercase(s: &str) -> impl Iterator<Item = char> + '_ {
    s.chars().flat_map(char::to_lowercase)
}

/// Alfabetico senza distinzione di maiuscole; a parità, ordine esatto.
fn alphabetical(a: &Entry, b: &Entry) -> Ordering {
    lowercase(&a.name)
        .cmp(lowercase(&b.name))
        .then_with(|| a.name.cmp(&b.name))
        .then_with(|| a.username.cmp(&b.username))
}

/// "AAAA-MM-GG HH:MM UTC". Senza dipendenze per il fuso orario locale, l'ora è in UTC.
fn format_timestamp(secs: u64) -> String {
    let rest = secs % 86_400;
    match i64::try_from(secs / 86_400) {
        Ok(days) => {
            let (year, month, day) = civil_from_days(days);
            format!(
                "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
                rest / 3_600,
                rest % 3_600 / 60
            )
        }
        Err(_) => "—".to_owned(),
    }
}

/// Giorni dal 1970-01-01 → (anno, mese, giorno) nel calendario gregoriano.
/// Algoritmo `civil_from_days` di Howard Hinnant.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn optional(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() {
        "—"
    } else {
        s
    }
}

fn replace(slot: &mut String, value: String) {
    slot.zeroize();
    *slot = value;
}

fn replace_opt(slot: &mut Option<String>, value: Option<String>) {
    slot.zeroize();
    *slot = value;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::ClipboardBackend;
    use std::fs;
    use std::path::PathBuf;
    use zeroize::Zeroizing;

    /// Clipboard che non tocca quello di sistema.
    struct NoClipboard;

    impl ClipboardBackend for NoClipboard {
        fn set_secret(&mut self, _text: &str) -> Result<(), String> {
            Ok(())
        }

        fn get(&mut self) -> Option<Zeroizing<String>> {
            None
        }

        fn clear(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    fn entry(name: &str, username: &str, url: Option<&str>) -> Entry {
        Entry::new(
            name.to_owned(),
            username.to_owned(),
            "segreto".to_owned(),
            url.map(str::to_owned),
            Some("appunti riservati".to_owned()),
        )
    }

    /// Vault vuoto appena creato in una directory temporanea (KDF di default).
    fn new_session(tag: &str) -> (Session, PathBuf) {
        let dir = std::env::temp_dir().join(format!("pwdv-gui-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.pwdv");
        let data = VaultData::default();
        let key = store::create(&path, b"pw", &data).unwrap();
        let view = MainView::new(&data);
        (
            Session {
                path,
                key,
                data,
                view,
            },
            dir,
        )
    }

    fn draft(name: &str, password: &str) -> Draft {
        let mut draft = Draft::empty();
        draft.name.push_str(name);
        draft.password.push_str(password);
        draft
    }

    #[test]
    fn search_is_fuzzy_on_name_username_and_url() {
        let github = entry("GitHub", "mario.rossi", Some("https://github.com"));
        assert!(matches("", &github));
        assert!(matches("gthb", &github));
        assert!(matches("GIT", &github));
        assert!(matches("rossi", &github));
        assert!(matches("hub.com", &github));
        assert!(matches("git rossi", &github));
        assert!(!matches("bhtg", &github), "le lettere devono essere in ordine");
        assert!(!matches("git bianchi", &github), "ogni parola deve comparire");
    }

    #[test]
    fn search_ignores_notes_and_password() {
        let banca = entry("Banca", "utente", None);
        assert!(!matches("segreto", &banca));
        assert!(!matches("riservati", &banca));
    }

    #[test]
    fn list_is_alphabetical_ignoring_case_and_follows_the_filter() {
        let entries = vec![
            entry("posta", "a", None),
            entry("Banca", "b", None),
            entry("amazon", "c", None),
            entry("Zeta", "d", None),
        ];
        let mut view = MainView::new(&VaultData::default());
        view.refresh(&entries);
        assert_eq!(view.visible, [2, 1, 0, 3]);

        view.query.push_str("ta");
        view.refresh(&entries);
        assert_eq!(view.visible, [0, 3]);
    }

    #[test]
    fn timestamps_are_formatted_in_utc() {
        // Valori attesi da `date -u -d @<secondi> '+%Y-%m-%d %H:%M'`.
        for (secs, expected) in [
            (0, "1970-01-01 00:00"),
            (951_782_400, "2000-02-29 00:00"),
            (1_000_000_000, "2001-09-09 01:46"),
            (1_757_795_580, "2025-09-13 20:33"),
            (4_102_444_799, "2099-12-31 23:59"),
        ] {
            assert_eq!(format_timestamp(secs), format!("{expected} UTC"));
        }
    }

    #[test]
    fn draft_validation() {
        let entries = vec![entry("GitHub", "u", None), entry("Posta", "u", None)];
        let mut draft = Draft::empty();
        assert!(draft.is_blank());
        assert_eq!(draft.problem(&entries, None), Some("Il nome è obbligatorio."));

        draft.name.push_str("  Posta ");
        assert_eq!(draft.problem(&entries, None), Some("Esiste già una voce con questo nome."));
        assert_eq!(
            draft.problem(&entries, Some(1)),
            Some("La password è obbligatoria."),
            "una voce può tenere il proprio nome"
        );

        draft.password.push_str("pw");
        assert_eq!(draft.problem(&entries, Some(1)), None);
    }

    #[test]
    fn draft_detects_changes_and_applies_them() {
        let mut github = entry("GitHub", "mario", Some("https://github.com"));
        github.modified = 0;
        let mut draft = Draft::of(&github);
        assert!(!draft.differs_from(&github));

        draft.url.clear();
        draft.username.push_str(".rossi");
        assert!(draft.differs_from(&github));

        draft.apply_to(&mut github);
        assert_eq!(github.username, "mario.rossi");
        assert_eq!(github.url, None);
        assert_eq!(github.password, "segreto");
        assert!(github.modified > 0);
    }

    #[cfg(unix)]
    #[test]
    fn failed_save_keeps_the_change_in_memory_until_retry() {
        use std::os::unix::fs::PermissionsExt;

        let (mut session, dir) = new_session("savefail");
        let mut clipboard = Clipboard::with_backend(Box::new(NoClipboard));
        let ctx = egui::Context::default();
        let now = Now::current();
        session.view.mode = Mode::New(draft("Nuova", "pw-nuova"));

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        apply(Action::Save, &mut session, &mut clipboard, &ctx, now);
        let failed = session.view.save_error.is_some();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(failed, "la directory in sola lettura deve far fallire il salvataggio");
        assert_eq!(session.data.entries.len(), 1, "la modifica resta in memoria");
        assert!(store::load(&session.path, b"pw").unwrap().entries.is_empty());

        apply(Action::Retry, &mut session, &mut clipboard, &ctx, now);
        assert!(session.view.save_error.is_none());
        assert_eq!(store::load(&session.path, b"pw").unwrap().entries.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_before_lock_commits_a_valid_draft_and_drops_an_invalid_one() {
        let (mut session, dir) = new_session("beforelock");

        session.view.mode = Mode::New(draft("Bozza", "pw-bozza"));
        save_before_lock(&mut session).unwrap();
        assert_eq!(store::load(&session.path, b"pw").unwrap().entries.len(), 1);

        // Senza password la bozza non è salvabile: niente scrittura.
        let before = fs::read(&session.path).unwrap();
        session.view.mode = Mode::New(draft("Incompleta", ""));
        save_before_lock(&mut session).unwrap();
        assert_eq!(fs::read(&session.path).unwrap(), before);
        let _ = fs::remove_dir_all(&dir);
    }
}

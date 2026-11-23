//! Aspetto della GUI: palette scura, angoli vivi, spaziature e qualche
//! componente condiviso. Solo colori e forme: nessun segreto passa di qui.

use eframe::egui::{self, Color32, CornerRadius, FontId, Margin, Stroke, TextStyle};

/// Fondo della zona di lavoro.
pub const BG: Color32 = Color32::from_rgb(0x13, 0x14, 0x16);
/// Barre e pannello laterale: un gradino sopra il fondo.
pub const PANEL: Color32 = Color32::from_rgb(0x18, 0x19, 0x1c);
/// Riquadri, pulsanti a riposo.
pub const SURFACE: Color32 = Color32::from_rgb(0x1f, 0x21, 0x25);
pub const HOVER: Color32 = Color32::from_rgb(0x29, 0x2c, 0x31);
pub const PRESSED: Color32 = Color32::from_rgb(0x32, 0x36, 0x3c);
/// Fondo dei campi di testo: più scuro del riquadro che li contiene.
pub const INPUT: Color32 = Color32::from_rgb(0x0e, 0x0f, 0x11);
pub const BORDER: Color32 = Color32::from_rgb(0x2b, 0x2e, 0x33);
pub const BORDER_STRONG: Color32 = Color32::from_rgb(0x3d, 0x41, 0x48);

pub const TEXT: Color32 = Color32::from_rgb(0xdd, 0xe0, 0xe4);
pub const TEXT_WEAK: Color32 = Color32::from_rgb(0x8d, 0x93, 0x9b);
pub const TEXT_FAINT: Color32 = Color32::from_rgb(0x5f, 0x64, 0x6b);

/// Blu dei pulsanti principali e della selezione. Testo bianco sopra: ~5:1.
pub const ACCENT: Color32 = Color32::from_rgb(0x2d, 0x6f, 0xb0);
pub const ACCENT_BRIGHT: Color32 = Color32::from_rgb(0x5a, 0xa2, 0xe6);
/// Fondo della riga selezionata nella lista.
pub const ACCENT_DIM: Color32 = Color32::from_rgb(0x1a, 0x2a, 0x3b);

pub const DANGER: Color32 = Color32::from_rgb(0xe5, 0x5f, 0x58);
pub const DANGER_DIM: Color32 = Color32::from_rgb(0x3a, 0x1d, 0x1c);
pub const WARN: Color32 = Color32::from_rgb(0xd9, 0xa4, 0x41);
pub const WARN_DIM: Color32 = Color32::from_rgb(0x33, 0x29, 0x16);

/// Altezza minima di pulsanti e campi.
pub const CONTROL_HEIGHT: f32 = 30.0;

/// Tema unico, indipendente dal tema del sistema.
pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.all_styles_mut(|style| {
        style.visuals = visuals();

        style.text_styles = [
            (TextStyle::Small, FontId::proportional(11.5)),
            (TextStyle::Body, FontId::proportional(14.0)),
            (TextStyle::Button, FontId::proportional(14.0)),
            (TextStyle::Heading, FontId::proportional(21.0)),
            (TextStyle::Monospace, FontId::monospace(13.5)),
        ]
        .into();

        let spacing = &mut style.spacing;
        spacing.item_spacing = egui::vec2(8.0, 8.0);
        spacing.button_padding = egui::vec2(12.0, 5.0);
        spacing.interact_size.y = CONTROL_HEIGHT;
        spacing.window_margin = Margin::same(20);
        spacing.menu_margin = Margin::same(6);
        spacing.menu_spacing = 0.0;
        spacing.scroll.bar_width = 6.0;
        spacing.scroll.floating = true;
    });
}

fn visuals() -> egui::Visuals {
    let mut v = egui::Visuals::dark();
    let square = CornerRadius::ZERO;

    v.override_text_color = None;
    v.weak_text_color = Some(TEXT_WEAK);
    v.hyperlink_color = ACCENT_BRIGHT;
    v.faint_bg_color = SURFACE;
    v.extreme_bg_color = INPUT;
    v.text_edit_bg_color = Some(INPUT);
    v.code_bg_color = INPUT;
    v.warn_fg_color = WARN;
    v.error_fg_color = DANGER;

    v.panel_fill = BG;
    v.window_fill = PANEL;
    v.window_stroke = Stroke::new(1.0, BORDER_STRONG);
    v.window_corner_radius = square;
    v.menu_corner_radius = square;
    v.window_shadow = egui::Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: Color32::from_black_alpha(140),
    };
    v.popup_shadow = egui::Shadow {
        offset: [0, 4],
        blur: 12,
        spread: 0,
        color: Color32::from_black_alpha(120),
    };

    v.selection.bg_fill = ACCENT;
    v.selection.stroke = Stroke::new(1.0, ACCENT_BRIGHT);
    v.text_cursor.stroke = Stroke::new(2.0, ACCENT_BRIGHT);

    let w = &mut v.widgets;
    w.noninteractive.bg_fill = PANEL;
    w.noninteractive.weak_bg_fill = PANEL;
    w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);

    w.inactive.bg_fill = SURFACE;
    w.inactive.weak_bg_fill = SURFACE;
    w.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    w.inactive.fg_stroke = Stroke::new(1.0, TEXT);

    w.hovered.bg_fill = HOVER;
    w.hovered.weak_bg_fill = HOVER;
    w.hovered.bg_stroke = Stroke::new(1.0, BORDER_STRONG);
    w.hovered.fg_stroke = Stroke::new(1.0, Color32::WHITE);

    w.active.bg_fill = PRESSED;
    w.active.weak_bg_fill = PRESSED;
    w.active.bg_stroke = Stroke::new(1.0, ACCENT_BRIGHT);
    w.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);

    w.open.bg_fill = HOVER;
    w.open.weak_bg_fill = HOVER;
    w.open.bg_stroke = Stroke::new(1.0, BORDER_STRONG);
    w.open.fg_stroke = Stroke::new(1.0, TEXT);

    for widget in [
        &mut w.noninteractive,
        &mut w.inactive,
        &mut w.hovered,
        &mut w.active,
        &mut w.open,
    ] {
        widget.corner_radius = square;
        widget.expansion = 0.0;
    }
    v
}

/// Azione principale della schermata: una sola per vista.
pub fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).color(Color32::WHITE)).fill(ACCENT)
}

/// Azione distruttiva.
pub fn danger_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).color(DANGER)).fill(DANGER_DIM)
}

/// Azione secondaria senza cornice, come un collegamento.
pub fn quiet_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).color(TEXT_WEAK)).frame(false)
}

/// Pulsante largo quanto lo spazio disponibile, testo centrato.
pub trait WideButton {
    fn add_wide(&mut self, enabled: bool, button: egui::Button<'_>) -> egui::Response;
}

impl WideButton for egui::Ui {
    fn add_wide(&mut self, enabled: bool, button: egui::Button<'_>) -> egui::Response {
        let size = egui::vec2(self.available_width(), 34.0);
        self.add_enabled_ui(enabled, |ui| ui.add_sized(size, button))
            .inner
    }
}

/// Riquadro con bordo sottile: moduli e gruppi di campi.
pub fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .inner_margin(Margin::same(24))
}

/// Riquadro di avviso con barra colorata a sinistra.
pub fn callout(ui: &mut egui::Ui, color: Color32, fill: Color32, text: &str) {
    let frame = egui::Frame::new()
        .fill(fill)
        .inner_margin(Margin {
            left: 14,
            right: 10,
            top: 8,
            bottom: 8,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(egui::RichText::new(text).color(color));
        });
    let rect = frame.response.rect;
    let bar = egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height()));
    ui.painter().rect_filled(bar, CornerRadius::ZERO, color);
}

/// Etichetta di un campo: piccola, maiuscola, attenuata.
pub fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(
        egui::RichText::new(text.to_uppercase())
            .small()
            .color(TEXT_FAINT)
            .strong(),
    );
}

/// Insetto in pixel art di `crate::BUG_PIXELS`, lato `cell * 16` punti.
pub fn bug_mark(ui: &mut egui::Ui, cell: f32, color: Color32) -> egui::Response {
    let rows = crate::BUG_PIXELS;
    let side = cell * rows.len() as f32;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(side, side), egui::Sense::hover());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        for (y, row) in rows.iter().enumerate() {
            for (x, byte) in row.bytes().enumerate() {
                if byte == b'#' {
                    let min = rect.min + egui::vec2(x as f32 * cell, y as f32 * cell);
                    let pixel = egui::Rect::from_min_size(min, egui::vec2(cell, cell));
                    painter.rect_filled(pixel, CornerRadius::ZERO, color);
                }
            }
        }
    }
    response
}

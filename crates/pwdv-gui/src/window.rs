//! Cornice della finestra disegnata dall'app: barra del titolo con i pulsanti
//! riduci, ingrandisci e chiudi, e bordi trascinabili per ridimensionare. La
//! finestra non ha decorazioni di sistema, così l'aspetto è lo stesso su ogni
//! desktop. Nessun segreto passa di qui: il titolo è sempre "pwdv".

use eframe::egui::{self, CursorIcon, ResizeDirection, ViewportCommand};

use crate::theme;

const TITLE_BAR_HEIGHT: f32 = 32.0;
/// I pulsanti occupano tutta l'altezza della barra, come nei sistemi desktop.
const BUTTON_SIZE: egui::Vec2 = egui::vec2(44.0, TITLE_BAR_HEIGHT);
/// Spessore della fascia sui bordi che avvia il ridimensionamento.
const RESIZE_MARGIN: f32 = 5.0;

/// Barra del titolo: va mostrata prima di ogni altro pannello.
pub fn title_bar(ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    let maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
    let frame = egui::Frame::new()
        .fill(theme::PANEL)
        .stroke(egui::Stroke::new(1.0, theme::BORDER));
    egui::Panel::top("pwdv-title-bar")
        .exact_size(TITLE_BAR_HEIGHT)
        .resizable(false)
        .frame(frame)
        .show(ui, |ui| {
            let bar = ui.max_rect();
            // Sotto i pulsanti: trascinare sposta, doppio clic ingrandisce.
            let drag = ui.interact(bar, ui.id().with("drag"), egui::Sense::click_and_drag());
            if drag.double_clicked() {
                ctx.send_viewport_cmd(ViewportCommand::Maximized(!maximized));
            } else if drag.drag_started_by(egui::PointerButton::Primary) {
                ctx.send_viewport_cmd(ViewportCommand::StartDrag);
            }

            ui.spacing_mut().item_spacing.x = 0.0;
            ui.horizontal_centered(|ui| {
                ui.add_space(10.0);
                theme::bug_mark(ui, 1.0, theme::TEXT_WEAK);
                ui.add_space(8.0);
                ui.label(egui::RichText::new("pwdv").color(theme::TEXT_WEAK).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if caption_button(ui, Caption::Close)
                        .on_hover_text("Chiudi")
                        .clicked()
                    {
                        ctx.send_viewport_cmd(ViewportCommand::Close);
                    }
                    let (caption, hint) = if maximized {
                        (Caption::Restore, "Ripristina")
                    } else {
                        (Caption::Maximize, "Ingrandisci")
                    };
                    if caption_button(ui, caption).on_hover_text(hint).clicked() {
                        ctx.send_viewport_cmd(ViewportCommand::Maximized(!maximized));
                    }
                    if caption_button(ui, Caption::Minimize)
                        .on_hover_text("Riduci a icona")
                        .clicked()
                    {
                        ctx.send_viewport_cmd(ViewportCommand::Minimized(true));
                    }
                });
            });
        });
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Caption {
    Minimize,
    Maximize,
    Restore,
    Close,
}

/// Pulsante della barra del titolo con il simbolo disegnato a linee sottili,
/// indipendente dai glifi disponibili nel font.
fn caption_button(ui: &mut egui::Ui, caption: Caption) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(BUTTON_SIZE, egui::Sense::click());
    let (fill, color) = match (
        caption,
        response.hovered(),
        response.is_pointer_button_down_on(),
    ) {
        (Caption::Close, true, _) => (theme::DANGER, egui::Color32::WHITE),
        (_, true, true) => (theme::PRESSED, theme::TEXT),
        (_, true, false) => (theme::HOVER, theme::TEXT),
        _ => (egui::Color32::TRANSPARENT, theme::TEXT_WEAK),
    };
    let painter = ui.painter();
    painter.rect_filled(rect, egui::CornerRadius::ZERO, fill);
    let stroke = egui::Stroke::new(1.0, color);
    let c = rect.center();
    let r = 5.0;
    match caption {
        Caption::Minimize => {
            painter.hline(c.x - r..=c.x + r, c.y, stroke);
        }
        Caption::Maximize => {
            let square = egui::Rect::from_center_size(c, egui::vec2(2.0 * r, 2.0 * r));
            painter.rect_stroke(square, 0.0, stroke, egui::StrokeKind::Inside);
        }
        Caption::Restore => {
            let back =
                egui::Rect::from_min_size(c + egui::vec2(-r + 2.0, -r), egui::vec2(8.0, 8.0));
            let front =
                egui::Rect::from_min_size(c + egui::vec2(-r, -r + 2.0), egui::vec2(8.0, 8.0));
            painter.rect_stroke(back, 0.0, stroke, egui::StrokeKind::Inside);
            painter.rect_filled(
                front,
                0.0,
                if fill == egui::Color32::TRANSPARENT {
                    theme::PANEL
                } else {
                    fill
                },
            );
            painter.rect_stroke(front, 0.0, stroke, egui::StrokeKind::Inside);
        }
        Caption::Close => {
            painter.line_segment([c + egui::vec2(-r, -r), c + egui::vec2(r, r)], stroke);
            painter.line_segment([c + egui::vec2(-r, r), c + egui::vec2(r, -r)], stroke);
        }
    }
    response
}

/// Ridimensionamento dai bordi: cursore adatto al passaggio e, alla pressione,
/// il ridimensionamento passa al compositor. Inattivo a finestra ingrandita.
pub fn resize_edges(ctx: &egui::Context) {
    let (maximized, rect, hover, pressed) = ctx.input(|i| {
        (
            i.viewport().maximized.unwrap_or(false),
            i.viewport_rect(),
            i.pointer.hover_pos(),
            i.pointer.primary_pressed(),
        )
    });
    if maximized {
        return;
    }
    let Some(direction) = hover.and_then(|pos| edge_at(rect, pos)) else {
        return;
    };
    ctx.set_cursor_icon(cursor_for(direction));
    if pressed {
        ctx.send_viewport_cmd(ViewportCommand::BeginResize(direction));
    }
}

fn edge_at(rect: egui::Rect, pos: egui::Pos2) -> Option<ResizeDirection> {
    let west = pos.x - rect.left() < RESIZE_MARGIN;
    let east = rect.right() - pos.x < RESIZE_MARGIN;
    let north = pos.y - rect.top() < RESIZE_MARGIN;
    let south = rect.bottom() - pos.y < RESIZE_MARGIN;
    match (north, south, west, east) {
        (true, _, true, _) => Some(ResizeDirection::NorthWest),
        (true, _, _, true) => Some(ResizeDirection::NorthEast),
        (_, true, true, _) => Some(ResizeDirection::SouthWest),
        (_, true, _, true) => Some(ResizeDirection::SouthEast),
        (true, ..) => Some(ResizeDirection::North),
        (_, true, ..) => Some(ResizeDirection::South),
        (_, _, true, _) => Some(ResizeDirection::West),
        (_, _, _, true) => Some(ResizeDirection::East),
        _ => None,
    }
}

fn cursor_for(direction: ResizeDirection) -> CursorIcon {
    match direction {
        ResizeDirection::North => CursorIcon::ResizeNorth,
        ResizeDirection::South => CursorIcon::ResizeSouth,
        ResizeDirection::East => CursorIcon::ResizeEast,
        ResizeDirection::West => CursorIcon::ResizeWest,
        ResizeDirection::NorthEast => CursorIcon::ResizeNorthEast,
        ResizeDirection::SouthEast => CursorIcon::ResizeSouthEast,
        ResizeDirection::NorthWest => CursorIcon::ResizeNorthWest,
        ResizeDirection::SouthWest => CursorIcon::ResizeSouthWest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edges_and_corners_are_detected() {
        let rect = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(800.0, 600.0));
        let at = |x, y| edge_at(rect, egui::pos2(x, y));
        assert!(matches!(at(1.0, 1.0), Some(ResizeDirection::NorthWest)));
        assert!(matches!(at(799.0, 599.0), Some(ResizeDirection::SouthEast)));
        assert!(matches!(at(400.0, 1.0), Some(ResizeDirection::North)));
        assert!(matches!(at(799.0, 300.0), Some(ResizeDirection::East)));
        assert!(at(400.0, 300.0).is_none());
    }
}

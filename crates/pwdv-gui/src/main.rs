//! GUI di pwdv.

mod app;
mod main_view;
mod security;
mod unlock;
mod window;
mod worker;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("pwdv")
            // Deve coincidere con `StartupWMClass` in packaging/linux/pwdv.desktop.in.
            .with_app_id("pwdv")
            .with_inner_size([1000.0, 680.0])
            .with_min_inner_size([720.0, 480.0])
            .with_icon(bug_icon())
            // Barra del titolo e bordi sono disegnati da `window`.
            .with_decorations(false),
        // Già escluso dalla feature `persistence` disabilitata; esplicito per sicurezza.
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        "pwdv",
        options,
        Box::new(|_cc| Ok(Box::new(app::PwdvApp::default()))),
    )
}

/// Icona in pixel art: un insetto nero su fondo grigio. Stessa griglia di
/// `packaging/linux/pwdv.svg`, usata dai launcher tramite il file `.desktop`.
const BUG_PIXELS: [&str; 16] = [
    "................",
    "....#......#....",
    ".....#....#.....",
    "......####......",
    ".....######.....",
    ".#..########..#.",
    "..#.##.##.##.#..",
    "...##########...",
    ".#..########..#.",
    "..#.##.##.##.#..",
    "...##########...",
    "....########....",
    "...#.######.#...",
    "..#...####...#..",
    "................",
    "................",
];

/// Lato in pixel reali di ogni pixel della griglia.
const BUG_SCALE: usize = 8;

/// Icona della finestra (usata su X11; su Wayland conta quella del `.desktop`).
fn bug_icon() -> egui::IconData {
    const BLACK: [u8; 4] = [0x00, 0x00, 0x00, 0xff];
    const GRAY: [u8; 4] = [0x9a, 0x9a, 0x9a, 0xff];
    let side = BUG_PIXELS.len() * BUG_SCALE;
    let mut rgba = Vec::with_capacity(side * side * 4);
    for row in BUG_PIXELS {
        for _ in 0..BUG_SCALE {
            for cell in row.bytes() {
                let pixel = if cell == b'#' { BLACK } else { GRAY };
                for _ in 0..BUG_SCALE {
                    rgba.extend_from_slice(&pixel);
                }
            }
        }
    }
    egui::IconData {
        rgba,
        width: side as u32,
        height: side as u32,
    }
}

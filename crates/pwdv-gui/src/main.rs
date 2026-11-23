//! GUI di pwdv.

mod app;
mod main_view;
mod security;
mod theme;
mod unlock;
mod window;
mod worker;

use eframe::egui;

fn main() -> eframe::Result {
    // Prima di aprire la finestra: un crash a vault aperto non deve salvare
    // DEK e voci su disco. Se non si riesce, meglio non partire.
    if let Err(e) = pwdv_core::hardening::disable_core_dumps() {
        eprintln!("pwdv-gui: impossibile disattivare i core dump: {e}");
        std::process::exit(1);
    }
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
        // Senza vsync: su Wayland, con la finestra su un altro workspace il
        // compositor non manda più frame callback ed `eglSwapBuffers` con
        // intervallo 1 resta bloccato. Il thread della UI si ferma, non
        // risponde ai ping (Hyprland: "non risponde") e non aggiorna più il
        // cursore. I repaint dell'app sono solo su eventi e timer, quindi
        // senza vsync non c'è un ciclo di rendering continuo.
        glow_options: eframe::egui_glow::GlowConfiguration {
            vsync: false,
            ..Default::default()
        },
        ..Default::default()
    };
    eframe::run_native(
        "pwdv",
        options,
        Box::new(|cc| {
            theme::apply(&cc.egui_ctx);
            Ok(Box::new(app::PwdvApp::default()))
        }),
    )
}

/// Icona in pixel art: un insetto nero su fondo grigio. Stessa griglia di
/// `packaging/linux/pwdv.svg`, usata dai launcher tramite il file `.desktop`.
/// La stessa griglia è disegnata nella UI da `theme::bug_mark`.
pub(crate) const BUG_PIXELS: [&str; 16] = [
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

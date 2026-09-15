//! GUI di pwdv.

mod app;
mod main_view;
mod security;
mod unlock;
mod worker;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("pwdv")
            .with_inner_size([1000.0, 680.0])
            .with_min_inner_size([720.0, 480.0])
            .with_icon(placeholder_icon()),
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

/// Icona provvisoria generata a runtime: quadrato blu con un cerchio chiaro.
fn placeholder_icon() -> egui::IconData {
    const SIZE: u32 = 64;
    const CENTER: f32 = (SIZE as f32 - 1.0) / 2.0;
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let (dx, dy) = (x as f32 - CENTER, y as f32 - CENTER);
            let pixel = if dx.hypot(dy) < 14.0 {
                [0xf2, 0xf4, 0xf8, 0xff]
            } else {
                [0x3b, 0x6e, 0xd8, 0xff]
            };
            rgba.extend_from_slice(&pixel);
        }
    }
    egui::IconData {
        rgba,
        width: SIZE,
        height: SIZE,
    }
}

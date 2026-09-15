//! Sicurezza operativa: blocco per inattività e clipboard che si svuota da solo.

use std::ops::RangeInclusive;
use std::time::{Duration, Instant, SystemTime};

use eframe::egui;
use zeroize::Zeroizing;

/// Blocco automatico predefinito.
pub const DEFAULT_AUTOLOCK: Duration = Duration::from_secs(5 * 60);
/// Durate offerte nel menu, in minuti.
pub const AUTOLOCK_CHOICES_MIN: [u64; 6] = [1, 2, 5, 10, 15, 30];
/// Variabile d'ambiente con la durata iniziale del blocco automatico, in secondi.
pub const AUTOLOCK_ENV: &str = "PWDV_AUTOLOCK_SECONDS";
const AUTOLOCK_RANGE_SECS: RangeInclusive<u64> = 10..=86_400;
/// Dopo quanto il valore copiato viene tolto dal clipboard.
pub const CLIPBOARD_TTL: Duration = Duration::from_secs(20);

/// Istante corrente su due orologi. `Instant` non avanza mentre il sistema è
/// sospeso, l'orologio di sistema sì: le scadenze li guardano entrambi, così
/// un portatile che si risveglia dopo un'ora trova il vault già bloccato.
#[derive(Clone, Copy)]
pub struct Now {
    pub instant: Instant,
    pub wall: SystemTime,
}

impl Now {
    pub fn current() -> Self {
        Now {
            instant: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    #[cfg(test)]
    pub fn plus(self, d: Duration) -> Self {
        Now {
            instant: self.instant + d,
            wall: self.wall + d,
        }
    }
}

/// Scade quando uno dei due orologi ha superato la durata. Un orologio di
/// sistema spostato all'indietro non allunga la scadenza.
#[derive(Clone, Copy)]
struct Deadline {
    start: Now,
    after: Duration,
}

impl Deadline {
    fn new(after: Duration, now: Now) -> Self {
        Deadline { start: now, after }
    }

    fn remaining(&self, now: Now) -> Duration {
        let monotonic = now.instant.saturating_duration_since(self.start.instant);
        let wall = now.wall.duration_since(self.start.wall).unwrap_or_default();
        self.after.saturating_sub(monotonic.max(wall))
    }

    fn expired(&self, now: Now) -> bool {
        self.remaining(now).is_zero()
    }
}

/// Timer di inattività: qualunque input nella finestra lo riporta a zero.
pub struct IdleTimer {
    deadline: Deadline,
}

impl IdleTimer {
    pub fn new(timeout: Duration, now: Now) -> Self {
        IdleTimer {
            deadline: Deadline::new(timeout, now),
        }
    }

    pub fn timeout(&self) -> Duration {
        self.deadline.after
    }

    pub fn set_timeout(&mut self, timeout: Duration, now: Now) {
        self.deadline = Deadline::new(timeout, now);
    }

    pub fn touch(&mut self, now: Now) {
        self.deadline.start = now;
    }

    pub fn remaining(&self, now: Now) -> Duration {
        self.deadline.remaining(now)
    }

    pub fn expired(&self, now: Now) -> bool {
        self.deadline.expired(now)
    }
}

/// Durata iniziale del blocco automatico: `PWDV_AUTOLOCK_SECONDS` se è un
/// numero tra 10 e 86400, altrimenti 5 minuti.
pub fn initial_autolock() -> Duration {
    std::env::var(AUTOLOCK_ENV)
        .ok()
        .and_then(|value| parse_autolock(&value))
        .unwrap_or(DEFAULT_AUTOLOCK)
}

fn parse_autolock(value: &str) -> Option<Duration> {
    let secs: u64 = value.trim().parse().ok()?;
    AUTOLOCK_RANGE_SECS
        .contains(&secs)
        .then(|| Duration::from_secs(secs))
}

/// Input dell'utente nella finestra: tastiera, mouse, touch. Gli eventi che
/// arrivano dal sistema (focus della finestra, puntatore uscito, modificatori
/// aggiornati al cambio di focus) non contano come attività.
pub fn is_user_input(event: &egui::Event) -> bool {
    use egui::Event;
    matches!(
        event,
        Event::Copy
            | Event::Cut
            | Event::Paste(_)
            | Event::Text(_)
            | Event::Key { .. }
            | Event::PointerMoved(_)
            | Event::MouseMoved(_)
            | Event::PointerButton { .. }
            | Event::Zoom(_)
            | Event::Rotate(_)
            | Event::Ime(_)
            | Event::Touch { .. }
            | Event::MouseWheel { .. }
    )
}

/// Accesso al clipboard di sistema. In produzione arboard, nei test un finto.
pub trait ClipboardBackend {
    /// Scrive `text` chiedendo ai gestori della cronologia di non conservarlo.
    fn set_secret(&mut self, text: &str) -> Result<(), String>;
    fn get(&mut self) -> Option<Zeroizing<String>>;
    fn clear(&mut self) -> Result<(), String>;
}

/// arboard con `wayland-data-control`: su Wayland usa il protocollo
/// data-control, altrimenti X11. In entrambi i casi il contenuto è servito da
/// un thread di questo processo e sparisce quando il processo termina.
/// XWayland da solo non basta: Hyprland non passa il clipboard X11 alle
/// applicazioni Wayland.
struct SystemClipboard(arboard::Clipboard);

impl ClipboardBackend for SystemClipboard {
    fn set_secret(&mut self, text: &str) -> Result<(), String> {
        let set = self.0.set();
        // Aggiunge il MIME `x-kde-passwordManagerHint: secret`, la convenzione
        // rispettata dai gestori della cronologia degli appunti su Linux.
        #[cfg(target_os = "linux")]
        let set = {
            use arboard::SetExtLinux;
            set.exclude_from_history()
        };
        set.text(text).map_err(|e| e.to_string())
    }

    fn get(&mut self) -> Option<Zeroizing<String>> {
        self.0.get_text().ok().map(Zeroizing::new)
    }

    fn clear(&mut self) -> Result<(), String> {
        self.0.clear().map_err(|e| e.to_string())
    }
}

/// Clipboard dell'applicazione. Vive quanto `PwdvApp`, non quanto la sessione:
/// deve poter essere svuotato anche al momento del blocco e alla chiusura.
pub struct Clipboard {
    backend: Option<Box<dyn ClipboardBackend>>,
    /// Ultimo valore copiato da pwdv, finché non viene tolto dal clipboard.
    pending: Option<Pending>,
    unavailable: Option<String>,
}

struct Pending {
    value: Zeroizing<String>,
    deadline: Deadline,
}

impl Clipboard {
    pub fn system() -> Self {
        match arboard::Clipboard::new() {
            Ok(clipboard) => Clipboard::with_backend(Box::new(SystemClipboard(clipboard))),
            Err(e) => Clipboard {
                backend: None,
                pending: None,
                unavailable: Some(e.to_string()),
            },
        }
    }

    pub fn with_backend(backend: Box<dyn ClipboardBackend>) -> Self {
        Clipboard {
            backend: Some(backend),
            pending: None,
            unavailable: None,
        }
    }

    /// Perché il clipboard di sistema non è disponibile, se non lo è.
    pub fn unavailable(&self) -> Option<&str> {
        self.unavailable.as_deref()
    }

    /// Unico punto del programma che scrive nel clipboard. Il valore viene
    /// tolto dopo `CLIPBOARD_TTL`; una copia successiva sostituisce la
    /// precedente e fa ripartire il conto, così anche lei viene cancellata.
    pub fn copy(&mut self, text: &str, now: Now) -> Result<(), String> {
        let backend = self
            .backend
            .as_mut()
            .ok_or_else(|| "clipboard di sistema non disponibile".to_owned())?;
        backend.set_secret(text)?;
        self.pending = Some(Pending {
            value: Zeroizing::new(text.to_owned()),
            deadline: Deadline::new(CLIPBOARD_TTL, now),
        });
        Ok(())
    }

    /// Tempo alla cancellazione dell'ultimo valore copiato, se ce n'è uno.
    pub fn remaining(&self, now: Now) -> Option<Duration> {
        self.pending.as_ref().map(|pending| pending.deadline.remaining(now))
    }

    /// Da chiamare a ogni frame: alla scadenza svuota il clipboard.
    pub fn tick(&mut self, now: Now) {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.deadline.expired(now))
        {
            self.clear_now();
        }
    }

    /// Svuota subito, ma solo se il clipboard contiene ancora il valore
    /// copiato da pwdv: quello che l'utente ha copiato altrove resta dov'è.
    pub fn clear_now(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let Some(backend) = self.backend.as_mut() else {
            return;
        };
        if backend
            .get()
            .is_some_and(|current| *current == *pending.value)
        {
            // Se fallisce non c'è altro da tentare: il valore resta finché
            // qualcos'altro non lo sostituisce.
            let _ = backend.clear();
        }
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        self.clear_now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Clipboard finto condiviso: il test vede quello che vede "il sistema".
    #[derive(Clone, Default)]
    struct Fake(Rc<RefCell<Option<String>>>);

    impl Fake {
        fn content(&self) -> Option<String> {
            self.0.borrow().clone()
        }

        /// Qualcun altro copia qualcosa.
        fn foreign_copy(&self, text: &str) {
            *self.0.borrow_mut() = Some(text.to_owned());
        }
    }

    impl ClipboardBackend for Fake {
        fn set_secret(&mut self, text: &str) -> Result<(), String> {
            *self.0.borrow_mut() = Some(text.to_owned());
            Ok(())
        }

        fn get(&mut self) -> Option<Zeroizing<String>> {
            self.content().map(Zeroizing::new)
        }

        fn clear(&mut self) -> Result<(), String> {
            *self.0.borrow_mut() = None;
            Ok(())
        }
    }

    fn fake_clipboard() -> (Clipboard, Fake) {
        let fake = Fake::default();
        (Clipboard::with_backend(Box::new(fake.clone())), fake)
    }

    const SEC: Duration = Duration::from_secs(1);

    #[test]
    fn deadline_expires_on_whichever_clock_is_further_ahead() {
        let now = Now::current();
        let deadline = Deadline::new(60 * SEC, now);
        assert_eq!(deadline.remaining(now), 60 * SEC);
        assert!(!deadline.expired(now.plus(59 * SEC)));
        assert!(deadline.expired(now.plus(60 * SEC)));

        // Sospensione: l'orologio monotono è quasi fermo, quello di sistema no.
        let resumed = Now {
            instant: now.instant + SEC,
            wall: now.wall + 3_600 * SEC,
        };
        assert!(deadline.expired(resumed));

        // Orologio di sistema spostato indietro: conta solo quello monotono.
        let moved_back = Now {
            instant: now.instant + 30 * SEC,
            wall: now.wall - 3_600 * SEC,
        };
        assert_eq!(deadline.remaining(moved_back), 30 * SEC);
    }

    #[test]
    fn idle_timer_restarts_on_input_and_on_a_new_timeout() {
        let now = Now::current();
        let mut idle = IdleTimer::new(DEFAULT_AUTOLOCK, now);
        assert!(!idle.expired(now.plus(299 * SEC)));

        idle.touch(now.plus(200 * SEC));
        assert!(!idle.expired(now.plus(499 * SEC)));
        assert!(idle.expired(now.plus(500 * SEC)));

        idle.set_timeout(60 * SEC, now.plus(500 * SEC));
        assert_eq!(idle.timeout(), 60 * SEC);
        assert!(idle.expired(now.plus(560 * SEC)));
    }

    #[test]
    fn autolock_from_the_environment_is_validated() {
        assert_eq!(parse_autolock("30"), Some(30 * SEC));
        assert_eq!(parse_autolock(" 600 "), Some(600 * SEC));
        assert_eq!(parse_autolock("5"), None, "sotto il minimo");
        assert_eq!(parse_autolock("100000"), None, "sopra il massimo");
        assert_eq!(parse_autolock("cinque"), None);
    }

    #[test]
    fn only_user_events_count_as_activity() {
        use egui::Event;
        assert!(is_user_input(&Event::PointerMoved(egui::pos2(1.0, 2.0))));
        assert!(is_user_input(&Event::Text("a".to_owned())));
        assert!(is_user_input(&Event::Copy));
        assert!(!is_user_input(&Event::WindowFocused(true)));
        assert!(!is_user_input(&Event::PointerGone));
        assert!(!is_user_input(&Event::ModifiersChanged(egui::Modifiers::CTRL)));
    }

    #[test]
    fn copied_value_is_cleared_after_twenty_seconds() {
        let (mut clipboard, fake) = fake_clipboard();
        let now = Now::current();
        clipboard.copy("segreto", now).unwrap();
        assert_eq!(clipboard.remaining(now), Some(20 * SEC));

        clipboard.tick(now.plus(19 * SEC));
        assert_eq!(fake.content().as_deref(), Some("segreto"));

        clipboard.tick(now.plus(20 * SEC));
        assert_eq!(fake.content(), None);
        assert_eq!(clipboard.remaining(now.plus(20 * SEC)), None);
    }

    #[test]
    fn a_second_copy_restarts_the_countdown_and_is_cleared_too() {
        let (mut clipboard, fake) = fake_clipboard();
        let now = Now::current();
        clipboard.copy("primo", now).unwrap();
        clipboard.copy("secondo", now.plus(15 * SEC)).unwrap();

        clipboard.tick(now.plus(20 * SEC));
        assert_eq!(fake.content().as_deref(), Some("secondo"));

        clipboard.tick(now.plus(35 * SEC));
        assert_eq!(fake.content(), None);
    }

    #[test]
    fn content_copied_elsewhere_is_left_alone() {
        let (mut clipboard, fake) = fake_clipboard();
        let now = Now::current();
        clipboard.copy("segreto", now).unwrap();
        fake.foreign_copy("indirizzo copiato dal browser");

        clipboard.tick(now.plus(20 * SEC));
        assert_eq!(fake.content().as_deref(), Some("indirizzo copiato dal browser"));
        assert_eq!(clipboard.remaining(now.plus(20 * SEC)), None);
    }

    #[test]
    fn clear_now_and_drop_empty_the_clipboard() {
        let (mut clipboard, fake) = fake_clipboard();
        let now = Now::current();
        clipboard.copy("al blocco", now).unwrap();
        clipboard.clear_now();
        assert_eq!(fake.content(), None);

        clipboard.copy("alla chiusura", now).unwrap();
        drop(clipboard);
        assert_eq!(fake.content(), None);
    }

    #[test]
    fn unavailable_clipboard_refuses_to_copy() {
        let mut clipboard = Clipboard {
            backend: None,
            pending: None,
            unavailable: Some("nessun display".to_owned()),
        };
        assert!(clipboard.copy("segreto", Now::current()).is_err());
        assert_eq!(clipboard.unavailable(), Some("nessun display"));
    }
}

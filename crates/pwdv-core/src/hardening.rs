//! Protezioni del processo che tiene in memoria chiavi e password.
//!
//! Da chiamare come prima cosa nel `main` di ogni eseguibile, prima di leggere
//! qualunque segreto.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

/// Diventa vero alla prima richiesta di blocco in RAM non riuscita.
static LOCK_FAILED: AtomicBool = AtomicBool::new(false);

/// Blocca in RAM le pagine di `bytes`, così il sistema non le scrive nello
/// swap (CWE-591). Da chiamare **prima** di scrivere il segreto nel buffer.
/// Audit 2026-11-23, rilievo M2; ADR 0009.
///
/// - Un errore non ferma il programma: viene ricordato e
///   [`memory_lock_failed`] permette a CLI e GUI di avvisare l'utente.
/// - Le pagine non vengono mai sbloccate: `munlock` non tiene un conteggio, e
///   sbloccare una pagina condivisa con un altro segreto lo esporrebbe. Restano
///   bloccate fino all'uscita del processo, entro `RLIMIT_MEMLOCK`.
/// - Non protegge dall'ibernazione, che salva anche le pagine bloccate: per
///   quella e per le copie nelle librerie valgono i prerequisiti del README.
pub fn lock_bytes(bytes: &[u8]) {
    lock_region(bytes.as_ptr(), bytes.len());
}

/// Come [`lock_bytes`], sull'intera capacità della stringa: il segreto può
/// occuparla tutta senza riallocazioni. Serve `&String` per la capacità.
#[allow(clippy::ptr_arg)]
pub fn lock_string(text: &String) {
    lock_region(text.as_ptr(), text.capacity());
}

/// Vero se almeno un blocco in RAM non è riuscito (limite `RLIMIT_MEMLOCK`
/// esaurito, piattaforma non supportata).
pub fn memory_lock_failed() -> bool {
    LOCK_FAILED.load(Ordering::Relaxed)
}

fn lock_region(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    if imp::lock(ptr, len).is_err() {
        LOCK_FAILED.store(true, Ordering::Relaxed);
    }
}

/// Impedisce che la memoria del processo finisca su disco in un core dump:
/// un crash a vault aperto salverebbe DEK e voci in chiaro (per esempio in
/// `systemd-coredump`). Audit 2026-11-23, rilievo M1.
///
/// - Linux: `RLIMIT_CORE = 0` e `PR_SET_DUMPABLE = 0`. Il secondo vale anche se
///   `core_pattern` invia il dump a un programma (caso in cui il kernel ignora
///   `RLIMIT_CORE`) e impedisce ad altri processi dello stesso utente di
///   leggere la memoria con `ptrace` o `/proc/<pid>/mem`.
/// - Altri unix (macOS): solo `RLIMIT_CORE = 0`.
/// - Windows: nessuna operazione. I dump di Windows Error Reporting restano
///   possibili (README).
///
/// Abbassare questi limiti è sempre consentito a un processo non privilegiato;
/// un errore qui indica un ambiente anomalo e il chiamante deve fermarsi.
pub fn disable_core_dumps() -> io::Result<()> {
    imp::disable_core_dumps()
}

#[cfg(unix)]
mod imp {
    use std::io;

    pub fn disable_core_dumps() -> io::Result<()> {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `setrlimit` legge soltanto la struct passata per puntatore,
        // valida per tutta la durata della chiamata, e non la conserva. Non
        // esiste un'API della libreria standard per i limiti di risorsa.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
            return Err(io::Error::last_os_error());
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // `prctl` è variadica: gli argomenti vanno passati come
            // `unsigned long`, la dimensione che il kernel legge.
            let off: libc::c_ulong = 0;
            // SAFETY: con `PR_SET_DUMPABLE` tutti gli argomenti sono interi,
            // nessun puntatore né memoria coinvolti.
            if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, off, off, off, off) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn lock(ptr: *const u8, len: usize) -> io::Result<()> {
        // SAFETY: `sysconf` legge una costante di sistema, nessuna memoria.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = usize::try_from(page)
            .ok()
            .filter(|p| p.is_power_of_two())
            .ok_or_else(|| io::Error::other("page size"))?;
        // Inizio allineato alla pagina: POSIX consente di rifiutare indirizzi
        // non allineati (Linux arrotonda da solo, altri sistemi no).
        let offset = ptr.addr() & (page - 1);
        let start = ptr.wrapping_sub(offset);
        let span = len
            .checked_add(offset)
            .ok_or_else(|| io::Error::other("range"))?;
        // SAFETY: `mlock` non legge né scrive la memoria indicata, chiede solo
        // al kernel di tenerla residente. Un intervallo non mappato produce
        // un errore (ENOMEM), non un comportamento indefinito. La libreria
        // standard non espone questa chiamata.
        if unsafe { libc::mlock(start.cast::<libc::c_void>(), span) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(unix))]
mod imp {
    use std::io;

    pub fn disable_core_dumps() -> io::Result<()> {
        Ok(())
    }

    /// `VirtualLock` richiederebbe una dipendenza Windows non ancora
    /// approvata: si segnala il mancato blocco, e CLI e GUI avvisano.
    pub fn lock(_ptr: *const u8, _len: usize) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

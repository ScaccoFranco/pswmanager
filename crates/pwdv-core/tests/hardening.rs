//! Test in un binario separato: modifica i limiti dell'intero processo.

#[cfg(unix)]
#[test]
fn core_dumps_are_disabled() {
    pwdv_core::hardening::disable_core_dumps().unwrap();

    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: `getrlimit` scrive solo nella struct passata, valida e di proprietà del test.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
    assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));

    #[cfg(target_os = "linux")]
    {
        // SAFETY: `PR_GET_DUMPABLE` non usa argomenti né memoria.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        assert_eq!(dumpable, 0);
    }

    // Una seconda chiamata non deve fallire.
    pwdv_core::hardening::disable_core_dumps().unwrap();
}

/// Le pagine di una chiave risultano bloccate in RAM (`VmLck` > 0) e nessun
/// blocco è fallito. Il limite `RLIMIT_MEMLOCK` predefinito (8 MiB) basta.
#[cfg(target_os = "linux")]
#[test]
fn keys_and_strings_are_locked_in_ram() {
    let key = pwdv_core::key::Key32::random().unwrap();
    let mut text = String::with_capacity(64);
    pwdv_core::hardening::lock_string(&text);
    text.push_str("segreto");

    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let locked_kib: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmLck:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap();
    assert!(locked_kib > 0, "nessuna pagina bloccata");
    assert!(!pwdv_core::hardening::memory_lock_failed());
    assert_ne!(key.as_bytes(), &[0u8; 32]);
}

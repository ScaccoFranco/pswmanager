//! CLI di pwdv. Le password si leggono solo dal terminale, mai dagli argomenti.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use zeroize::Zeroizing;

use pwdv::store;
use pwdv::vault::{Entry, VaultData};

type CliResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Parser)]
#[command(name = "pwdv", version, about = "Local encrypted password vault")]
struct Cli {
    /// Vault file [default: $HOME/.vault.pwdv]
    #[arg(long, global = true, value_name = "PATH")]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new, empty vault
    Init,
    /// Add an entry (its password is prompted for)
    Add {
        name: String,
        #[arg(short, long)]
        username: String,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Show an entry, password included
    Get { name: String },
    /// List entries (passwords are never shown)
    List,
    /// Remove an entry
    Rm { name: String },
    /// Change the master password (re-wraps the key, vault data untouched)
    Passwd,
    /// Generate a random password
    Gen {
        #[arg(short, long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..))]
        length: u16,
        /// Character classes to draw from, comma separated
        #[arg(short, long, value_enum, value_delimiter = ',', default_values_t = Charset::ALL)]
        charset: Vec<Charset>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Charset {
    Lower,
    Upper,
    Digits,
    Symbols,
}

impl Charset {
    const ALL: [Charset; 4] = [
        Charset::Lower,
        Charset::Upper,
        Charset::Digits,
        Charset::Symbols,
    ];

    fn chars(self) -> &'static str {
        match self {
            Charset::Lower => "abcdefghijklmnopqrstuvwxyz",
            Charset::Upper => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            Charset::Digits => "0123456789",
            Charset::Symbols => "!#$%&()*+,-./:;<=>?@[]^_{|}~",
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pwdv: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> CliResult {
    let Cli { vault, command } = cli;
    match command {
        Command::Gen { length, charset } => {
            println!("{}", generate(length, &charset)?.as_str());
            Ok(())
        }
        Command::Init => init(&vault_path(vault)?),
        Command::Add {
            name,
            username,
            url,
            notes,
        } => add(&vault_path(vault)?, name, username, url, notes),
        Command::Get { name } => get(&vault_path(vault)?, &name),
        Command::List => list(&vault_path(vault)?),
        Command::Rm { name } => rm(&vault_path(vault)?, &name),
        Command::Passwd => passwd(&vault_path(vault)?),
    }
}

fn init(path: &Path) -> CliResult {
    if path.try_exists()? {
        return Err(format!("{} already exists", path.display()).into());
    }
    let master = prompt_new("New master password: ")?;
    store::save(path, master.as_bytes(), &VaultData::default())?;
    println!("created {}", path.display());
    Ok(())
}

fn add(
    path: &Path,
    name: String,
    username: String,
    url: Option<String>,
    notes: Option<String>,
) -> CliResult {
    let (master, mut data) = unlock(path)?;
    if data.entries.iter().any(|e| e.name == name) {
        return Err(format!("entry '{name}' already exists").into());
    }
    let mut password = prompt(&format!("Password for '{name}': "))?;
    if password.is_empty() {
        return Err("password must not be empty".into());
    }
    let done = format!("added '{name}'");
    // `take` sposta la String senza copiarne il buffer.
    let password = std::mem::take(&mut *password);
    data.entries
        .push(Entry::new(name, username, password, url, notes));
    store::save(path, master.as_bytes(), &data)?;
    println!("{done}");
    Ok(())
}

fn get(path: &Path, name: &str) -> CliResult {
    let (_, data) = unlock(path)?;
    let entry = data
        .entries
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| format!("no entry named '{name}'"))?;
    println!("name:     {}", entry.name);
    println!("username: {}", entry.username);
    println!("password: {}", entry.password);
    if let Some(url) = &entry.url {
        println!("url:      {url}");
    }
    if let Some(notes) = &entry.notes {
        println!("notes:    {notes}");
    }
    println!("created:  {} (unix time)", entry.created);
    println!("modified: {} (unix time)", entry.modified);
    Ok(())
}

fn list(path: &Path) -> CliResult {
    let (_, data) = unlock(path)?;
    if data.entries.is_empty() {
        eprintln!("vault is empty");
    }
    let mut entries: Vec<&Entry> = data.entries.iter().collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    for e in entries {
        println!("{}\t{}\t{}", e.name, e.username, e.url.as_deref().unwrap_or(""));
    }
    Ok(())
}

fn rm(path: &Path, name: &str) -> CliResult {
    let (master, mut data) = unlock(path)?;
    let index = data
        .entries
        .iter()
        .position(|e| e.name == name)
        .ok_or_else(|| format!("no entry named '{name}'"))?;
    data.entries.remove(index);
    store::save(path, master.as_bytes(), &data)?;
    println!("removed '{name}'");
    Ok(())
}

fn passwd(path: &Path) -> CliResult {
    // Verifica la password attuale prima di chiedere la nuova due volte.
    let (old, _) = unlock(path)?;
    let new = prompt_new("New master password: ")?;
    store::change_password(path, old.as_bytes(), new.as_bytes())?;
    println!("master password changed");
    Ok(())
}

fn vault_path(arg: Option<PathBuf>) -> CliResult<PathBuf> {
    match arg {
        Some(path) => Ok(path),
        None => std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join(".vault.pwdv"))
            .ok_or_else(|| "HOME is not set; pass --vault".into()),
    }
}

/// Chiede la master password e apre il vault.
fn unlock(path: &Path) -> CliResult<(Zeroizing<String>, VaultData)> {
    if !path.try_exists()? {
        return Err(format!("no vault at {}; run `pwdv init` first", path.display()).into());
    }
    let master = prompt("Master password: ")?;
    let data = store::load(path, master.as_bytes())?;
    Ok((master, data))
}

fn prompt(label: &str) -> CliResult<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(label)?))
}

fn prompt_new(label: &str) -> CliResult<Zeroizing<String>> {
    let first = prompt(label)?;
    if first.is_empty() {
        return Err("password must not be empty".into());
    }
    let confirm = prompt("Confirm: ")?;
    if *first != *confirm {
        return Err("passwords do not match".into());
    }
    Ok(first)
}

/// Estrazione uniforme da OsRng sull'unione delle classi scelte.
fn generate(length: u16, charsets: &[Charset]) -> CliResult<Zeroizing<String>> {
    let mut alphabet: Vec<u8> = charsets.iter().flat_map(|c| c.chars().bytes()).collect();
    alphabet.sort_unstable();
    alphabet.dedup();

    let mut out = Zeroizing::new(String::with_capacity(length.into()));
    for _ in 0..length {
        let byte = alphabet.choose(&mut OsRng).ok_or("empty character set")?;
        out.push(char::from(*byte));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::collections::BTreeSet;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn gen_defaults_are_length_20_all_classes() {
        let cli = Cli::try_parse_from(["pwdv", "gen"]).unwrap();
        match cli.command {
            Command::Gen { length, charset } => {
                assert_eq!(length, 20);
                assert_eq!(charset, Charset::ALL);
            }
            _ => panic!("expected gen"),
        }
    }

    #[test]
    fn gen_parses_charset_list_and_rejects_zero_length() {
        let cli = Cli::try_parse_from(["pwdv", "gen", "-l", "8", "-c", "digits,lower"]).unwrap();
        match cli.command {
            Command::Gen { length, charset } => {
                assert_eq!(length, 8);
                assert_eq!(charset, [Charset::Digits, Charset::Lower]);
            }
            _ => panic!("expected gen"),
        }
        assert!(Cli::try_parse_from(["pwdv", "gen", "-l", "0"]).is_err());
    }

    #[test]
    fn generate_respects_length_and_charset() {
        let pw = generate(64, &[Charset::Digits]).unwrap();
        assert_eq!(pw.len(), 64);
        assert!(pw.bytes().all(|b| b.is_ascii_digit()), "{}", pw.as_str());
    }

    /// Su 20 000 estrazioni da 36 simboli ognuno esce (probabilità di mancarne
    /// uno ~ 36 * (35/36)^20000, trascurabile) e nessun altro compare.
    #[test]
    fn generate_covers_exactly_the_alphabet() {
        let pw = generate(20_000, &[Charset::Lower, Charset::Digits]).unwrap();
        let seen: BTreeSet<u8> = pw.bytes().collect();
        let expected: BTreeSet<u8> = (b'a'..=b'z').chain(b'0'..=b'9').collect();
        assert_eq!(seen, expected);
    }

    #[test]
    fn two_generations_differ() {
        let a = generate(20, &Charset::ALL).unwrap();
        let b = generate(20, &Charset::ALL).unwrap();
        assert_ne!(a, b);
    }
}

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Gates whether a saved `processed` count from a prior run may be reused - a
/// mismatch on any field means a different candidate stream, so resuming would
/// silently skip words that were never actually checked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResumeContext {
    pub scheme: String,
    pub salt: String,
    pub mutate: bool,
    pub modes: Vec<bool>,
}

#[derive(Serialize, Deserialize)]
struct ProgressFile {
    inputfile: Option<String>,
    processed: u64,
    context: ResumeContext,
}

/// Streams unique, non-empty words from any line-oriented reader. Reads raw bytes
/// and lossily decodes each line so malformed UTF-8 in third-party wordlists
/// (common in real-world dumps like rockyou.txt) doesn't abort the whole scan.
fn dedup_lines<R: BufRead>(mut reader: R) -> impl Iterator<Item = String> {
    let mut seen: HashSet<String> = HashSet::new();
    std::iter::from_fn(move || loop {
        let mut buf = Vec::new();
        let bytes_read = reader.read_until(b'\n', &mut buf).unwrap_or(0);
        if bytes_read == 0 {
            return None;
        }
        let word = String::from_utf8_lossy(&buf).trim().to_string();
        if word.is_empty() || seen.contains(&word) {
            continue;
        }
        seen.insert(word.clone());
        return Some(word);
    })
}

pub fn read_dictionary(path: &Path) -> io::Result<impl Iterator<Item = String>> {
    let file = File::open(path)?;
    Ok(dedup_lines(BufReader::new(file)))
}

/// Same dedup/streaming behavior as `read_dictionary`, for the wordlist embedded
/// into the binary at compile time instead of a file on disk.
pub fn read_dictionary_str(contents: &'static str) -> impl Iterator<Item = String> {
    dedup_lines(io::Cursor::new(contents.as_bytes()))
}

/// A found WIF is a real, spendable private key - keep the file readable by the
/// owner only, regardless of the process umask.
pub fn write_discovery(
    output_file: &Path,
    address: &str,
    password: &str,
    wif: &str,
    balance: &str,
) -> io::Result<()> {
    let entry = serde_json::json!({
        "address": address,
        "password": password,
        "wif": wif,
        "balance": balance,
    });
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(output_file)?;
    writeln!(file, "{entry}")?;
    fs::set_permissions(output_file, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn progress_file_path(output_file: &Path) -> PathBuf {
    let mut name = output_file.as_os_str().to_owned();
    name.push(".progress.json");
    PathBuf::from(name)
}

/// Returns the number of already-checked candidates, or `None` if no resumable run
/// matches this input file and context (e.g. derivation scheme, modes, mutation).
pub fn read_progress(
    progress_file: &Path,
    input_file: Option<&Path>,
    context: &ResumeContext,
) -> Option<u64> {
    let data = fs::read_to_string(progress_file).ok()?;
    let parsed: ProgressFile = serde_json::from_str(&data).ok()?;
    let expected_inputfile = input_file.map(|p| p.to_string_lossy().to_string());
    if parsed.inputfile != expected_inputfile || parsed.context != *context {
        return None;
    }
    Some(parsed.processed)
}

pub fn write_progress(
    progress_file: &Path,
    input_file: Option<&Path>,
    processed: u64,
    context: &ResumeContext,
) -> io::Result<()> {
    let data = ProgressFile {
        inputfile: input_file.map(|p| p.to_string_lossy().to_string()),
        processed,
        context: context.clone(),
    };
    fs::write(progress_file, serde_json::to_string(&data).unwrap())
}

pub fn clear_progress(progress_file: &Path) -> io::Result<()> {
    match fs::remove_file(progress_file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn sample_context() -> ResumeContext {
        ResumeContext {
            scheme: "sha256".to_string(),
            salt: String::new(),
            mutate: false,
            modes: vec![false, true],
        }
    }

    #[test]
    fn read_dictionary_dedups_and_skips_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("words.txt");
        fs::write(&path, "alpha\n\nalpha\nbeta\n  \nbeta\ngamma").unwrap();

        let words: Vec<String> = read_dictionary(&path).unwrap().collect();
        assert_eq!(words, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn read_dictionary_tolerates_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("words.txt");
        let mut bytes = b"good\n".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe, b'\n']);
        bytes.extend_from_slice(b"also_good\n");
        fs::write(&path, bytes).unwrap();

        let words: Vec<String> = read_dictionary(&path).unwrap().collect();
        assert_eq!(words[0], "good");
        assert_eq!(words.last().unwrap(), "also_good");
    }

    #[test]
    fn write_discovery_round_trips_special_characters_as_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.txt");
        write_discovery(&path, "1Addr", "pass|word\nwith\"quotes", "wif123", "0.5").unwrap();

        let mut contents = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed["password"], "pass|word\nwith\"quotes");
        assert_eq!(parsed["address"], "1Addr");

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn progress_round_trips_when_context_matches() {
        let dir = tempfile::tempdir().unwrap();
        let progress_path = dir.path().join("output.txt.progress.json");
        let context = sample_context();
        let input = PathBuf::from("words.txt");

        write_progress(&progress_path, Some(&input), 42, &context).unwrap();
        assert_eq!(
            read_progress(&progress_path, Some(&input), &context),
            Some(42)
        );
    }

    #[test]
    fn progress_is_ignored_when_context_or_input_differs() {
        let dir = tempfile::tempdir().unwrap();
        let progress_path = dir.path().join("output.txt.progress.json");
        let context = sample_context();
        let input = PathBuf::from("words.txt");
        write_progress(&progress_path, Some(&input), 42, &context).unwrap();

        let mut different_context = context.clone();
        different_context.scheme = "warpwallet".to_string();
        assert_eq!(
            read_progress(&progress_path, Some(&input), &different_context),
            None
        );

        let different_input = PathBuf::from("other.txt");
        assert_eq!(
            read_progress(&progress_path, Some(&different_input), &context),
            None
        );
    }

    #[test]
    fn clear_progress_is_a_no_op_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let progress_path = dir.path().join("missing.progress.json");
        assert!(clear_progress(&progress_path).is_ok());
    }
}

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use indicatif::ProgressBar;
use rayon::prelude::*;
use rusqlite::Connection;
use secp256k1::{All, Secp256k1};

use crate::file_management::{self, ResumeContext};
use crate::offline_db::{OfflineBalanceChecker, QUERY_CHUNK_SIZE};
use crate::privatekey::{addresses_from_private_key, wif_from_private_key};
use crate::schemes::Scheme;

const CHUNK_SIZE: usize = 1000;

pub struct Candidate {
    pub word: String,
    pub privkey: [u8; 32],
    pub compressed: bool,
    pub address: String,
}

pub struct ScanConfig {
    pub modes: Vec<bool>,
    pub scheme: Scheme,
    pub resume_context: ResumeContext,
}

pub struct ScanSummary {
    pub discoveries: Vec<String>,
    pub balance_total_satoshi: u64,
}

pub fn satoshi_to_btc_string(satoshi: u64) -> String {
    format!("{}.{:08}", satoshi / 100_000_000, satoshi % 100_000_000)
}

fn candidates_for_word(
    secp: &Secp256k1<All>,
    word: &str,
    scheme: &Scheme,
    modes: &[bool],
) -> Vec<Candidate> {
    let privkey = scheme.derive(word);
    // One EC scalar multiplication per word, not one per mode - compressed and
    // uncompressed addresses are just two encodings of the same point.
    let Some(addresses) = addresses_from_private_key(secp, &privkey, modes) else {
        return Vec::new();
    };
    addresses
        .into_iter()
        .map(|(compressed, address)| Candidate {
            word: word.to_string(),
            privkey,
            compressed,
            address,
        })
        .collect()
}

fn derive_chunk(
    words: &[String],
    secp: &Secp256k1<All>,
    scheme: &Scheme,
    modes: &[bool],
) -> Vec<Candidate> {
    words
        .par_iter()
        .flat_map(|word| candidates_for_word(secp, word, scheme, modes))
        .collect()
}

/// Injectable balance source - lets tests substitute a fake lookup instead of a
/// real SQLite index, the same way the Python tests monkeypatched `balance_checker.check`.
pub trait BalanceLookup: Send + Sync {
    fn check_chunk(&self, addresses: &[&str]) -> HashMap<String, u64>;
}

/// Looks up balances in a local SQLite index. `rusqlite::Connection` is `!Sync`, so
/// each rayon worker thread lazily opens and keeps its own read-only connection.
pub struct SqliteBalanceLookup {
    db_path: PathBuf,
}

impl SqliteBalanceLookup {
    pub fn new(db_path: impl Into<PathBuf>) -> Self {
        SqliteBalanceLookup {
            db_path: db_path.into(),
        }
    }
}

thread_local! {
    static THREAD_CONNECTION: RefCell<Option<(PathBuf, Connection)>> = const { RefCell::new(None) };
}

impl BalanceLookup for SqliteBalanceLookup {
    fn check_chunk(&self, addresses: &[&str]) -> HashMap<String, u64> {
        THREAD_CONNECTION.with(|cell| {
            let mut slot = cell.borrow_mut();
            let needs_open = !matches!(&*slot, Some((path, _)) if path == &self.db_path);
            if needs_open {
                let connection = OfflineBalanceChecker::open_connection(&self.db_path)
                    .expect("offline balance index could not be opened");
                *slot = Some((self.db_path.clone(), connection));
            }
            let (_, connection) = slot.as_ref().unwrap();
            OfflineBalanceChecker::check(connection, addresses, QUERY_CHUNK_SIZE)
                .expect("offline balance lookup query failed")
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn launch(
    words: impl Iterator<Item = String>,
    output_file: &Path,
    progress_file: &Path,
    input_file_for_progress: Option<&Path>,
    balance_lookup: &dyn BalanceLookup,
    config: &ScanConfig,
    secp: &Secp256k1<All>,
    progress_bar: &ProgressBar,
) -> Result<ScanSummary> {
    let modes_len = config.modes.len().max(1);
    let resume_count = file_management::read_progress(
        progress_file,
        input_file_for_progress,
        &config.resume_context,
    )
    .unwrap_or(0);
    if resume_count > 0 {
        progress_bar.println(format!(
            "Resuming: skipping {resume_count} already-checked candidates"
        ));
    }
    progress_bar.set_position(resume_count);

    let words_to_skip = (resume_count / modes_len as u64) as usize;
    let first_word_remaining_skip = (resume_count % modes_len as u64) as usize;

    let mut words_iter = words.skip(words_to_skip);
    let mut discoveries: Vec<String> = Vec::new();
    let mut balance_total_satoshi: u64 = 0;
    let mut processed = resume_count;

    // Software-pipelined: while chunk N's addresses are looked up against SQLite
    // (sequential, on this thread), chunk N+1 is derived in parallel on the rayon
    // pool at the same time, instead of leaving the pool idle during every lookup.
    let first_chunk_words: Vec<String> = (&mut words_iter).take(CHUNK_SIZE).collect();
    let mut pending_candidates = if first_chunk_words.is_empty() {
        None
    } else {
        let mut candidates = derive_chunk(&first_chunk_words, secp, &config.scheme, &config.modes);
        let drain_count = first_word_remaining_skip.min(candidates.len());
        candidates.drain(0..drain_count);
        Some(candidates)
    };

    while let Some(current_candidates) = pending_candidates.take() {
        let next_chunk_words: Vec<String> = (&mut words_iter).take(CHUNK_SIZE).collect();
        let addresses: Vec<&str> = current_candidates
            .iter()
            .map(|c| c.address.as_str())
            .collect();

        let (balances, next_candidates) = if next_chunk_words.is_empty() {
            (balance_lookup.check_chunk(&addresses), Vec::new())
        } else {
            rayon::join(
                || balance_lookup.check_chunk(&addresses),
                || derive_chunk(&next_chunk_words, secp, &config.scheme, &config.modes),
            )
        };

        if !current_candidates.is_empty() {
            for candidate in &current_candidates {
                if let Some(&balance_satoshi) = balances.get(&candidate.address)
                    && balance_satoshi > 0
                    && !discoveries.contains(&candidate.address)
                {
                    let wif = wif_from_private_key(&candidate.privkey, candidate.compressed);
                    let balance_str = satoshi_to_btc_string(balance_satoshi);
                    progress_bar.println(format!("{} : {balance_str} BTC", candidate.address));
                    file_management::write_discovery(
                        output_file,
                        &candidate.address,
                        &candidate.word,
                        &wif,
                        &balance_str,
                    )?;
                    discoveries.push(candidate.address.clone());
                    balance_total_satoshi += balance_satoshi;
                }
            }

            processed += current_candidates.len() as u64;
            progress_bar.set_position(processed);
            file_management::write_progress(
                progress_file,
                input_file_for_progress,
                processed,
                &config.resume_context,
            )?;
        }

        pending_candidates = if next_chunk_words.is_empty() {
            None
        } else {
            Some(next_candidates)
        };
    }

    file_management::clear_progress(progress_file)?;
    Ok(ScanSummary {
        discoveries,
        balance_total_satoshi,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct FakeLookup {
        balances: HashMap<String, u64>,
        queried: Mutex<Vec<String>>,
    }

    impl FakeLookup {
        fn new(balances: HashMap<String, u64>) -> Self {
            FakeLookup {
                balances,
                queried: Mutex::new(Vec::new()),
            }
        }
    }

    impl BalanceLookup for FakeLookup {
        fn check_chunk(&self, addresses: &[&str]) -> HashMap<String, u64> {
            self.queried
                .lock()
                .unwrap()
                .extend(addresses.iter().map(|a| a.to_string()));
            addresses
                .iter()
                .filter_map(|a| self.balances.get(*a).map(|&b| (a.to_string(), b)))
                .collect()
        }
    }

    fn test_config() -> ScanConfig {
        ScanConfig {
            modes: vec![false, true],
            scheme: Scheme::Sha256,
            resume_context: ResumeContext {
                scheme: "sha256".to_string(),
                salt: String::new(),
                mutate: false,
                modes: vec![false, true],
            },
        }
    }

    fn target_address(secp: &Secp256k1<All>, word: &str, compressed: bool) -> String {
        let privkey = Scheme::Sha256.derive(word);
        crate::privatekey::address_from_private_key(secp, &privkey, compressed).unwrap()
    }

    #[test]
    fn finds_a_funded_address_and_writes_discovery() {
        let secp = Secp256k1::new();
        let address = target_address(&secp, "correct horse battery staple", false);
        let lookup = FakeLookup::new(HashMap::from([(address.clone(), 12_345_000u64)]));

        let dir = tempfile::tempdir().unwrap();
        let output_file = dir.path().join("output.txt");
        let progress_file = dir.path().join("output.txt.progress.json");
        let words = vec!["correct horse battery staple".to_string()].into_iter();

        let pbar = ProgressBar::hidden();
        let outcome = launch(
            words,
            &output_file,
            &progress_file,
            None,
            &lookup,
            &test_config(),
            &secp,
            &pbar,
        )
        .unwrap();

        assert_eq!(outcome.discoveries, vec![address]);
        assert_eq!(outcome.balance_total_satoshi, 12_345_000);
        assert!(!progress_file.exists());
        assert!(output_file.exists());
    }

    #[test]
    fn resume_skips_already_checked_candidates() {
        let secp = Secp256k1::new();
        let lookup = FakeLookup::new(HashMap::new());
        let dir = tempfile::tempdir().unwrap();
        let output_file = dir.path().join("output.txt");
        let progress_file = dir.path().join("output.txt.progress.json");
        let input_file = PathBuf::from("words.txt");

        // 3 words x 2 modes = 6 candidates; pretend 3 were already processed
        // (word "a" fully, plus the first mode of word "b").
        file_management::write_progress(
            &progress_file,
            Some(&input_file),
            3,
            &test_config().resume_context,
        )
        .unwrap();

        let words = vec!["a".to_string(), "b".to_string(), "c".to_string()].into_iter();
        let pbar = ProgressBar::hidden();
        let outcome = launch(
            words,
            &output_file,
            &progress_file,
            Some(&input_file),
            &lookup,
            &test_config(),
            &secp,
            &pbar,
        )
        .unwrap();

        assert!(outcome.discoveries.is_empty());

        let expected_queried: Vec<String> = vec![
            target_address(&secp, "b", true),
            target_address(&secp, "c", false),
            target_address(&secp, "c", true),
        ];
        let mut actually_queried = lookup.queried.lock().unwrap().clone();
        actually_queried.sort();
        let mut expected_sorted = expected_queried.clone();
        expected_sorted.sort();
        assert_eq!(actually_queried, expected_sorted);
        assert!(!progress_file.exists());
    }

    #[test]
    fn mismatched_resume_context_restarts_from_scratch() {
        let secp = Secp256k1::new();
        let lookup = FakeLookup::new(HashMap::new());
        let dir = tempfile::tempdir().unwrap();
        let output_file = dir.path().join("output.txt");
        let progress_file = dir.path().join("output.txt.progress.json");
        let input_file = PathBuf::from("words.txt");

        let mut stale_context = test_config().resume_context;
        stale_context.scheme = "warpwallet".to_string();
        file_management::write_progress(&progress_file, Some(&input_file), 99, &stale_context)
            .unwrap();

        let words = vec!["a".to_string()].into_iter();
        let pbar = ProgressBar::hidden();
        let outcome = launch(
            words,
            &output_file,
            &progress_file,
            Some(&input_file),
            &lookup,
            &test_config(),
            &secp,
            &pbar,
        )
        .unwrap();
        assert!(outcome.discoveries.is_empty());
    }
}

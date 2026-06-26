use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use secp256k1::Secp256k1;

use crate::file_management::{self, ResumeContext};
use crate::mutate::{self, APPROX_VARIANTS_PER_WORD};
use crate::offline_db;
use crate::scan::{self, ScanConfig, SqliteBalanceLookup};
use crate::schemes::{Scheme, WARPWALLET_APPROX_SECONDS_PER_DERIVATION};

const DEFAULT_WORDLIST: &str = include_str!("../data/default_wordlist.txt");

#[derive(Parser)]
#[command(
    name = "brainwallet-bruteforce",
    version,
    about = "Brute-force Bitcoin brainwallets from a wordlist against a local balance index."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Brute-force a wordlist against a local Bitcoin balance index
    Scan(ScanArgs),
    /// Build a local balance index from a Blockchair address dump
    BuildDb(BuildDbArgs),
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum SchemeArg {
    Sha256,
    Sha256d,
    Warpwallet,
}

impl SchemeArg {
    fn name(&self) -> &'static str {
        match self {
            SchemeArg::Sha256 => "sha256",
            SchemeArg::Sha256d => "sha256d",
            SchemeArg::Warpwallet => "warpwallet",
        }
    }
}

#[derive(clap::Args)]
struct ScanArgs {
    /// Words dictionary file (default: bundled wordlist)
    #[arg(short, long)]
    input: Option<PathBuf>,
    /// Output file
    #[arg(short, long, default_value = "output.txt")]
    output: PathBuf,
    /// Check compressed addresses only
    #[arg(short, long)]
    compressed: bool,
    /// Check uncompressed addresses only
    #[arg(short = 'u', long = "uncompressed-only")]
    uncompressed_only: bool,
    /// Number of worker threads (default: all logical CPUs)
    #[arg(short, long)]
    workers: Option<usize>,
    /// Expand each dictionary word with common mutations (case, leetspeak, digit/year
    /// suffixes) - much slower, wider coverage
    #[arg(short, long)]
    mutate: bool,
    /// Passphrase-to-private-key derivation scheme. 'warpwallet' is deliberately slow
    /// (~0.5s/word) and needs --salt.
    #[arg(long, value_enum, default_value_t = SchemeArg::Sha256)]
    scheme: SchemeArg,
    /// Salt for the warpwallet scheme (conventionally an email address). Ignored otherwise.
    #[arg(long, default_value = "")]
    salt: String,
    /// Required to actually run --mutate together with --scheme warpwallet, since that
    /// combination can take hours to days (see the estimate it prints first).
    #[arg(long = "force-slow-combo")]
    force_slow_combo: bool,
    /// Path to a local SQLite balance index built with 'build-db'
    #[arg(long = "db")]
    db: PathBuf,
}

#[derive(clap::Args)]
struct BuildDbArgs {
    /// Blockchair bitcoin-addresses TSV.GZ dump
    /// (download from https://gz.blockchair.com/bitcoin/addresses/)
    dump_file: PathBuf,
    /// Where to write the SQLite index
    #[arg(short, long, default_value = "balances.sqlite")]
    output: PathBuf,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => run_scan(args),
        Command::BuildDb(args) => run_build_db(args),
    }
}

fn estimate_slow_combo_seconds(word_count: usize) -> f64 {
    word_count as f64 * APPROX_VARIANTS_PER_WORD as f64 * WARPWALLET_APPROX_SECONDS_PER_DERIVATION
}

fn dictionary_words(input: &Option<PathBuf>) -> Result<Box<dyn Iterator<Item = String>>> {
    match input {
        Some(path) => {
            let iter = file_management::read_dictionary(path)
                .with_context(|| format!("dictionary file not found: {}", path.display()))?;
            Ok(Box::new(iter))
        }
        None => Ok(Box::new(file_management::read_dictionary_str(
            DEFAULT_WORDLIST,
        ))),
    }
}

fn run_scan(args: ScanArgs) -> Result<()> {
    if args.compressed && args.uncompressed_only {
        bail!("--compressed and --uncompressed-only can't be used together");
    }
    if !args.salt.is_empty() && args.scheme != SchemeArg::Warpwallet {
        bail!("--salt only applies to --scheme warpwallet");
    }
    if !args.db.exists() {
        bail!(
            "--db file not found: {} (build it first with 'build-db')",
            args.db.display()
        );
    }

    let modes: Vec<bool> = if args.compressed {
        println!("Address mode: compressed only");
        vec![true]
    } else if args.uncompressed_only {
        println!("Address mode: uncompressed only");
        vec![false]
    } else {
        println!("Address mode: uncompressed + compressed");
        vec![false, true]
    };

    let scheme_name = args.scheme.name();
    let scheme = Scheme::from_name(scheme_name, &args.salt).expect("scheme name is always valid");
    println!("Derivation scheme: {scheme_name}");
    if args.scheme == SchemeArg::Warpwallet {
        println!(
            "Warning: warpwallet is deliberately slow (~{WARPWALLET_APPROX_SECONDS_PER_DERIVATION}s/word) - \
             this run will be CPU-bound. Throughput will be far lower than with sha256."
        );
    }

    if let Some(workers) = args.workers {
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build_global()
            .ok();
    }

    println!("Balance index: {}", args.db.display());

    if args.mutate && args.scheme == SchemeArg::Warpwallet {
        let word_count = dictionary_words(&args.input)?.count();
        let estimated_hours = estimate_slow_combo_seconds(word_count) / 3600.0;
        println!(
            "Warning: --mutate (~{APPROX_VARIANTS_PER_WORD} variants/word) with --scheme warpwallet \
             (~{WARPWALLET_APPROX_SECONDS_PER_DERIVATION}s/derivation) on this {word_count}-word dictionary \
             is roughly {estimated_hours:.1} hours of work."
        );
        if !args.force_slow_combo {
            bail!(
                "Refusing to run --mutate with --scheme warpwallet without --force-slow-combo \
                 (see the estimate above)."
            );
        }
    }

    let mut words = dictionary_words(&args.input)?;
    if args.mutate {
        println!(
            "Mutation rules: ON (case, leetspeak, digit/year suffixes - expect many more candidates)"
        );
        words = Box::new(mutate::mutate_wordlist(words));
    }

    let resume_context = ResumeContext {
        scheme: scheme_name.to_string(),
        salt: args.salt.clone(),
        mutate: args.mutate,
        modes: modes.clone(),
    };
    let config = ScanConfig {
        modes,
        scheme,
        resume_context,
    };

    let secp = Secp256k1::new();
    let lookup = SqliteBalanceLookup::new(&args.db);
    let progress_file = file_management::progress_file_path(&args.output);

    let pbar = ProgressBar::no_length();
    pbar.set_style(
        ProgressStyle::with_template("{spinner} {pos} addr scanned ({per_sec})").unwrap(),
    );

    let outcome = scan::launch(
        words,
        &args.output,
        &progress_file,
        args.input.as_deref(),
        &lookup,
        &config,
        &secp,
        &pbar,
    )?;
    pbar.finish_and_clear();

    if outcome.discoveries.is_empty() {
        println!("We didn't find anything !");
    }
    println!(
        "You have found a total of {} btc",
        scan::satoshi_to_btc_string(outcome.balance_total_satoshi)
    );
    println!("Addresses with btc : {}", outcome.discoveries.len());

    Ok(())
}

fn run_build_db(args: BuildDbArgs) -> Result<()> {
    println!(
        "Building index at {} from {} ...",
        args.output.display(),
        args.dump_file.display()
    );
    let kept = offline_db::build_database(&args.dump_file, &args.output)?;
    println!("Done: indexed {kept} funded addresses.");
    Ok(())
}

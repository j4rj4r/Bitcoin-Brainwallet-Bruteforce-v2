fn main() {
    if let Err(e) = brainwallet_bruteforce::cli::run() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

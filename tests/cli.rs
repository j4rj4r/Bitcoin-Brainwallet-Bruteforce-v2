use assert_cmd::Command;
use predicates::str::contains;

fn bin() -> Command {
    Command::cargo_bin("brainwallet-bruteforce").unwrap()
}

#[test]
fn version_flag_reports_cargo_toml_version() {
    bin()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn rejects_compressed_and_uncompressed_only_together() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("balances.sqlite");
    std::fs::write(&db, b"").unwrap();

    bin()
        .args(["scan", "-c", "-u", "--db"])
        .arg(&db)
        .assert()
        .failure()
        .stderr(contains("--compressed and --uncompressed-only"));
}

#[test]
fn rejects_salt_without_warpwallet_scheme() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("balances.sqlite");
    std::fs::write(&db, b"").unwrap();

    bin()
        .args(["scan", "--salt", "me@example.com", "--db"])
        .arg(&db)
        .assert()
        .failure()
        .stderr(contains("--salt only applies to --scheme warpwallet"));
}

#[test]
fn rejects_missing_db_file() {
    bin()
        .args(["scan", "--db", "/does/not/exist.sqlite"])
        .assert()
        .failure()
        .stderr(contains("--db file not found"));
}

#[test]
fn requires_db_argument() {
    bin()
        .args(["scan"])
        .assert()
        .failure()
        .stderr(contains("--db"));
}

#[test]
fn refuses_mutate_with_warpwallet_without_force_flag() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("balances.sqlite");
    std::fs::write(&db, b"").unwrap();
    let wordlist = dir.path().join("words.txt");
    std::fs::write(&wordlist, "hello\nworld\n").unwrap();

    bin()
        .args(["scan", "-i"])
        .arg(&wordlist)
        .args(["-m", "--scheme", "warpwallet", "--salt", "x", "--db"])
        .arg(&db)
        .assert()
        .failure()
        .stderr(contains("--force-slow-combo"));
}

#[test]
fn build_db_requires_dump_file_argument() {
    bin().args(["build-db"]).assert().failure();
}

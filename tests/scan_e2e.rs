use std::fs;
use std::io::Write;

use assert_cmd::Command;
use flate2::Compression;
use flate2::write::GzEncoder;

fn bin() -> Command {
    Command::cargo_bin("brainwallet-bruteforce").unwrap()
}

/// Builds a balance index, then scans a wordlist against it through the real
/// compiled binary - proves the whole pipeline (build-db -> scan -> discovery
/// write) works end-to-end, not just the internal library calls.
#[test]
fn build_db_then_scan_finds_the_warpwallet_vector_address() {
    let dir = tempfile::tempdir().unwrap();

    let dump_path = dir.path().join("dump.tsv.gz");
    let file = fs::File::create(&dump_path).unwrap();
    let mut encoder = GzEncoder::new(file, Compression::default());
    writeln!(encoder, "address\tbalance").unwrap();
    writeln!(encoder, "1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ\t12345678").unwrap();
    writeln!(encoder, "some_spent_address\t0").unwrap();
    encoder.finish().unwrap();

    let db_path = dir.path().join("balances.sqlite");
    bin()
        .args(["build-db"])
        .arg(&dump_path)
        .args(["-o"])
        .arg(&db_path)
        .assert()
        .success();
    assert!(db_path.exists());

    let wordlist_path = dir.path().join("words.txt");
    fs::write(&wordlist_path, "ER8FT+HFjk0\nirrelevant_word\n").unwrap();

    let output_path = dir.path().join("output.txt");
    bin()
        .args(["scan", "-i"])
        .arg(&wordlist_path)
        .args(["--scheme", "warpwallet", "--salt", "7DpniYifN6c", "--db"])
        .arg(&db_path)
        .args(["-o"])
        .arg(&output_path)
        .assert()
        .success();

    let contents = fs::read_to_string(&output_path).unwrap();
    let entry: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
    assert_eq!(entry["address"], "1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ");
    assert_eq!(entry["password"], "ER8FT+HFjk0");
    assert_eq!(
        entry["wif"],
        "5JfEekYcaAexqcigtFAy4h2ZAY95vjKCvS1khAkSG8ATo1veQAD"
    );
    assert_eq!(entry["balance"], "0.12345678");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&output_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

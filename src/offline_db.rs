use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::{Connection, OpenFlags, params};

const CREATE_TABLE_SQL: &str =
    "CREATE TABLE balances (address TEXT PRIMARY KEY, balance_satoshi INTEGER NOT NULL)";
const COMMIT_EVERY: usize = 50_000;
pub const QUERY_CHUNK_SIZE: usize = 500;

/// Builds a local SQLite index of funded addresses from a Blockchair
/// "bitcoin addresses" TSV.GZ dump (https://gz.blockchair.com/bitcoin/addresses/).
///
/// Only addresses with a non-zero balance are kept - most addresses in Bitcoin's
/// history have since been spent down to zero, so this is a small fraction of the
/// full dump. Returns the number of addresses indexed.
pub fn build_database(dump_path: &Path, db_path: &Path) -> Result<usize> {
    let mut connection = Connection::open(db_path)?;
    connection.execute_batch(&format!(
        "DROP TABLE IF EXISTS balances; {CREATE_TABLE_SQL}"
    ))?;

    let file = File::open(dump_path)
        .with_context(|| format!("cannot open dump file {}", dump_path.display()))?;
    let mut reader = BufReader::new(GzDecoder::new(file));

    let pbar = ProgressBar::no_length();
    pbar.set_style(
        ProgressStyle::with_template("{spinner} {pos} rows indexed ({per_sec})").unwrap(),
    );

    let mut header = String::new();
    reader.read_line(&mut header)?; // skip header row

    let mut batch: Vec<(String, i64)> = Vec::with_capacity(COMMIT_EVERY);
    let mut kept = 0usize;
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            break;
        }
        pbar.inc(1);
        let mut parts = line.trim_end_matches('\n').split('\t');
        let (Some(address), Some(balance_str)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(balance_satoshi) = balance_str.parse::<i64>() else {
            continue;
        };
        if balance_satoshi <= 0 {
            continue;
        }
        batch.push((address.to_string(), balance_satoshi));
        kept += 1;
        if batch.len() >= COMMIT_EVERY {
            insert_batch(&mut connection, &batch)?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        insert_batch(&mut connection, &batch)?;
    }
    pbar.finish_and_clear();

    Ok(kept)
}

fn insert_batch(connection: &mut Connection, batch: &[(String, i64)]) -> rusqlite::Result<()> {
    let tx = connection.transaction()?;
    {
        let mut stmt = tx.prepare("INSERT OR REPLACE INTO balances VALUES (?1, ?2)")?;
        for (address, balance_satoshi) in batch {
            stmt.execute(params![address, balance_satoshi])?;
        }
    }
    tx.commit()
}

/// Looks up balances (in satoshis) from a local SQLite index instead of any network API.
pub struct OfflineBalanceChecker;

impl OfflineBalanceChecker {
    /// Opens a fresh read-only connection to `db_path`. Cheap enough to call once per
    /// worker thread - `rusqlite::Connection` is `!Sync`, so each thread needs its own.
    pub fn open_connection(db_path: &Path) -> rusqlite::Result<Connection> {
        Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
    }

    pub fn check<S: AsRef<str>>(
        connection: &Connection,
        addresses: &[S],
        chunk_size: usize,
    ) -> rusqlite::Result<HashMap<String, u64>> {
        let mut balances = HashMap::new();
        for chunk in addresses.chunks(chunk_size.max(1)) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "SELECT address, balance_satoshi FROM balances WHERE address IN ({placeholders})"
            );
            let mut stmt = connection.prepare(&sql)?;
            let params_iter = rusqlite::params_from_iter(chunk.iter().map(|a| a.as_ref()));
            let mut rows = stmt.query(params_iter)?;
            while let Some(row) = rows.next()? {
                let address: String = row.get(0)?;
                let balance_satoshi: i64 = row.get(1)?;
                balances.insert(address, balance_satoshi as u64);
            }
        }
        Ok(balances)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    fn write_gzip_dump(path: &Path, rows: &[(&str, &str)]) {
        let file = File::create(path).unwrap();
        let mut encoder = GzEncoder::new(file, Compression::default());
        writeln!(encoder, "address\tbalance").unwrap();
        for (address, balance) in rows {
            writeln!(encoder, "{address}\t{balance}").unwrap();
        }
        encoder.finish().unwrap();
    }

    #[test]
    fn build_database_keeps_only_positive_balances() {
        let dir = tempfile::tempdir().unwrap();
        let dump_path = dir.path().join("dump.tsv.gz");
        let db_path = dir.path().join("balances.sqlite");
        write_gzip_dump(
            &dump_path,
            &[
                ("rich_addr", "12345"),
                ("spent_addr", "0"),
                ("malformed_addr", "not_a_number"),
            ],
        );

        let kept = build_database(&dump_path, &db_path).unwrap();
        assert_eq!(kept, 1);

        let connection = OfflineBalanceChecker::open_connection(&db_path).unwrap();
        let balances = OfflineBalanceChecker::check(
            &connection,
            &[
                "rich_addr".to_string(),
                "spent_addr".to_string(),
                "unknown_addr".to_string(),
            ],
            QUERY_CHUNK_SIZE,
        )
        .unwrap();
        assert_eq!(balances.get("rich_addr"), Some(&12345));
        assert_eq!(balances.get("spent_addr"), None);
        assert_eq!(balances.get("unknown_addr"), None);
    }

    #[test]
    fn check_chunks_large_address_lists() {
        let dir = tempfile::tempdir().unwrap();
        let dump_path = dir.path().join("dump.tsv.gz");
        let db_path = dir.path().join("balances.sqlite");
        let rows: Vec<(String, String)> = (0..1200)
            .map(|i| (format!("addr{i}"), "10".to_string()))
            .collect();
        let row_refs: Vec<(&str, &str)> =
            rows.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        write_gzip_dump(&dump_path, &row_refs);

        build_database(&dump_path, &db_path).unwrap();
        let connection = OfflineBalanceChecker::open_connection(&db_path).unwrap();
        let addresses: Vec<String> = (0..1200).map(|i| format!("addr{i}")).collect();
        let balances = OfflineBalanceChecker::check(&connection, &addresses, 500).unwrap();
        assert_eq!(balances.len(), 1200);
    }

    #[test]
    fn check_with_empty_addresses_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let dump_path = dir.path().join("dump.tsv.gz");
        let db_path = dir.path().join("balances.sqlite");
        write_gzip_dump(&dump_path, &[("addr", "10")]);
        build_database(&dump_path, &db_path).unwrap();

        let connection = OfflineBalanceChecker::open_connection(&db_path).unwrap();
        let balances =
            OfflineBalanceChecker::check(&connection, &[] as &[&str], QUERY_CHUNK_SIZE).unwrap();
        assert!(balances.is_empty());
    }
}

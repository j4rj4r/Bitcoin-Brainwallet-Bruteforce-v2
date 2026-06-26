# Bitcoin-Brainwallet-Bruteforce

A tool for brute-forcing Bitcoin brainwallets from a wordlist. For each candidate word it derives a
private key, derives the corresponding Bitcoin address, and checks that address against a local
balance index.

Candidate derivation is parallelized across all CPU cores with [rayon](https://github.com/rayon-rs/rayon).
Progress is saved as it goes, so an interrupted run can be resumed by simply rerunning the same command.

## Requirements
- Rust >= 1.80 (`rustup` recommended)
- A local balance index (see below)

## Install
```
cargo install --path .
```
This installs the `brainwallet-bruteforce` command. You can also run it directly from the repo with
`cargo run --release --` instead of installing.

## Building the balance index

Balance checks are done entirely against a local index built from a free
[Blockchair bitcoin-addresses dump](https://gz.blockchair.com/bitcoin/addresses/) (a daily snapshot of
every address that has ever held a balance, ~2 GB compressed):
```
curl -O https://gz.blockchair.com/bitcoin/addresses/blockchair_bitcoin_addresses_latest.tsv.gz
brainwallet-bruteforce build-db blockchair_bitcoin_addresses_latest.tsv.gz -o balances.sqlite
```
The index only keeps addresses with a non-zero balance at the time of the dump, so it's much smaller
than the raw download. Since balances change with every block, re-download and rebuild the index
periodically to stay current - a hit against a stale index is still worth a manual check, but the
index itself won't reflect very recent transactions.

## Usage

The bundled dictionary (20,000 common passwords) is used if none is given:
```
brainwallet-bruteforce scan --db balances.sqlite
```
Or define another dictionary to use:
```
brainwallet-bruteforce scan -i anotherdict.txt --db balances.sqlite
```
By default both compressed and uncompressed addresses are checked for every word. To check only one
form:
```
brainwallet-bruteforce scan --db balances.sqlite -c   # compressed only
brainwallet-bruteforce scan --db balances.sqlite -u   # uncompressed only
```
By default all logical CPUs are used. To limit concurrency:
```
brainwallet-bruteforce scan --db balances.sqlite -w 4
```
To widen coverage beyond the literal words in the dictionary, `-m`/`--mutate` expands every word into
common password variants (case changes, leetspeak substitutions, digit and year suffixes - roughly
400-600 variants per word). This finds far more than a plain wordlist, but takes proportionally longer
to run:
```
brainwallet-bruteforce scan --db balances.sqlite -m
```
By default, passphrases are turned into private keys with the classic `sha256(passphrase)` brainwallet
scheme. Other generators use different schemes, which are much less commonly checked by other tools -
`--scheme` lets you target those instead:
```
brainwallet-bruteforce scan --db balances.sqlite --scheme sha256d                          # double SHA256
brainwallet-bruteforce scan --db balances.sqlite --scheme warpwallet --salt me@example.com  # WarpWallet (https://keybase.io/warp/)
```
WarpWallet is deliberately expensive (scrypt with a high cost factor) and needs a salt - normally an
email address, but WarpWallet accepts any string. Because each derivation takes roughly half a second,
a `--scheme warpwallet` run is CPU-bound at a much lower rate than `sha256`: expect tens of words per
second per core, not hundreds of thousands.

Combining `-m` with `--scheme warpwallet` multiplies a per-word cost that's already slow by ~450
variants per word, which can add up to hours or days even for a modest dictionary. The CLI estimates
the total time for your dictionary and refuses to run that combination unless you also pass
`--force-slow-combo`.

If a run is interrupted (Ctrl+C or a crash), rerun the exact same command and it will pick up where it
left off. Resuming only applies if the scheme, salt, address modes and mutation setting all match the
interrupted run - otherwise it starts over, since a different scheme produces an entirely different set
of candidates.

Each funded address found is appended to the output file (created with `0600` permissions, since it
contains a real spendable private key) as one JSON object per line:
```
{"address": "...", "password": "...", "wif": "...", "balance": "..."}
```

## Development
```
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt
```

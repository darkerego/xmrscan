# Monero RPC Balance Scanner

An asynchronous Python utility for restoring, validating, scanning, and monitoring multiple Monero wallets through dedicated local `monero-wallet-rpc` processes and one or more remote or local `monerod` RPC endpoints.

It supports mixed private-key and mnemonic input, error recovery, offline address verification, adaptive subaddress lookup, cached wallet reuse, restore-height-aware cache rebuilding, multi-password cache import, transaction-history export, and optional, explicitly enabled transfers of unlocked funds.

> **Important:** This project handles private spend keys, seed phrases, wallet passwords, and real funds. Keep the input and generated secret files private. The scanner does not transmit private keys to a `monerod` endpoint, but the local `monero-wallet-rpc` processes necessarily handle them.

## Why Monero wallet scanning is computationally expensive

Monero balance discovery is fundamentally different from scanning a transparent blockchain such as Bitcoin, Ethereum, or most EVM chains. On those networks, an explorer or indexer can generally associate an address with visible transactions, outputs, or account balances. **A normal Monero transaction does not publicly identify the recipient's wallet address, and its transferred amounts are hidden.** Consequently, the scanner cannot simply ask a blockchain explorer or daemon for an address's balance.

Instead, **each Monero wallet must examine blockchain transaction outputs using its private view key** to determine whether they belong to that wallet. This involves deriving shared secrets from transaction public keys, checking one-time output keys, and decoding amounts for outputs that match. The wallet must also track which discovered outputs have been spent to calculate the spendable balance. In practical terms:

1. The daemon supplies blocks and transaction data, but it does not provide a public address-to-balance index.
2. `monero-wallet-rpc` performs wallet-specific cryptographic checks over the blocks covered by that wallet's restore height and scan state.
3. **Scanning hundreds or thousands of unrelated wallets repeats much of this work separately for every wallet.** The cost depends on the number of outputs examined, not just on how many transactions ultimately belong to those wallets.
4. Monero's **view tags** make it possible to reject most irrelevant outputs cheaply, reducing expensive elliptic-curve operations, but scanning still requires processing transaction data and performing cryptographic checks.
5. Restoring from an unnecessarily early block height, requesting very large subaddress lookahead windows, and refreshing many wallets simultaneously can substantially increase CPU usage, memory pressure, network/RPC traffic, and total scan time.

This explains why a Monero scanner may take hours to build accurate wallet histories while a transparent-chain balance checker can often use a lightweight indexed RPC or explorer lookup. **The scanner's daemon and wallet RPC processes do different jobs:** the daemon provides blockchain data; the wallet RPC processes identify which outputs belong to each wallet.

For technical background, see [Monero wallet RPC documentation](https://docs.getmonero.org/interacting/monero-wallet-rpc-reference/) and [how view tags accelerate scanning](https://learnmemonero.com/en/technical/stealth/view-tags/).

### CPU sizing and parallel wallet workers

There are **three related concurrency controls** in this program:

| Option | What it controls |
| --- | --- |
| `--workers-per-rpc` | Maximum concurrent wallet-RPC worker processes assigned to one healthy `monerod` RPC endpoint. Each active worker can be scanning a different wallet. |
| `--wallet-threads` | Parallel-job thread limit passed as `--max-concurrency` to **each** `monero-wallet-rpc` subprocess. |
| `--max-total-workers` | Overall maximum number of wallet-RPC subprocesses across all configured daemon endpoints. |

A useful **starting heuristic for CPU-bound scans** is:

```text
concurrent wallet-RPC workers × wallet-threads ≲ logical CPU cores available to the scanner
```

The author has observed the best throughput when this approximate thread budget does **not exceed the VM's available CPU cores**. On a **16-core VM with a single daemon RPC endpoint**, a well-performing configuration has been **eight wallet workers with two wallet threads each**:

```bash
python3 xmrscan.py \
  --keys keys.lst \
  --rpcs rpcs.lst \
  --workers-per-rpc 8 \
  --wallet-threads 2 \
  --max-total-workers 8
```

That gives **8 workers × 2 threads = 16 configured parallel-job threads**, allowing up to eight wallets to scan concurrently. This is a tested workload-specific setting, **not a guarantee that exactly 16 OS threads will run or that 16 is optimal on every system**. Wallet RPC processes also have other threads and overhead. If `monerod` runs on the same VM, leave CPU and memory headroom for it; if it runs on another server, size this budget for the **machine running `monero-wallet-rpc`**, while also watching daemon RPC throughput and latency. Once the CPU is saturated, adding more workers may reduce overall throughput through contention rather than make scanning faster.

For practical tuning, start with `--wallet-threads 2`, increase `--workers-per-rpc` until total throughput stops improving, and watch overall **wallets completed per hour**, CPU utilization, RAM, and daemon RPC error/backoff rates. The ideal setting may differ between fresh historical rescans and already-synchronized cached wallets.

## Contents

- [Why Monero wallet scanning is computationally expensive](#why-monero-wallet-scanning-is-computationally-expensive)
- [CPU sizing and parallel wallet workers](#cpu-sizing-and-parallel-wallet-workers)
- [Requirements and installation](#requirements-and-installation)
- [Quick start](#quick-start)
- [Input formats](#input-formats)
- [Operating modes](#operating-modes)
- [Advanced key recovery and exports](#advanced-key-recovery-and-exports)
- [Subaddress discovery](#subaddress-discovery)
- [Restore heights and cache rebuilding](#restore-heights-and-cache-rebuilding)
- [Working with imported wallet caches](#working-with-imported-wallet-caches)
- [Password migration](#password-migration)
- [Persistent monitoring and transaction notifications](#persistent-monitoring-and-transaction-notifications)
- [Sweeping and journaling](#sweeping-and-journaling)
- [Output files and directories](#output-files-and-directories)
- [Automatic report backups](#automatic-report-backups)
- [Complete command-line reference](#complete-command-line-reference)
- [Troubleshooting](#troubleshooting)
- [Operational notes](#operational-notes)

## Requirements and installation

- Python **3.11 or newer**.
- The official **`monero-wallet-rpc`** executable available on `PATH`, or provided with `--wallet-rpc-bin`.
- An accessible `monerod` HTTP(S) JSON-RPC endpoint for blockchain scanning. Offline validation, offline address verification, and cache password migration do not need a synchronized daemon.
- Python packages: `aiohttp>=3.12`, `PyNaCl>=1.5`, `pycryptodome>=3.20`.
- For the full supported mnemonic set: `mnemonic>=0.21`, `monero>=1.1`, `bip-utils>=2.12.0`.

Create a Python environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install 'aiohttp>=3.12' 'PyNaCl>=1.5' 'pycryptodome>=3.20' 'mnemonic>=0.21' 'monero>=1.1' 'bip-utils>=2.12.0'
python xmrscan.py --help
```

Check the native executable separately:

```bash
monero-wallet-rpc --version
```

For a binary outside `PATH`, pass its actual filesystem location using `--wallet-rpc-bin`. The scanner runs an independent local wallet-RPC subprocess for each active worker and binds its RPC endpoint to `127.0.0.1` with digest authentication.

## Quick start

### 1. Prepare a keys file

Create `keys.lst` with one wallet entry per line. The parser accepts several formats described below. Blank lines and lines starting with `#` are ignored. A mixture of supported formats is allowed when `--key-format auto` (the default) is selected.

### 2. Prepare a node list

Create `rpcs.lst` with one daemon endpoint per line, for example:

```text
http://127.0.0.1:18081
```

Endpoints may use `http://` or `https://`. Comments and blank lines are ignored. Entries are probed for network, availability, and height, and duplicate endpoints are removed when they resolve to the same address and port.

### 3. Validate the key file without scanning blocks

```bash
python xmrscan.py \
  --keys keys.lst \
  --validate-only
```

Invalid entries are copied **verbatim** to `data/.error_keys` (or the selected `--data-dir`). This mode does not require `--rpcs` or normally start wallet RPC. Legacy mnemonic validity may still require wallet RPC during a later restoration.

### 4. Scan balances and export transaction history

```bash
python xmrscan.py \
  --keys keys.lst \
  --rpcs rpcs.lst \
  --restore-height 3000000 \
  --workers-per-rpc 4 \
  --max-total-workers 6 \
  --output xmr_balances.csv \
  --transactions-output xmr_transactions.csv
```

This creates or opens cached wallet files in `data/.xmr_wallet_cache/`, configures subaddress lookup, synchronizes each wallet, and exports balances to `data/xmr_balances.csv` and transfers to `data/xmr_transactions.csv`. Relative output names supplied on the command line are placed inside `data/`. The restore height applies when **creating** wallets, not retroactively to existing cached wallets unless a rebuild option is supplied.

## Input formats

The default `--key-format auto` recognizes the following line formats:

| Input form | Meaning |
| --- | --- |
| `address:view:spend` | Monero address, private view key, private spend key |
| `address:spend` | Monero address and private spend key; deterministic view key derived locally |
| `view:spend` | Private view and spend keys; primary address derived locally |
| Seed words | Monero mnemonic / Polyseed / BIP39 phrase |
| `address:seed words` | Supplied address plus a mnemonic |
| `bip39:seed words` | Explicit BIP39 override |
| `polyseed:seed words` | Explicit Polyseed override |
| `legacy:seed words` | Explicit Monero legacy override |
| `address:bip39:seed words` | Supplied address and explicit seed type |

The format names above describe the file syntax; use **actual wallet secrets** in your own file, not the descriptive words in the table.

### Mnemonic formats

| Family | Word counts | Implementation |
| --- | --- | --- |
| Monero Polyseed (Cake Wallet / Feather) | 16 | Local wordlist/checksum validation and key derivation with `bip-utils`; restored with `generate_from_keys` |
| Monero legacy / older short seeds | 12, 13, 14, 24, 25 | Monero wordlists and/or wallet-RPC restoration, depending on format |
| BIP39 | 12, 15, 18, 21, 24 | Local checksum validation, then Cake/Ledger/Trezor-style key derivation |

**Automatic format recognition** uses word counts plus applicable wordlist and checksum checks. Some 12- and 24-word phrases can be ambiguous. A supplied primary address can help distinguish legacy Monero from BIP39 and can distinguish supported BIP39 derivation conventions. BIP39 words alone **cannot prove** which app-specific derivation convention, account index, or optional passphrase originally generated the wallet. In automatic BIP39 mode, the program falls back to the Cake convention when no supplied address matches.

Relevant options: `--mnemonic-format`, `--mnemonic-language`, `--bip39-scheme`, `--bip39-account`, `--bip39-passphrase-file`, and `--seed-offset-file`.

The current Polyseed conversion rejects a nonempty `--seed-offset-file` rather than silently generating the wrong wallet. This combination is **not implemented**.

### Derived address differs from supplied address

The scanner keeps the original address for reporting and derives the actual wallet from the supplied usable keys. An address mismatch **does not prevent scanning or an explicitly enabled sweep**. The wallet actually loaded by wallet RPC must nevertheless match the expected derived wallet; a genuinely unrelated cached wallet is rejected or rebuilt.

For a supplied Monero subaddress, the program also attempts to verify which account and subaddress index it belongs to, subject to its lookahead limits.

## Operating modes

| Mode | Required switches | Blockchain sync? | Broadcasts transfers? |
| --- | --- | --- | --- |
| Input validation | `--keys keys.lst --validate-only` | No | No |
| Offline address verification | `--keys keys.lst --verify-addresses-only` | No | No |
| Standard balance scan | `--keys keys.lst --rpcs rpcs.lst` | Yes | No, unless an explicit sweep is enabled |
| Advanced offline recovery | `--keys keys.lst --advanced-key-recovery --validate-only` | No | No |
| Conditional cache recreation offline | `--keys keys.lst --restore-height 3000000 --rebuild-if-lower --validate-only` | No | No |
| Cached-wallet password migration | `--migrate-cache-passwords` plus password inputs | No | No |
| Persistent watch | `--watch-transfers` plus normal scan inputs | Yes, then continuous refresh | Only with separately enabled sweep options |

Offline address verification starts local wallet RPC in `--offline` mode. It does **not** call historical `refresh`, `rescan_blockchain`, `get_balance`, or transaction-sending RPCs. It saves `data/xmr_address_verification.csv` by default.

```bash
python xmrscan.py \
  --keys keys.lst \
  --verify-addresses-only \
  --max-total-workers 6 \
  --subaddress-lookahead 50:200 \
  --subaddress-search-limit 50:3200
```

`--validate-only` and `--verify-addresses-only` are different: the first primarily validates file contents and keys locally; the second **opens/restores wallets** to inspect their primary addresses and subaddresses through wallet RPC.

## Advanced key recovery and exports

Normal parsing can normalize key formatting, derive missing/invalid deterministic view keys, and attempt a limited set of verified spend-key repairs. Enable `--advanced-key-recovery` for a second pass which:

- Builds an index of supplied primary addresses across the **entire** input file.
- Cross-checks keys against addresses appearing on other lines, which helps identify mixed-up address/key pairs.
- Searches missing hexadecimal nibbles at every position, subject to a per-key candidate budget.
- Tests a one-character substitution in noncanonical 64-digit spend keys and removes one or two excess hex digits.
- Accepts altered key material only when it can be verified against an address or a suitable supplied view key.

Default advanced limits are **two missing hex digits** and **750,000 candidates per invalid key**. The limit can be raised for three missing digits, but an increased limit is not a guarantee of complete three-digit search.

```bash
python xmrscan.py \
  --keys keys.lst \
  --advanced-key-recovery \
  --corrected-keys-output all_valid_keys.lst \
  --fixed-keys-output repaired_only.lst \
  --validate-only
```

This command writes into `data/` by default:

- `data/all_valid_keys.lst`: locally usable original and repaired key pairs, plus applicable retained mnemonic entries and subaddress hints.
- `data/repaired_only.lst`: entries whose key material was repaired or whose supplied **primary** address was corrected. Unchanged valid keys are omitted.
- `data/.error_keys`: original unrecoverable lines.
- `data/.recovered_keys`: key pairs recovered by the advanced pass.
- `data/.key_crossmatches.csv`: matches between addresses and keys from different source lines.

Both key exports are optional and independent. If either export option is supplied **without a filename**, the default `data/.corrected_keys` or `data/.fixed_keys` is created in the output directory. Legacy mnemonic entries preserved in the full export still require RPC validation. A retained subaddress hint is not proof of ownership; use offline address verification for that.

`--no-key-recovery` disables recovery and cannot be combined with `--advanced-key-recovery`.

## Subaddress discovery

The scanner starts with an account/subaddress discovery window of `50:200`. If a supplied subaddress is not found, it can expand the lookahead adaptively up to `50:3200` by default. Verified indices are recorded in the output.

```bash
python xmrscan.py \
  --keys keys.lst \
  --verify-addresses-only \
  --subaddress-lookahead 50:1000 \
  --subaddress-search-limit 50:3200
```

The lookup runs **before** historical blockchain refresh; identifying a subaddress mathematically does not require synchronization. Increasing the discovery window for an already scanned cached wallet may require revisiting earlier blocks. The scanner tracks lookahead metadata and handles the required rescan in normal scanning mode; offline verification intentionally does not mark the wallet history as resynchronized.

A supplied primary address starting with `4` and a supplied subaddress starting with `8` are distinct address types on Monero mainnet. A higher BIP39 derivation *account* is a separate concept from a Monero subaddress index. Arbitrarily high subaddresses cannot be ruled out by any finite lookahead.

## Restore heights and cache rebuilding

`--restore-height` sets the earliest block to scan when **creating** a wallet. The default is `0` (genesis). Cached wallets resume from their saved state unless rebuilt; changing only the command-line height does not rewind an existing cache.

### Rebuild all selected cached wallets

```bash
python xmrscan.py \
  --keys keys.lst \
  --rpcs rpcs.lst \
  --restore-height 2500000 \
  --rebuild-cache \
  --max-total-workers 6
```

`--rebuild-cache` archives the selected cache files, recreates wallets at the requested restore height, and performs a normal synchronization. It is not compatible with `--validate-only`.

### Rebuild only caches originally restored from a *later* height

```bash
python xmrscan.py \
  --keys keys.lst \
  --rpcs rpcs.lst \
  --restore-height 2500000 \
  --rebuild-if-lower \
  --rebuild-unknown-height \
  --max-total-workers 6
```

`--rebuild-if-lower` compares `2500000` with the **original restore height** stored in each cache's `.restore-height.json` sidecar. It rebuilds only if the recorded height is **greater** than the requested value. Caches without trusted metadata are treated as *unknown*; `--rebuild-unknown-height` opts into rebuilding those as well. It does **not** use `get_height` as a substitute, because that reports the wallet's present scan cursor rather than its original restore height.

### Recreate offline and synchronize later

```bash
python xmrscan.py \
  --keys keys.lst \
  --restore-height 2500000 \
  --rebuild-if-lower \
  --rebuild-unknown-height \
  --validate-only
```

This particular combination runs wallet RPC offline to recreate affected wallet files but does not scan blocks. Subsequent normal runs synchronize the new caches. Both rebuild modes preserve unrelated cached wallets and existing sweep journals and archive selected files in `data/.xmr_wallet_cache/.restore_height_backups/`.

**Restore-height limitation:** If an older output is still unspent and you begin scanning after its creation block, the reconstructed wallet may omit it and show an incomplete balance. For full balance/history reconstruction, use a height at or before the wallet's first incoming transaction. See [Monero's restore-height guide](https://www.getmonero.org/resources/user-guides/change-restore-height.html).

## Working with imported wallet caches

Cached wallets use two principal files: the wallet cache file and its matching `.keys` file. They may also have restore-height and subaddress-lookahead JSON sidecars. Copy these together from the other server, preferably after stopping that server's wallet RPC processes. Do not overwrite an unrelated wallet with the same name or discard the local cache's shared password file.

### Try a list of existing passwords automatically

Create `wallet_passwords.txt` with one password per line in preferred order and restrict its permissions:

```bash
chmod 600 wallet_passwords.txt
python xmrscan.py \
  --keys keys.lst \
  --rpcs rpcs.lst \
  --cache-dir .xmr_wallet_cache \
  --cache-password-list wallet_passwords.txt \
  --max-total-workers 6
```

For each cached wallet the scanner tries unique passwords from the list in order, then its local `.wallet-password` as a fallback. It advances on recognized password-rejection errors; unrelated RPC failures are not silently treated as invalid passwords. The successful password is kept in memory and not logged or written into a per-wallet mapping.

Password list details:

- Each **nonempty** line is one literal password.
- Leading/trailing spaces and `#` characters are **significant**; lines are not treated as comments.
- Duplicate values are tried only once.
- The file must be at most 1 MiB and contain at most 10,000 unique nonempty values.
- Importing caches with `--cache-password-list` **does not change** their encrypted passwords.

The same list works with `--verify-addresses-only` to inspect imported wallets without syncing them.

## Password migration

Use this as a **standalone** operation after importing caches. It needs neither `--keys` nor `--rpcs`:

```bash
python xmrscan.py \
  --cache-dir .xmr_wallet_cache \
  --migrate-cache-passwords \
  --cache-password-list wallet_passwords.txt \
  --new-cache-password-file new_wallet_password.txt
```

The target is the supplied new password or the existing `.wallet-password`. If they differ, the program keeps the current common password file until **all** cached wallets have been verified with the new target. The migration finds scanner-named `xmr_*.keys` wallets, copies encrypted wallet files into `.password_migration_backups/`, opens each with the candidate list (or `--old-cache-password-file`), calls Monero's `change_wallet_password` when needed, and verifies reopening with the target password.

You may use `--old-cache-password-file` instead of a list when all imported wallets have one password. Both can be provided, in which case the list is searched first and the single old password is appended as another candidate.

Migration is incompatible with concurrent scanning, rebuilding, watching, and validation; run it while other wallet-RPC processes using those caches are stopped. A partially failed migration leaves the prior encrypted backups available and reports the failure rather than declaring success.

## Persistent monitoring and transaction notifications

`--watch-transfers` leaves synchronized wallets open in dedicated wallet-RPC processes. It uses the native `--tx-notify` callback plus periodic `get_transfers` reconciliation, so a missed callback does not permanently hide new transactions. A persistent transaction-ID ledger establishes the initial history baseline and tracks subsequently seen receipts.

**One dedicated wallet-RPC process is required per watched wallet.** Unlike normal scanning, watch mode will not queue hundreds of wallets behind six processes. Select no more wallets than your configured worker/node capacity supports.

```bash
python xmrscan.py \
  --keys keys.lst \
  --rpcs rpcs.lst \
  --watch-transfers \
  --watch-lines 561-566 \
  --workers-per-rpc 6 \
  --max-total-workers 6 \
  --watch-refresh-seconds 20 \
  --watch-poll-seconds 60 \
  --watch-check-seconds 2
```

The `--watch-lines` selection refers to **physical line numbers in the original** `keys.lst`. The default watch refresh interval is 20 seconds, transaction reconciliation is 60 seconds, and notification-spool checking is 2 seconds. Monitoring continues until interrupted, with recovery/requeue behavior for transient RPC failures.

## Sweeping and journaling

The `--sweep-to` option supplies a destination and enables **dry-run reporting** by default. Live broadcasts require `--execute-sweeps`. The scanner uses Monero wallet RPC `sweep_all` on unlocked balances across wallet accounts and subaddresses.

A one-time sweep example that prompts for the destination interactively:

```bash
read -r -p 'Monero destination address: ' SWEEP_ADDRESS
python xmrscan.py \
  --keys keys.lst \
  --rpcs rpcs.lst \
  --sweep-to "$SWEEP_ADDRESS" \
  --execute-sweeps \
  --max-total-workers 6
```

For continuous sweeping **after outputs unlock**:

```bash
read -r -p 'Monero destination address: ' SWEEP_ADDRESS
python xmrscan.py \
  --keys keys.lst \
  --rpcs rpcs.lst \
  --watch-transfers \
  --watch-auto-sweep \
  --watch-lines 561-566 \
  --workers-per-rpc 6 \
  --max-total-workers 6 \
  --sweep-to "$SWEEP_ADDRESS" \
  --execute-sweeps
```

In watch mode, notifications report new incoming funds but spending occurs only when the wallet sees usable **unlocked outputs**. The watcher periodically rechecks unlock status even if no new notification arrives. The continuous sweep journal tracks the output identities used in each attempt so later deposits can be swept separately. Timeouts or uncertain submission outcomes are journaled instead of triggering blind duplicate broadcasts.

Journals:

- `data/.xmr_sweep_journal.jsonl`: regular one-time sweep attempts.
- `data/.xmr_watch_sweep_journal.jsonl`: watched unlocked-output sweep attempts.

Do not delete or edit active journals while wallet RPC processes are running. An interrupted transaction request can have been broadcast even if its RPC response was lost; consult the journal and wallet history before reconciling an ambiguous attempt. A different *supplied* address does not block an explicitly authorized sweep of a correctly derived wallet.

## Output files and directories

All generated files default to a **`data/` directory in the working directory**. The scanner creates it automatically. The input files (`keys.lst`, `rpcs.lst`, password lists, and seed-passphrase files) are read from the paths you supply and are not moved.

| Default path | Purpose |
| --- | --- |
| `data/xmr_balances.csv` | Balances, unlocked amounts, synchronization heights, sweep status, errors |
| `data/xmr_transactions.csv` | Incoming/outgoing transfers, UTC timestamps, fees, subaddress indices |
| `data/xmr_address_verification.csv` | Offline address/subaddress verification report |
| `data/.error_keys` | Original invalid or unrecoverable input lines |
| `data/.recovered_keys` | Verified repaired key pairs from advanced recovery |
| `data/.key_crossmatches.csv` | Supplied address matches to other key-file rows |
| `data/.corrected_keys` | Optional full corrected key list |
| `data/.fixed_keys` | Optional recovered/corrected-only key list |
| `data/.xmr_wallet_cache/` | Cached encrypted wallets, `.keys` files, wallet-RPC logs, metadata, notification spools |
| `data/.xmr_wallet_cache/.wallet-password` | Default password used when creating cached wallets |
| `data/.xmr_wallet_cache/.restore_height_backups/` | Archived encrypted caches before restore-height rebuilds |
| `data/.xmr_wallet_cache/.password_migration_backups/` | Archived encrypted caches before password changes |
| `data/.xmr_sweep_journal.jsonl` | Append-only one-time sweep journal |
| `data/.xmr_watch_sweep_journal.jsonl` | Append-only continuous sweep journal |
| `data/backups/` | Timestamped, retained snapshots of output files before they are replaced |

Specify a different output root with `--data-dir`. For example:

```bash
python xmrscan.py \
  --keys keys.lst \
  --rpcs rpcs.lst \
  --data-dir /srv/monero-scan/data \
  --max-total-workers 6
```

A relative `--output`, `--transactions-output`, `--cache-dir`, journal path, or key-export path is resolved **inside the data directory**. For example, `--output daily/balances.csv` creates `data/daily/balances.csv`; `--output data/balances.csv` is not prefixed twice. An **absolute** output path is still honored for compatibility, and its backups go in a `backups/` directory beside that file.

Existing outputs from older versions located outside `data/` are **not automatically moved or deleted**. If reusing an existing cache directory, move it into `data/.xmr_wallet_cache/` first, or pass its existing absolute location using `--cache-dir`.

## Automatic report backups

**Before opening or replacing an existing balance CSV, transaction CSV, verification report, invalid-key export, recovered-key export, or other generated snapshot, the scanner first writes a complete copy to a timestamped backup file.** Each backup uses a unique name and is retained; a later run does not overwrite an earlier backup.

Examples:

```text
data/
├── xmr_balances.csv
├── xmr_transactions.csv
├── xmr_address_verification.csv
├── .error_keys
├── .xmr_wallet_cache/
├── .xmr_sweep_journal.jsonl
└── backups/
    ├── xmr_balances.csv.20261031T184500.123456Z.a9b7c2d1e5.bak
    ├── xmr_transactions.csv.20261031T184500.234567Z.19f3a4b6c8.bak
    └── xmr_address_verification.csv.20261031T184600.345678Z.b7c1d2e3f4.bak
```

Backups are copied to a temporary file, flushed to disk, and renamed into place **before** the destination is truncated or replaced. If backup creation fails, the overwrite is aborted so the previous report is preserved. Both full reports and partial reports from interrupted runs are backed up on the next invocation.

Append-only sweep journals and notification ledgers are **not truncated**, so they do not need a backup on every scan. Cache rebuilds and password migration already archive the original encrypted wallet files separately. `data/backups/` can grow over time; there is no automatic deletion or retention limit. On POSIX, the backup directory is created owner-only and backup files use `0600` permissions.

## Complete command-line reference

The following option names and defaults are taken from the script's argument parser.

### Inputs and mnemonic derivation

| Option | Default | Description |
| --- | --- | --- |
| `--data-dir` | `data` | Root directory for generated reports, exports, journals, and caches |
| `--keys` | Required for all nonmigration workflows | Input key/mnemonic list |
| `--key-format` | `auto` | `auto`, `address-view-spend`, `address-spend`, `view-spend`, `mnemonic`, `address-mnemonic` |
| `--mnemonic-format` | `auto` | `auto`, `polyseed`, `legacy`, `mymonero`, `bip39` |
| `--mnemonic-language` | Not set | Seed-language override for legacy wallet RPC |
| `--bip39-scheme` | `auto` | `auto`, `cake`, `ledger`, `trezor` |
| `--bip39-account` | `0` | BIP39 derivation account index |
| `--bip39-passphrase-file` | Not set | File containing BIP39 passphrase |
| `--seed-offset-file` | Not set | Seed offset for supported legacy restoration; nonempty Polyseed offset is currently unsupported |
| `--network` | `mainnet` | `mainnet`, `testnet`, or `stagenet` |

### Validation, recovery, and export

| Option | Default | Description |
| --- | --- | --- |
| `--validate-only` | Off | Offline input validation; special offline recreation behavior with `--rebuild-if-lower` |
| `--verify-addresses-only` | Off | Verify primary/subaddresses offline with wallet RPC |
| `--verify-output` | `data/xmr_address_verification.csv` | Offline verification report |
| `--no-key-recovery` | Off | Disable ordinary spend/view key recovery |
| `--advanced-key-recovery` | Off | Search damaged hexadecimal keys and cross-reference addresses |
| `--advanced-max-missing-nibbles` | `2` | Largest missing hex-digit count attempted (1–3) |
| `--advanced-max-candidates` | `750000` | Maximum tested candidates per invalid key |
| `--advanced-progress-every` | `50000` | Progress interval in candidates; `0` disables |
| `--advanced-recovery-output` | `data/.recovered_keys` | Advanced recovered-key list |
| `--crossmatch-output` | `data/.key_crossmatches.csv` | Address cross-reference CSV |
| `--corrected-keys-output [PATH]` | Disabled | Export entire usable/corrected list; no path means `.corrected_keys` |
| `--fixed-keys-output [PATH]` | Disabled | Export only repaired/corrected entries; no path means `.fixed_keys` |

### Daemon connectivity and worker scheduling

| Option | Default | Description |
| --- | --- | --- |
| `--rpcs` | Not set | Text file of daemon RPC URLs; required for blockchain scans |
| `--wallet-rpc-bin` | `monero-wallet-rpc` | Local executable |
| `--workers-per-rpc` | `4` | Concurrent wallet workers assigned per healthy daemon |
| `--max-total-workers` | `32` | Total local wallet-RPC process cap |
| `--wallet-threads` | `2` | Max parallel-job threads per wallet-RPC subprocess (`monero-wallet-rpc --max-concurrency`); see [CPU sizing](#cpu-sizing-and-parallel-wallet-workers) |
| `--max-node-lag` | `20` | Maximum allowed lag behind the best probed node |
| `--probe-timeout` | `15` seconds | Initial daemon probe timeout |
| `--startup-timeout` | `40` seconds | Local wallet-RPC startup deadline |
| `--wallet-control-timeout` | `180` seconds | Short wallet RPC control timeout; historical refresh has no overall timeout |
| `--progress-interval` | `60` seconds | Long-running RPC progress log interval |
| `--retries` | `2` | Additional wallet attempts after initial failure |
| `--worker-start-retries` | `3` | Maximum wallet-RPC process startup failures |
| `--node-failure-threshold` | `2` | Failures before node cooldown |
| `--node-cooldown` | `45` seconds | Cooldown following repeated node failures |
| `--node-recovery-successes` | `3` | Successful scans used for capacity recovery, supplemented by health probes |
| `--node-recovery-ramp-seconds` | `5` | Health-probed capacity ramp; `0` immediately restores full capacity |
| `--daemon-ssl-ca-certificates` | System/default | HTTPS daemon CA bundle |
| `--daemon-ssl-allow-any-cert` | Off | Disable HTTPS daemon certificate verification |
| `--verbose` | Off | Additional debug logging |

### Caching, restore height, and passwords

| Option | Default | Description |
| --- | --- | --- |
| `--cache-dir` | `data/.xmr_wallet_cache` | Wallet-cache directory |
| `--restore-height` | `0` | Block height for newly restored wallets |
| `--rebuild-cache` | Off | Rebuild every selected cached wallet at explicitly supplied restore height |
| `--rebuild-if-lower` | Off | Rebuild only if recorded cached creation height is later than the requested height |
| `--rebuild-unknown-height` | Off | Also rebuild unknown-height caches with `--rebuild-if-lower` |
| `--cache-password-list` | Not set | Ordered candidate passwords for existing encrypted caches |
| `--migrate-cache-passwords` | Off | Standalone offline re-encryption of imported caches |
| `--old-cache-password-file` | Not set | Legacy single password candidate for migration |
| `--new-cache-password-file` | Not set | Common target password for migration |
| `--subaddress-lookahead` | `50:200` | Initial account/subaddress discovery window |
| `--subaddress-search-limit` | `50:3200` | Upper bound for adaptive supplied-subaddress lookup |

### Scanning output, watch mode, and sweeping

| Option | Default | Description |
| --- | --- | --- |
| `--output` | `data/xmr_balances.csv` | Balance results CSV |
| `--transactions-output` | `data/xmr_transactions.csv` | Transactions CSV |
| `--no-transactions` | Off | Skip transaction history RPC/export |
| `--watch-transfers` | Off | Keep selected wallets open and monitor receipts |
| `--watch-lines` | All valid wallet lines | Physical line numbers/ranges for watch mode |
| `--watch-refresh-seconds` | `20` | Wallet automatic refresh interval |
| `--watch-poll-seconds` | `60` | Transaction reconciliation interval |
| `--watch-check-seconds` | `2` | Notification-spool check interval |
| `--watch-auto-sweep` | Off | Sweep unlocked outputs repeatedly in watch mode |
| `--sweep-to` | Not set | Destination Monero address; dry run unless execution enabled |
| `--execute-sweeps` | Off | Authorize real outgoing transfers |
| `--sweep-priority` | `0` | Monero priority in the accepted 0–4 range |
| `--sweep-journal` | `data/.xmr_sweep_journal.jsonl` | One-time sweep journal |
| `--watch-sweep-journal` | `data/.xmr_watch_sweep_journal.jsonl` | Watched-output sweep journal |

### Argument constraints worth knowing

- `--rebuild-cache` and `--rebuild-if-lower` cannot be used together; both require an **explicit** `--restore-height`.
- `--rebuild-unknown-height` requires `--rebuild-if-lower`.
- `--rebuild-cache` cannot be used with `--validate-only`; `--rebuild-if-lower` **can**, and then recreates affected wallets offline.
- `--verify-addresses-only` cannot be combined with `--validate-only`, watch mode, or sweeping options.
- Password migration requires `--cache-password-list` and/or `--old-cache-password-file`, and must run separately from scanning and rebuilding.
- `--execute-sweeps` requires `--sweep-to`. In watch mode it additionally requires `--watch-auto-sweep`; watch auto-sweep requires all three switches.
- `--watch-lines` requires `--watch-transfers`, and selected wallets must fit the available dedicated worker capacity.
- `--advanced-key-recovery` and `--no-key-recovery` are mutually exclusive.
- The maximum subaddress lookahead product is 500,000 addresses, as constrained by the parser.

## Troubleshooting

**Wallet scans take hours or seem stuck during `refresh`.** A first restore from height `0` scans from genesis, and long `refresh` RPC calls are intentionally allowed to run without a total timeout. Look at the per-worker progress messages and `wallet-rpc-*.log` files. Increase `--progress-interval` for less frequent logs. Choose an appropriate earlier history boundary with `--restore-height`, but remember that outputs before that height will be omitted.

**A changed `--restore-height` appears to have no effect.** Cached wallets resume their saved scan cursor. Supply `--rebuild-if-lower`, or `--rebuild-cache` to force recreation. Imported caches without `.restore-height.json` are `UNKNOWN` unless you choose `--rebuild-unknown-height`.

**`Failed to derive subaddress public key` in Monero logs.** This can occur while examining particular transaction outputs and does not, by itself, prove bad wallet keys. Check whether the wallet continues syncing. Investigate persistent failures tied to a specific height or missing expected deposits.

**Supplied address does not match derived primary address.** The input may contain a different primary address, a valid subaddress, mixed-up rows, a different BIP39 derivation scheme, or an incorrect seed offset. Use `--verify-addresses-only` and, if necessary, advanced cross-match reporting. The scanner still scans the derived wallet; it does not silently treat a mismatched *cached wallet* as the correct one.

**Some mnemonic phrases are rejected.** Check the selected mnemonic family, BIP39 wordlist/checksum, account index, passphrase, and seed offset. Sixteen-word Polyseed support needs `bip-utils`; the implementation converts Polyseed locally rather than using the legacy RPC seed restore method. Unrecoverable original lines are written to `data/.error_keys` by default.

**Imported wallet cache will not open.** Ensure both wallet files were copied, try `--cache-password-list`, inspect wallet-RPC logs, and confirm the cache isn't in use by another server process. Corruption and genuine file errors are not fixed by additional password attempts.

**Node repeatedly disconnects or workers become idle.** Check `monerod` daemon health, daemon RPC limits, available RAM/CPU, `--workers-per-rpc`, and the node cooldown/recovery settings. The scheduler reduces concurrency on daemon-related failures and restores available capacity through independent health probes.

**The wallet has an incoming transaction but no immediate sweep.** Newly received funds are not necessarily unlocked/spendable. Watch mode checks unlocked outputs periodically, while the sweep journals can also prevent resubmission of an unresolved attempt. See wallet history and the relevant JSONL journal before retrying an uncertain transfer.

**File permissions or secret-file exposure.** Secure imported `keys.lst`, plaintext password lists, and any exported keys with restrictive permissions. Example:

```bash
chmod 600 keys.lst wallet_passwords.txt
```

## Operational notes

- The daemon endpoint may be local or remote; **wallet private keys stay in local wallet RPC**, not the remote `monerod` RPC request payload.
- Use the same Monero network (`mainnet`, `testnet`, or `stagenet`) across wallet restoration and daemon endpoints.
- A private view key **cannot always** be derived from the spend key for older nondeterministic wallet pairs. The scanner's deterministic fallback may yield a different address; compare against authoritative wallet records.
- Exported key files are sensitive even if named `.fixed_keys` or `.corrected_keys`; they can contain full spend-capable private keys.
- This tool is a locally run script, not a hosted service. Keep backups of both original key material and encrypted wallet files before restoration or password migration.
- The current CLI does not provide a standalone resume/checkpoint command; it resumes naturally through its existing cached wallet files.
- Exit status: `0` is normal successful completion, `1` is used for invalid/rejected entries or other recorded failures, `2` for configuration/startup failures, and `130` for an interrupt. In watch mode, normal operation is long-running and usually ends by interruption.

## Official Monero references

- [Monero wallet RPC reference](https://www.getmonero.org/resources/developer-guides/wallet-rpc.html)
- [Restoring a wallet from mnemonic seed](https://www.getmonero.org/resources/user-guides/restore_account.html)
- [Restoring a wallet from private keys](https://www.getmonero.org/resources/user-guides/restore_from_keys.html)
- [Changing the wallet restore height](https://www.getmonero.org/resources/user-guides/change-restore-height.html)

---

This README documents the supplied `xmrscan.py` version with multi-password cache import, advanced recovery, conditional restore-height rebuilding, offline address verification, and persistent monitoring. The instructions are based on its implemented argument parser and code paths; live behavior still depends on the installed Monero wallet-RPC version, available resources, and the chosen daemon.
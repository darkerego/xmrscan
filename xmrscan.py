#!/usr/bin/env python3
"""Concurrent Monero scanner with mnemonic restoration, sweeping, and dated transaction history.

Input wallets: one ADDRESS:PRIVATE_VIEW_KEY:PRIVATE_SPEND_KEY, ADDRESS:PRIVATE_SPEND_KEY,
PRIVATE_VIEW_KEY:PRIVATE_SPEND_KEY, a 16-word Cake Wallet/Feather Polyseed, a 24/25-word Monero legacy seed,
a 12/13/14-word old-style Monero seed, or a BIP39 phrase. BIP39 includes
Cake/Exodus-style, Ledger/Coinomi-style, and Trezor derivation choices.
Seed types are auto-detected using word count, Monero wordlist validation,
and BIP39 checksums. Ambiguous 12/24-word seeds use a supplied address to
choose the matching format; truly unresolved ambiguity is never guessed.
On invalid spend keys, the scanner attempts bounded, verified repairs:
formatting cleanup, 32-byte seed scalar reduction, endian reversal, and a
single lost hex digit. Opt-in --advanced-key-recovery cross-references all
supplied primary wallet addresses, tests one/two missing hex nibbles at every
position and repairs one corrupted nibble in a noncanonical 64-digit scalar.
Use --corrected-keys-output [PATH] for every usable keypair, or
--fixed-keys-output [PATH] to export ONLY entries where key material was
repaired or a mismatched supplied PRIMARY address was corrected. Both modes
can run together and neither modifies the input keys file. Originals
remain unchanged; unrecoverable entries remain in .error_keys.
Recovered keypairs are stored in an owner-only .recovered_keys file; supplied
addresses matched to a different input line appear in .key_crossmatches.csv. Guessed spend keys are accepted only if the supplied
address or deterministic view key independently validates them. Invalid
supplied view keys are replaced using the deterministic derivation from a
valid spend key; non-deterministic historical wallets can have different view
keys, so the supplied-address mismatch is explicitly logged. No secrets are logged.
If an input line includes an address different from the derived primary,
wallet RPC verifies it against the restored wallet's subaddresses. Subaddress
lookahead expands adaptively for supplied subaddresses, up to a bounded limit.
Cached wallets are rescanned if lookahead was enlarged after prior scanning.
A different or unverified supplied address is an informational discrepancy,
not a reason to skip scanning or an otherwise explicitly authorized sweep of
the correctly derived/restored wallet. The original address and verification
status are recorded in the balance CSV. A cached wallet whose actual primary
address differs from the keys used to derive its expected primary is still
rejected/recreated rather than allowing an unrelated cache to be spent.
If an existing key-based wallet cache opens to a primary address different
from the address derived from its keys, the scanner closes and deletes only
that mismatched cache pair and regenerates the wallet from the supplied keys.
Generated output defaults under data/ (--data-dir). All overwritten CSV reports
and key exports are first archived under data/backups/ with unique timestamps.
Wallet cache rebuild/migration retains its separate encrypted cache backups.
Input nodes: one HTTP(S) remote monerod JSON-RPC URL per line.

Requires Python 3.11+, aiohttp>=3.12, pynacl>=1.5, pycryptodome>=3.20.
For automatic 12/24-word mnemonic identification, install 'mnemonic>=0.21'
and 'monero>=1.1'. For 16-word Cake/Feather Polyseed, install 'bip-utils'.
16-word Polyseed is validated and converted to wallet keys locally before
calling generate_from_keys (v0.18.5.4 restore_deterministic_wallet only accepts
legacy Monero seed words). Also requires the official monero-wallet-rpc executable.

A configurable total of wallet-RPC processes share daemon endpoints, with
per-node concurrency limits, overload backoff and node failover.
Health-checked RPC recovery restores all idle worker slots without waiting
for long-running wallet scans to finish.

The remote daemons never receive the private keys. Wallet scans can run for
hours; refresh JSON-RPC requests have no total/read timeout, while short
wallet-control RPCs use a configurable timeout. Local wallet-RPC timeouts do
not, by themselves, mark the daemon unhealthy.

Optional --verify-addresses-only mode runs wallet RPC offline to restore/open
wallets and verify supplied primary/subaddresses without a blockchain refresh.
It writes an independent CSV and never broadcasts transactions.

Use --rebuild-cache to unconditionally rebuild caches at --restore-height;
--rebuild-if-lower only rebuilds when tracked wallet creation height exceeds
requested height. Old/imported caches are UNKNOWN unless restore metadata was
copied with them; --rebuild-unknown-height archives/recreates those on request.
--validate-only with --rebuild-if-lower recreates selected wallets OFFLINE.
--cache-password-list provides ordered fallback passwords for imported caches
in normal scanning, offline address verification, and password migration.
It never changes wallet encryption unless --migrate-cache-passwords is selected.
--migrate-cache-passwords changes offline cached wallet passwords using
--old-cache-password-file or --cache-password-list and the common cache password,
making backups first.
Wallet and lookahead cache files are archived before restoration.
Archived files remain in .restore_height_backups; old spends and outputs before
the chosen height will not be rediscovered by the freshly restored wallet.

Optional --watch-transfers mode retains synchronized wallets in dedicated
wallet RPC processes, enables --tx-notify and auto_refresh, and logs new
incoming transactions with a persistent per-wallet receipt ledger. With
--watch-auto-sweep, unlocked funds are swept through its existing journaled
sweep mechanism when the operator explicitly enables live execution.

Transaction history is exported by default to xmr_transactions.csv using the
wallet RPC get_transfers method. Dates are ISO-8601 UTC and transactions from
all wallet accounts are included. An optional post-sweep requery records new
locally pending transfers. No secret key or seed is written to CSV.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
from dataclasses import dataclass
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import hmac
import unicodedata
import ipaddress
import itertools
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import ssl
import sys
import tempfile
import time
from urllib.parse import urlsplit

try:
    import aiohttp
    from Crypto.Hash import keccak
    from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp
except ImportError as exc:
    raise SystemExit(
        "Missing Python dependency. Run: "
        "python -m pip install 'aiohttp>=3.12' 'pynacl>=1.5' 'pycryptodome>=3.20'"
    ) from exc

ATOMIC = Decimal("1000000000000")
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_BLOCK_SIZES = (0, 2, 3, 5, 6, 7, 9, 10, 11)
NETWORK_PREFIX = {"mainnet": 18, "testnet": 53, "stagenet": 24}
SUBADDRESS_PREFIX = {"mainnet": 42, "testnet": 63, "stagenet": 36}
FIELDS = (
    "line", "address", "supplied_address", "address_mismatch",
    "supplied_address_status", "supplied_account_index", "supplied_subaddress_index",
    "lookahead_accounts", "lookahead_subaddresses", "key_recovery", "seed_format", "balance_xmr", "unlocked_xmr",
    "balance_atomic",
    "unlocked_atomic", "wallet_height", "daemon_height", "rpc", "status", "error",
    "sweep_status", "sweep_txids", "sweep_amount_atomic", "sweep_fee_atomic", "sweep_error",
    "transaction_count", "incoming_count", "outgoing_count", "pending_count",
    "failed_count", "pool_count", "transactions_status"
)
TX_BUCKETS = ("in", "out", "pending", "failed", "pool")
TX_FIELDS = (
    "line", "wallet_address", "supplied_address", "address_mismatch", "txid", "direction", "state", "type",
    "timestamp_utc", "timestamp_unix", "timestamp_source", "block_height",
    "confirmations", "amount_xmr", "amount_atomic", "signed_amount_xmr",
    "fee_xmr", "fee_atomic", "account_index", "subaddress_index",
    "subaddress_indices_json", "transfer_address", "payment_id",
    "locked", "unlock_time", "double_spend_seen", "note",
    "destinations_json", "wallet_height", "daemon_height"
)
HEX_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
ADDRESS_RE = re.compile(r"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{95}$")
ED25519_SUBGROUP_ORDER = 2 ** 252 + 27742317777372353535851937790883648493
logger = logging.getLogger("xmrscan")

TX_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def write_tx_notification(path_text: str, txid: str) -> int:
    """Subprocess handler for Monero --tx-notify, given a single tx hash.

    The callback never performs transfers or reads wallet credentials.
    """
    if not TX_HASH_RE.fullmatch(txid):
        return 2
    path = Path(os.path.abspath(os.path.expanduser(path_text)))
    if not path.parent.is_dir() or path.is_symlink():
        return 2
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, (txid.lower() + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return 0


def parse_subaddress_lookahead(value: str) -> tuple[int, int]:
    """Monero's major:minor discovery window. Limit allocations to avoid OOM."""
    match = re.fullmatch(r"([0-9]+):([0-9]+)", value.strip())
    if not match:
        raise argparse.ArgumentTypeError("Expected ACCOUNTS:SUBADDRESSES, for example 50:2000")
    major, minor = map(int, match.groups())
    if not (1 <= major <= 10000 and 1 <= minor <= 100000):
        raise argparse.ArgumentTypeError("Both lookahead dimensions must be between 1 and 100000")
    if major * minor > 500000:
        raise argparse.ArgumentTypeError("Lookahead exceeds 500000 addresses; reduce its dimensions")
    return major, minor


def supplied_address_kind(value: str, network: str) -> str:
    """Return 'primary', 'subaddress' or 'invalid' after verifying checksum/network."""
    try:
        raw = monero_b58decode(value)
        if len(raw) != 69 or raw[-4:] != keccak256(raw[:-4])[:4]:
            return "invalid"
        if raw[0] == NETWORK_PREFIX[network]:
            return "primary"
        if raw[0] == SUBADDRESS_PREFIX[network]:
            return "subaddress"
    except ValueError:
        pass
    return "invalid"


def select_watch_lines(jobs: list, selection: str | None) -> list:
    """Choose explicit line numbers/ranges in the original keys file."""
    if not selection:
        return jobs
    chosen = set()
    for part in selection.split(","):
        part = part.strip()
        if re.fullmatch(r"[0-9]+", part):
            chosen.add(int(part))
        elif re.fullmatch(r"[0-9]+-[0-9]+", part):
            first, last = map(int, part.split("-"))
            if first > last or last - first > 100000:
                raise ValueError("Invalid --watch-lines range")
            chosen.update(range(first, last + 1))
        else:
            raise ValueError("--watch-lines must be comma-separated positive line numbers or ranges")
    return [job for job in jobs if job.line in chosen]


class TerminalColor:
    """ANSI colored console output with logging-style %-format arguments.

    Compatible with logger calls such as:
        c.info("Worker %d connected to %s", worker_id, node_url)
        c.warning("Retry in %.1f seconds", delay)
        c.error("Unexpected failure: %s", exc, exc_info=True)
        c.exception("Operation failed: %s", exc)

    Debug output is disabled by default; main() enables it with --verbose.
    """

    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    debug_enabled = False

    @classmethod
    def _emit(
            cls,
            symbol: str,
            bracket_color: str,
            symbol_color: str,
            message: object,
            *args: object,
            exc_info: object = None,
    ) -> None:
        """Print one formatted message and optionally its exception traceback."""
        # Match logging.Logger's msg % args behavior. The message may already
        # be formatted (or be a non-string object) when no args are supplied.
        formatted = str(message) % args if args else str(message)

        if cls.enabled:
            prefix = (
                f"{bracket_color}["
                f"{symbol_color}{symbol}"
                f"{bracket_color}]"
                f"{cls.RESET}"
            )
        else:
            prefix = f"[{symbol}]"

        print(f"{prefix}  {formatted}", flush=True)

        if exc_info:
            import traceback

            if isinstance(exc_info, tuple) and len(exc_info) == 3:
                exception_details = exc_info
            elif isinstance(exc_info, BaseException):
                exception_details = (
                    type(exc_info), exc_info, exc_info.__traceback__
                )
            else:
                exception_details = sys.exc_info()

            if exception_details[0] is not None:
                traceback.print_exception(*exception_details, file=sys.stdout)
                sys.stdout.flush()

    @classmethod
    def good(cls, message: object, *args: object) -> None:
        cls._emit("+", cls.GREEN, cls.YELLOW, message, *args)

    @classmethod
    def error(cls, message: object, *args: object,
              exc_info: object = None) -> None:
        cls._emit("!", cls.RED, cls.WHITE, message, *args,
                  exc_info=exc_info)

    @classmethod
    def bad(cls, message: object, *args: object) -> None:
        cls._emit("-", cls.RED, cls.WHITE, message, *args)

    @classmethod
    def info(cls, message: object, *args: object) -> None:
        cls._emit("i", cls.CYAN, cls.WHITE, message, *args)

    @classmethod
    def warn(cls, message: object, *args: object) -> None:
        cls._emit("!", cls.YELLOW, cls.WHITE, message, *args)

    @classmethod
    def warning(cls, message: object, *args: object) -> None:
        cls.warn(message, *args)

    @classmethod
    def debug(cls, message: object, *args: object) -> None:
        if cls.debug_enabled:
            cls._emit("*", cls.MAGENTA, cls.WHITE, message, *args)

    @classmethod
    def exception(cls, message: object, *args: object,
                  exc_info: object = True) -> None:
        cls.error(message, *args, exc_info=exc_info)


# Instantiate at module scope so functions work when this module is imported.
c = TerminalColor()


class WatchedTxLedger:
    """Persistent tx-id baseline; catches receipts after restarts or missed hooks."""

    def __init__(self, path: Path):
        self.path = path
        self.seen = set()
        self.initialized = path.is_file()
        if self.initialized:
            for raw in path.read_text(encoding="ascii").splitlines():
                if TX_HASH_RE.fullmatch(raw):
                    self.seen.add(raw.lower())

    def apply(self, ids: set[str]) -> set[str]:
        normalized = {t.lower() for t in ids if TX_HASH_RE.fullmatch(t)}
        new_ids = normalized - self.seen if self.initialized else set()
        if not self.initialized:
            # First activation: historical transactions form the baseline.
            self.initialized = True
        additions = normalized - self.seen
        if additions:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                for txid in sorted(additions):
                    os.write(fd, (txid + "\n").encode("ascii"))
                os.fsync(fd)
            finally:
                os.close(fd)
            self.seen.update(additions)
        elif not self.path.exists():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        return new_ids


class RPCError(Exception):
    pass


class RPCTransportError(RPCError):
    pass


class WalletRPCTransportError(RPCTransportError):
    """The *local wallet-RPC process* failed, not necessarily monerod.

    In particular, wallet-RPC request timeouts must not trigger daemon
    cooldown without independent evidence that monerod is unresponsive.
    """


@dataclass(slots=True)
class WalletJob:
    line: int
    view: str | None
    spend: str | None
    address: str
    name: str
    mnemonic: str | None = None
    retries: int = 0
    supplied_address: str | None = None
    key_recovery: str = ""
    seed_format: str = ""

    @property
    def address_mismatch(self) -> bool:
        return bool(self.supplied_address and self.address
                    and self.supplied_address != self.address)


@dataclass(frozen=True, slots=True)
class Node:
    url: str
    host: str
    port: int
    scheme: str
    height: int
    aliases: frozenset[str]

    @property
    def daemon_address(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def monero_b58encode(data: bytes) -> str:
    chunks = []
    for offset in range(0, len(data), 8):
        piece = data[offset:offset + 8]
        number = int.from_bytes(piece, "big")
        size = B58_BLOCK_SIZES[len(piece)]
        chars = ["1"] * size
        for index in range(size - 1, -1, -1):
            number, remainder = divmod(number, 58)
            chars[index] = B58_ALPHABET[remainder]
        if number:
            raise ValueError("Invalid Monero Base58 chunk")
        chunks.append("".join(chars))
    return "".join(chunks)


def derive_address(view: str, spend: str, network: str) -> str:
    """Encode prefix | public spend | public view | Keccak checksum."""
    spend_pub = crypto_scalarmult_ed25519_base_noclamp(bytes.fromhex(spend))
    view_pub = crypto_scalarmult_ed25519_base_noclamp(bytes.fromhex(view))
    payload = bytes((NETWORK_PREFIX[network],)) + spend_pub + view_pub
    address = monero_b58encode(payload + keccak256(payload)[:4])
    if len(address) != 95:
        raise ValueError("Unexpected address length")
    return address


def derive_view_key(spend: str) -> str:
    """Derive Monero's deterministic private view key from a private spend key.

    Hash the 32-byte secret spend scalar with Keccak-256 (NOT SHA3-256),
    then reduce that 256-bit value modulo the Ed25519 subgroup order,
    interpreting both values as little-endian integers.
    """
    if not HEX_KEY_RE.fullmatch(spend):
        raise ValueError("Private spend key must contain exactly 64 hex characters")
    raw = bytes.fromhex(spend)
    scalar = int.from_bytes(raw, "little")
    if not 0 < scalar < ED25519_SUBGROUP_ORDER:
        raise ValueError("Private spend key is not a valid canonical Monero scalar")
    hashed = keccak256(raw)
    reduced = int.from_bytes(hashed, "little") % ED25519_SUBGROUP_ORDER
    if not reduced:
        raise ValueError("Derived private view key was zero")
    return reduced.to_bytes(32, "little").hex()


SEED_WORD_COUNTS = frozenset((12, 13, 14, 15, 16, 18, 21, 24, 25))
SEED_FORMAT_TAGS = frozenset(("polyseed", "legacy", "mymonero", "bip39"))
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def normalize_mnemonic(value: str) -> str:
    """Normalize Unicode whitespace, preserving all seed words verbatim.

    The official wallet RPC validates legacy Monero seeds. Local bip_utils
    validates 16-word Polyseed; BIP39 is validated before BIP32 derivation.
    """
    words = value.strip().split()
    if len(words) not in SEED_WORD_COUNTS:
        raise ValueError(
            "Unknown mnemonic length: expected 16 Polyseed, 25/24 Monero legacy, "
            "13/14 MyMonero/old-style, or 12/15/18/21/24 BIP39 words")
    # BIP39 wordlists use Unicode NFKD: combining marks are valid parts of
    # words (e.g. decomposed French accents), even though str.isalpha() is false.
    if not all(word and all(unicodedata.category(char)[0] in ("L", "M")
                            for char in word) for word in words):
        raise ValueError("Mnemonic words must contain only Unicode letters/marks")
    return " ".join(words)


def bip39_valid_languages(seed: str) -> tuple[str, ...]:
    """Return checksum-valid BIP39 languages (not merely dictionary matches).

    No private seed is sent off-machine. For ambiguous 12/24-word phrases,
    checksum validation is required; missing dependency isn't silently treated
    as an invalid BIP39 seed.
    """
    try:
        from mnemonic import Mnemonic
    except ImportError as exc:
        raise ValueError(
            "Automatic 12/24-word seed detection requires the BIP39 validator: "
            "python3 -m pip install 'mnemonic>=0.21' 'monero>=1.1'") from exc
    return tuple(language for language in Mnemonic.list_languages()
                 if Mnemonic(language).check(seed))


def monero_legacy_candidates(seed: str, network: str) -> dict[str, str]:
    """Decode an unchecksummed 12/24-word Monero seed in known wordlists.

    Monero legacy 12/24-word forms have no checksum, so a word count alone
    cannot establish their identity. monero-python's legacy decoder validates
    membership in each Monero language dictionary and supplies canonical
    derived keys for optional address comparisons.
    """
    try:
        from monero.seed import Seed
        from monero.wordlists import list_wordlists
    except ImportError as exc:
        raise ValueError(
            "Automatic 12/24-word seed detection requires Monero wordlists: "
            "python3 -m pip install 'mnemonic>=0.21' 'monero>=1.1'") from exc
    candidates = {}
    for language in list_wordlists():
        try:
            wallet = Seed(seed, wordlist=language)
            address = derive_address(wallet.secret_view_key(),
                                     wallet.secret_spend_key(), network)
        except (ValueError, RuntimeError, IndexError, OverflowError, TypeError):
            continue
        candidates[str(language)] = address
    return candidates


def resolve_seed_format(seed: str, preferred: str = "auto", *,
                        supplied_address: str | None = None,
                        network: str = "mainnet",
                        bip39_passphrase: str = "",
                        bip39_account: int = 0) -> str:
    """Select Monero Polyseed, Monero legacy, or BIP39 from validated content.

    12/24 words are ambiguous by length. Both BIP39 checksum and Monero
    language-wordlist validation are performed. If both are valid, use the
    supplied wallet address to disambiguate. If no independent match exists,
    refuse to guess; the original line will go to .error_keys.

    For BIP39 address matching, try all supported derivation conventions.
    """
    count = len(seed.split())
    supported = {"polyseed": (16,), "legacy": (12, 13, 14, 24, 25),
                 "mymonero": (12, 13, 14), "bip39": (12, 15, 18, 21, 24)}
    if preferred != "auto":
        if preferred not in supported:
            raise ValueError(f"Unknown mnemonic format: {preferred}")
        if count not in supported[preferred]:
            raise ValueError(f"{preferred} seed does not support {count} words")
        if preferred == "bip39" and not bip39_valid_languages(seed):
            raise ValueError("BIP39 mnemonic has an invalid wordlist or checksum")
        return "legacy" if preferred == "mymonero" else preferred

    if count == 16:
        return "polyseed"
    if count in (13, 14, 25):
        return "legacy"
    if count in (15, 18, 21):
        if not bip39_valid_languages(seed):
            raise ValueError("BIP39 mnemonic has an invalid wordlist or checksum")
        return "bip39"
    if count not in (12, 24):
        raise ValueError(f"Cannot identify a {count}-word mnemonic")

    valid_bip39 = bool(bip39_valid_languages(seed))
    legacy = monero_legacy_candidates(seed, network)
    if valid_bip39 and not legacy:
        return "bip39"
    if legacy and not valid_bip39:
        return "legacy"
    if not legacy:
        raise ValueError(
            f"{count}-word seed is neither a checksum-valid BIP39 phrase "
            "nor a recognized Monero legacy mnemonic")

    # An unusually ambiguous phrase is simultaneously valid under both
    # dictionaries; wallet addresses can distinguish the derivations.
    if supplied_address:
        legacy_match = supplied_address in legacy.values()
        bip39_match = False
        for scheme in ("cake", "ledger", "trezor"):
            try:
                view, spend = bip39_monero_keys(
                    seed, bip39_passphrase, bip39_account, scheme)
                if derive_address(view, spend, network) == supplied_address:
                    bip39_match = True
            except (ValueError, RuntimeError):
                continue
        if legacy_match and not bip39_match:
            return "legacy"
        if bip39_match and not legacy_match:
            return "bip39"
    raise ValueError(
        f"Ambiguous {count}-word mnemonic: both BIP39 and Monero legacy "
        "are valid, with no unique matching address. Supply the correct "
        "primary address or explicitly tag the entry 'bip39:'/'legacy:'")


class PolyseedDependencyMissing(ValueError):
    """Environment is missing local Polyseed decoding, not an invalid wallet seed."""
    pass


def polyseed_to_wallet_keys(seed: str, network: str, seed_offset: str = "") -> tuple[str, str, str]:
    """Verify a 16-word Cake/Feather Polyseed and derive Monero wallet keys.

    v0.18.5.4 wallet RPC's restore_deterministic_wallet calls the legacy
    ElectrumWords::words_to_bytes, which cannot decode Polyseed. Instead,
    use bip_utils' Polyseed checksum and PBKDF2-HMAC-SHA256 keygen, reduce
    the resulting 32-byte seed to the Ed25519 subgroup, and restore through
    the already-supported generate_from_keys RPC.

    No mnemonic is sent to a remote daemon or logged.
    """
    if seed_offset:
        raise ValueError(
            "Polyseed with a seed-offset passphrase requires offset-aware "
            "derivation; this scanner does not yet support --seed-offset-file "
            "for Polyseed. Refusing to derive the wrong wallet")
    try:
        from bip_utils import MoneroPolyseedMnemonicValidator, MoneroPolyseedSeedGenerator
    except ImportError as exc:
        raise PolyseedDependencyMissing(
            "16-word Polyseed support requires bip-utils: "
            "python3 -m pip install 'bip-utils>=2.12.0'") from exc
    try:
        MoneroPolyseedMnemonicValidator().Validate(seed)
        seed_bytes = MoneroPolyseedSeedGenerator(seed).Generate()
    except (ValueError, RuntimeError) as exc:
        # Keep the mnemonic and its individual words out of exception output.
        raise ValueError(
            "Invalid 16-word Polyseed (wordlist, checksum, encrypted-seed "
            "status, or derivation failure)") from None
    if not isinstance(seed_bytes, bytes) or len(seed_bytes) != 32:
        raise ValueError("Polyseed derivation did not return a 32-byte secret")
    spend_scalar = int.from_bytes(seed_bytes, "little") % ED25519_SUBGROUP_ORDER
    if spend_scalar == 0:
        raise ValueError("Polyseed derived an invalid zero private spend scalar")
    spend = spend_scalar.to_bytes(32, "little").hex()
    view = derive_view_key(spend)
    address = derive_address(view, spend, network)
    return view, spend, address


def bip39_keys_auto_scheme(seed: str, passphrase: str, account: int,
                           network: str, supplied_address: str | None,
                           preference: str = "auto") -> tuple[str, str, str, str]:
    """Select BIP39 Monero derivation by an independently supplied address.

    The seed's words do not encode whether Cake, Ledger or Trezor was used.
    When no address disambiguates, retain Cake as the documented default and
    log that the derivation convention could not be established.
    """
    if preference not in ("auto", "cake", "ledger", "trezor"):
        raise ValueError(f"Unknown BIP39 derivation scheme: {preference}")
    schemes = ("cake", "ledger", "trezor") if preference == "auto" else (preference,)
    candidates = []
    for scheme in schemes:
        view, spend = bip39_monero_keys(seed, passphrase, account, scheme)
        address = derive_address(view, spend, network)
        candidates.append((view, spend, address, scheme))
    if supplied_address:
        matches = [_c for _c in candidates if _c[2] == supplied_address]
        if len(matches) == 1:
            return matches[0]
    if preference == "auto":
        TerminalColor.warning(
            "Cannot identify Cake/Ledger/Trezor derivation from BIP39 words alone%s; "
            "using Cake scheme. A matching original primary address permits "
            "automatic selection of the correct scheme",
            " (provided address did not match any candidate)" if supplied_address else "")
    return candidates[0]


def bip39_to_seed(mnemonic: str, passphrase: str) -> bytes:
    """Checksum-check BIP39, then PBKDF2-HMAC-SHA512 (BIP39)."""
    if not bip39_valid_languages(mnemonic):
        raise ValueError("BIP39 mnemonic has an invalid wordlist or checksum")
    normalized = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", normalized, salt, 2048, 64)


def secp_add(p: tuple[int, int] | None,
             q: tuple[int, int] | None) -> tuple[int, int] | None:
    """secp256k1 point addition for non-hardened BIP32 child derivation."""
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % SECP256K1_P == 0:
        return None
    if p == q:
        numerator = 3 * p[0] * p[0]
        denominator = 2 * p[1]
    else:
        numerator = q[1] - p[1]
        denominator = q[0] - p[0]
    slope = (numerator * pow(denominator % SECP256K1_P, -1, SECP256K1_P)) % SECP256K1_P
    x = (slope * slope - p[0] - q[0]) % SECP256K1_P
    y = (slope * (p[0] - x) - p[1]) % SECP256K1_P
    return x, y


def secp_mul(scalar: int) -> tuple[int, int] | None:
    result = None
    addend = SECP256K1_G
    while scalar:
        if scalar & 1:
            result = secp_add(result, addend)
        addend = secp_add(addend, addend)
        scalar >>= 1
    return result


def bip32_private_child(k: int, chain: bytes, index: int) -> tuple[int, bytes]:
    if not 0 <= index < 2 ** 32:
        raise ValueError("BIP32 derivation index out of range")
    if index & 0x80000000:
        data = b"\x00" + k.to_bytes(32, "big")
    else:
        point = secp_mul(k)
        if point is None:
            raise ValueError("BIP32 invalid parent private key")
        x, y = point
        data = bytes((2 | (y & 1),)) + x.to_bytes(32, "big")
    digest = hmac.new(chain, data + index.to_bytes(4, "big"), hashlib.sha512).digest()
    offset = int.from_bytes(digest[:32], "big")
    child = (k + offset) % SECP256K1_N
    if offset >= SECP256K1_N or child == 0:
        raise ValueError("Invalid BIP32 child; cannot derive this account")
    return child, digest[32:]


def bip39_monero_keys(mnemonic: str, passphrase: str, account: int,
                      scheme: str) -> tuple[str, str]:
    """Derive a Monero keypair from BIP39 using wallet-specific conventions.

    cake: BIP32 secp256k1 m/44'/128'/a'/0/0, reduce node key as little-endian.
    ledger: same BIP32 node, hash its bytes using Keccak256 before reduction.
    trezor: SLIP-10 ed25519 m/44'/128'/a', then reduce node key.
    These variants do NOT yield interchangeable Monero addresses.
    """
    if not 0 <= account < 2 ** 31:
        raise ValueError("BIP39 account index must be between 0 and 2147483647")
    if scheme not in ("cake", "ledger", "trezor"):
        raise ValueError(f"Unknown BIP39 Monero derivation scheme: {scheme}")
    seed = bip39_to_seed(mnemonic, passphrase)
    indices = (44 | 0x80000000, 128 | 0x80000000, account | 0x80000000)
    if scheme == "trezor":
        digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
        private, chain = digest[:32], digest[32:]
        for index in indices:
            digest = hmac.new(chain, b"\x00" + private + index.to_bytes(4, "big"),
                              hashlib.sha512).digest()
            private, chain = digest[:32], digest[32:]
    else:
        digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        key, chain = int.from_bytes(digest[:32], "big"), digest[32:]
        if not 0 < key < SECP256K1_N:
            raise ValueError("Invalid BIP32 root key")
        for index in (*indices, 0, 0):
            key, chain = bip32_private_child(key, chain, index)
        private = key.to_bytes(32, "big")
        if scheme == "ledger":
            private = keccak256(private)
    spend_int = int.from_bytes(private, "little") % ED25519_SUBGROUP_ORDER
    if not spend_int:
        raise ValueError("Derived an invalid zero private spend key")
    spend = spend_int.to_bytes(32, "little").hex()
    return derive_view_key(spend), spend


def read_secret_file(path: Path | None) -> str:
    if path is None:
        return ""
    path = path.expanduser()
    if not path.is_file():
        raise ValueError(f"Seed passphrase file missing: {path}")
    return path.read_text(encoding="utf-8").rstrip("\r\n")


def monero_b58decode(value: str) -> bytes:
    """Decode Monero's block-oriented Base58, checking each block width."""
    reverse_sizes = {v: k for k, v in enumerate(B58_BLOCK_SIZES) if k}
    chunks: list[bytes] = []
    for pos in range(0, len(value), 11):
        block = value[pos:pos + 11]
        nbytes = reverse_sizes.get(len(block))
        if nbytes is None:
            raise ValueError("Invalid Monero Base58 block length")
        number = 0
        for char in block:
            pos58 = B58_ALPHABET.find(char)
            if pos58 < 0:
                raise ValueError("Invalid character in Monero Base58 address")
            number = number * 58 + pos58
        if number >= 1 << (8 * nbytes):
            raise ValueError("Monero Base58 block overflow")
        chunks.append(number.to_bytes(nbytes, "big"))
    return b"".join(chunks)


def validate_sweep_address(value: str, network: str) -> str:
    """Allow standard and subaddress destinations with verified checksum/network."""
    if len(value) != 95:
        raise ValueError("Sweep destination must be a 95-character Monero standard address or subaddress")
    raw = monero_b58decode(value)
    if len(raw) != 69 or raw[0] not in (NETWORK_PREFIX[network], SUBADDRESS_PREFIX[network]):
        raise ValueError("Sweep destination is not a valid standard/subaddress on this network")
    if raw[-4:] != keccak256(raw[:-4])[:4]:
        raise ValueError("Sweep destination failed the Monero address checksum")
    return value


def is_canonical_scalar(value: str) -> bool:
    """Monero secret keys are 32-byte, little-endian canonical Ed25519 scalars."""
    if not HEX_KEY_RE.fullmatch(value):
        return False
    return 0 < int.from_bytes(bytes.fromhex(value), "little") < ED25519_SUBGROUP_ORDER


def clean_key_hex(value: str) -> tuple[str, str]:
    """Remove unambiguous formatting only; do not invent missing key digits."""
    clean = value.strip().strip('"\'`')
    transformations = []
    if clean[:2].lower() == "0x":
        clean = clean[2:]
        transformations.append("removed 0x prefix")
    # Hex secrets exported from SQL/CSV sometimes contain spaces, line breaks
    # or literal control characters from decoding/padding. These are never hex.
    cleaned = "".join(ch for ch in clean if not ch.isspace() and ord(ch) >= 32 and ord(ch) != 127)
    if cleaned != clean:
        transformations.append("removed whitespace/control characters")
    clean = cleaned.lower()
    return clean, "; ".join(transformations)


def recovery_candidates(value: str, *, insert_one_nibble: bool):
    """Yield bounded repair hypotheses. Never call any RPC or expose secrets."""
    clean, formatting = clean_key_hex(value)
    seen: set[str] = set()

    def emit(_candidate: str, _reason: str):
        if _candidate not in seen and is_canonical_scalar(_candidate):
            seen.add(_candidate)
            return _candidate, _reason
        return None

    # Exact same 32 bytes after stripping formatting are safe without an
    # address: no key material has changed.
    normalized = emit(clean, formatting or "exact canonical key")
    if normalized is not None:
        yield normalized

    if re.fullmatch(r"[0-9a-f]+", clean):
        if len(clean) == 64:
            raw = bytes.fromhex(clean)
            scalar = int.from_bytes(raw, "little")
            if scalar >= ED25519_SUBGROUP_ORDER:
                reduced = (scalar % ED25519_SUBGROUP_ORDER).to_bytes(32, "little").hex()
                entry = emit(reduced, "reduced raw 32-byte seed modulo l")
                if entry is not None:
                    yield entry
                # Alternative hypothesis for source formats with byte-order
                # reversal, only accepted when an independent reference verifies.
                reversed_reduced = (int.from_bytes(raw, "big") % ED25519_SUBGROUP_ORDER).to_bytes(32, "little").hex()
                entry = emit(reversed_reduced, "reversed seed byte order, then reduced")
                if entry is not None:
                    yield entry
        elif len(clean) in (62, 63):
            # Leading/trailing zeros are the most common casualties of SQL or
            # numeric/hex exports. Only accept modified values with verification.
            deficit = 64 - len(clean)
            for position, reason in ((0, "restored leading zero nibble(s)"),
                                     (len(clean), "restored trailing zero nibble(s)")):
                candidate = clean[:position] + "0" * deficit + clean[position:]
                entry = emit(candidate, reason)
                if entry is not None:
                    yield entry
            if len(clean) == 63 and insert_one_nibble:
                # A single missing hex digit can be recovered with an address
                # or a deterministic view-key check. At most 64 * 16 probes.
                for position in range(64):
                    for digit in "0123456789abcdef":
                        candidate = clean[:position] + digit + clean[position:]
                        entry = emit(candidate, f"restored one missing hex digit at position {position}")
                        if entry is not None:
                            yield entry
        elif len(clean) in (65, 66):
            surplus = len(clean) - 64
            if clean[:surplus] == "0" * surplus:
                entry = emit(clean[surplus:], "removed extra leading zero nibble(s)")
                if entry is not None:
                    yield entry
            if clean[-surplus:] == "0" * surplus:
                entry = emit(clean[:-surplus], "removed extra trailing zero nibble(s)")
                if entry is not None:
                    yield entry


def recover_spend_key(spend: str, *, view: str | None,
                      supplied_address: str | None, network: str,
                      enable_recovery: bool) -> tuple[str, str]:
    """Recover missing formatting or seed encoding, with independent proof.

    A guessed scalar is accepted ONLY when it yields the supplied primary
    address or yields the supplied deterministic private view key. No blind
    zero-padding/reduction is performed without one of these checks.
    """
    clean, formatting = clean_key_hex(spend)
    if is_canonical_scalar(clean):
        return clean, formatting
    if not enable_recovery:
        if len(clean) != 64 or not re.fullmatch(r"[0-9a-f]+", clean):
            raise ValueError(f"Private spend key must have exactly 64 hexadecimal characters (found {len(clean)})")
        raise ValueError("Private spend key is not a valid canonical Monero scalar")

    has_address = bool(supplied_address)
    has_deterministic_view = bool(view and is_canonical_scalar(view))
    for candidate, reason in recovery_candidates(spend, insert_one_nibble=has_address or has_deterministic_view):
        # Formatting-only normalization does not change the 32-byte key.
        if candidate == clean:
            return candidate, reason
        if has_deterministic_view and derive_view_key(candidate) == view:
            return candidate, reason + "; verified by deterministic view key"
        if has_address:
            try:
                candidate_view = view if view is not None else derive_view_key(candidate)
                if derive_address(candidate_view, candidate, network) == supplied_address:
                    return candidate, reason + "; verified against supplied address"
            except (ValueError, RuntimeError):
                continue

    if len(clean) != 64 or not re.fullmatch(r"[0-9a-f]+", clean):
        detail = f"Private spend key must have exactly 64 hexadecimal characters (found {len(clean)})"
    else:
        detail = "Private spend key is not a valid canonical Monero scalar"
    raise ValueError(
        detail + "; no verified repair found. A supplied matching primary address "
                 "or deterministic view key is needed to verify a changed private key"
    )


def load_wallets(path: Path, network: str,
                 key_format: str = "auto", *,
                 recover_keys: bool = True,
                 mnemonic_format: str = "auto",
                 bip39_passphrase: str = "",
                 bip39_account: int = 0,
                 bip39_scheme: str = "cake",
                 seed_offset: str = "",
                 duplicate_jobs: list[WalletJob] | None = None) -> tuple[list[WalletJob], list[dict]]:
    """Parse keypairs and Monero Electrum-style seeds without logging secrets.

    Mnemonics are accepted as 25/24 words or legacy 13/14 words, optionally
    preceded by an address and colon. An RPC restoration verifies the mnemonic
    wordlist/checksum. When a supplied address disagrees with the address
    derived from keys or a restored mnemonic, the derived address wins.
    --validate-only validates mnemonic shape only (offline). Entries that
    cannot be repaired are written verbatim to .error_keys next to --keys.
    """
    formats = ("auto", "address-view-spend", "address-spend", "view-spend",
               "mnemonic", "address-mnemonic")
    if key_format not in formats:
        raise ValueError("Unknown --key-format")
    jobs: list[WalletJob] = []
    invalid: list[dict] = []
    seen: set[str] = set()

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(":")]
        detected = key_format
        explicit_seed_format = None
        # Allow 'polyseed:word ...', 'bip39:word ...', and
        # 'address:bip39:word ...' without confusing them with key triples.
        if len(parts) >= 2 and parts[0].lower() in SEED_FORMAT_TAGS:
            explicit_seed_format = parts[0].lower()
            parts.pop(0)
            detected = "mnemonic"
        elif (len(parts) >= 3 and len(parts[0]) == 95
              and parts[1].lower() in SEED_FORMAT_TAGS):
            explicit_seed_format = parts[1].lower()
            parts.pop(1)
            detected = "address-mnemonic"
        if detected == "auto":
            if len(parts) == 3:
                detected = "address-view-spend"
            elif (len(parts) == 2 and len(parts[0]) == 95
                  and len(parts[1].split()) in SEED_WORD_COUNTS):
                detected = "address-mnemonic"
            elif len(parts) == 1 and " " in parts[0]:
                detected = "mnemonic"
            elif len(parts) == 2 and len(parts[0]) == 95:
                detected = "address-spend"
            elif len(parts) == 2 and 58 <= len(parts[0].removeprefix("0x")) <= 70:
                detected = "view-spend"
            else:
                invalid.append({"line": line_number, "status": "INVALID",
                                "error": "Expected address:view:spend, address:spend, "
                                         "view:spend, or supported mnemonic words"})
                continue

        expected = 3 if detected == "address-view-spend" else (1 if detected == "mnemonic" else 2)
        if len(parts) != expected:
            invalid.append({"line": line_number, "status": "INVALID",
                            "error": f"{detected} requires exactly {expected} colon-separated field(s)"})
            continue

        try:
            if detected in ("mnemonic", "address-mnemonic"):
                supplied_address = parts[0] if detected == "address-mnemonic" else ""
                if supplied_address and not ADDRESS_RE.fullmatch(supplied_address):
                    raise ValueError("Supplied address must be a 95-character Monero primary address")
                mnemonic = normalize_mnemonic(parts[-1])
                seed_format = resolve_seed_format(
                    mnemonic, explicit_seed_format or mnemonic_format,
                    supplied_address=supplied_address or None, network=network,
                    bip39_passphrase=bip39_passphrase,
                    bip39_account=bip39_account)
                if seed_format in ("bip39", "polyseed"):
                    if seed_format == "bip39":
                        view, spend, address, detected_scheme = bip39_keys_auto_scheme(
                            mnemonic, bip39_passphrase, bip39_account,
                            network, supplied_address or None, bip39_scheme)
                        TerminalColor.info("Line %d: verified BIP39 mnemonic (%s scheme)",
                                           line_number, detected_scheme)
                    else:
                        view, spend, address = polyseed_to_wallet_keys(
                            mnemonic, network, seed_offset)
                        detected_scheme = "Polyseed"
                        TerminalColor.info("Line %d: verified 16-word Polyseed checksum and derived keys locally",
                                           line_number)
                    if supplied_address and address != supplied_address:
                        TerminalColor.warning(
                            "Line %d: supplied address differs from %s-derived "
                            "address %s; using derived wallet",
                            line_number, detected_scheme, address)
                    # The verified address determines the cache identity, just
                    # like explicit private-key wallets. Never reuse a cache
                    # for a different derived primary address.
                    identifier = "address:" + address
                    digest = hashlib.sha256((network + ":" + address).encode()).hexdigest()[:40]
                    # generate_from_keys is compatible with Monero v0.18.5.4.
                    mnemonic = None
                else:
                    TerminalColor.info("Line %d: automatically detected %s mnemonic (%d words)",
                                       line_number, seed_format, len(mnemonic.split()))
                    view = spend = None
                    address = supplied_address
                    # Include an offset fingerprint in cache identity so a
                    # different passphrase never opens an unrelated cached wallet.
                    identifier = "seed:" + hashlib.sha256(
                        (seed_format + "\x00" + mnemonic + "\x00" + seed_offset)
                        .encode("utf-8")).hexdigest()
                    digest = hashlib.sha256((network + ":" + identifier).encode()).hexdigest()[:40]
            else:
                seed_format = "keys"
                mnemonic = None
                if detected == "address-view-spend":
                    supplied_address, view, spend = parts
                elif detected == "address-spend":
                    supplied_address, spend = parts
                    view = None
                else:
                    view, spend = parts
                    supplied_address = None
                if supplied_address is not None and not ADDRESS_RE.fullmatch(supplied_address):
                    raise ValueError("Address must be a 95-character standard Monero Base58 address")
                # A deterministic Monero wallet derives the private view key
                # from its canonical private spend key. A damaged view key is
                # therefore recoverable without changing the spend key.
                view_recovery = ""
                if view is not None:
                    view, view_formatting = clean_key_hex(view)
                    if not is_canonical_scalar(view):
                        if not recover_keys:
                            raise ValueError(
                                "Private view key is not a valid 64-character canonical scalar")
                        view = None
                        view_recovery = (
                            "derived deterministic view key from spend key "
                            "(supplied private view key was invalid)")
                        TerminalColor.warning(
                            "Line %d: invalid private view key; attempting "
                            "deterministic derivation from the private spend key",
                            line_number)
                    elif view_formatting:
                        TerminalColor.info(
                            "Line %d: normalized private view-key formatting",
                            line_number)
                spend, spend_recovery = recover_spend_key(
                    spend, view=view, supplied_address=supplied_address,
                    network=network, enable_recovery=recover_keys)
                if spend_recovery:
                    TerminalColor.warning(
                        "Line %d: private spend-key recovery: %s",
                        line_number, spend_recovery)
                if view is None:
                    view = derive_view_key(spend)
                    if view_recovery:
                        TerminalColor.warning(
                            "Line %d: successfully derived replacement "
                            "private view key from the private spend key",
                            line_number)
                key_recovery = "; ".join(
                    reason for reason in (spend_recovery, view_recovery) if reason)
                address = derive_address(view, spend, network)
                if supplied_address is not None and address != supplied_address:
                    TerminalColor.warning(
                        "Line %d: supplied address %s does not match address %s "
                        "derived from private keys; scanning derived address",
                        line_number, supplied_address, address)
                identifier = "address:" + address
                digest = hashlib.sha256((network + ":" + address).encode()).hexdigest()[:40]
        except PolyseedDependencyMissing:
            raise  # An unavailable decoder is not evidence of a bad mnemonic.
        except (ValueError, RuntimeError) as exc:
            invalid.append({"line": line_number, "status": "INVALID", "error": str(exc)})
            continue
        except Exception as exc:
            invalid.append({"line": line_number, "status": "INVALID",
                            "error": f"Wallet input parsing failed: {type(exc).__name__}"})
            continue

        if identifier in seen:
            TerminalColor.info("Line %s: duplicate wallet input, skipped for scanning", line_number)
            if duplicate_jobs is not None:
                duplicate_jobs.append(WalletJob(
                    line_number, view, spend, address, f"xmr_{digest}", mnemonic,
                    supplied_address=supplied_address or None,
                    key_recovery=(key_recovery if seed_format == "keys" else ""),
                    seed_format=seed_format))
            continue
        seen.add(identifier)
        jobs.append(WalletJob(
            line_number, view, spend, address, f"xmr_{digest}", mnemonic,
            supplied_address=supplied_address or None,
            key_recovery=(key_recovery if seed_format == "keys" else ""),
            seed_format=seed_format))
    return jobs, invalid


# Advanced key restoration is an opt-in SECOND pass. Never interpret a merely
# canonical scalar as a recovered key: a reference address or deterministic
# private view key must independently verify every altered secret.
def primary_address_index(keys_path: Path, network: str) -> dict[bytes, list[tuple[str, bytes, int]]]:
    """Index valid primary address public-spend keys from ALL input lines.

    Monero addresses contain public spend/view keys, so candidate spend keys can
    be rejected with only one curve multiplication and a dictionary lookup.
    The source line need not contain a valid private key to supply an address.
    """
    index: dict[bytes, list[tuple[str, bytes, int]]] = {}
    for lineno, raw in enumerate(keys_path.read_text(encoding="utf-8-sig").splitlines(), 1):
        part = raw.strip().split(":", 1)[0].strip()
        if len(part) != 95 or not ADDRESS_RE.fullmatch(part):
            continue
        try:
            decoded = monero_b58decode(part)
            if (len(decoded) != 69 or decoded[0] != NETWORK_PREFIX[network]
                    or decoded[-4:] != keccak256(decoded[:-4])[:4]):
                continue
        except (ValueError, TypeError):
            continue
        index.setdefault(decoded[1:33], []).append((part, decoded[33:65], lineno))
    return index


def advanced_nibble_candidates(original: str, max_missing: int):
    """Enumerate missing 1-3 hex nibbles at ALL possible positions/values.

    Every possible final 64-character string preserving the order of surviving
    input digits is considered, subject to the caller's explicit work budget.
    Also cover single-character substitution of invalid 64-character keys.
    """
    clean, _ = clean_key_hex(original)
    if not re.fullmatch(r"[0-9a-f]+", clean):
        return
    length = len(clean)
    deficit = 64 - length
    if 1 <= deficit <= max_missing:
        for slots in itertools.combinations(range(64), deficit):
            segments = []
            start = 0
            # Split original into the spans between insertion sites, so the
            # same fixed strings can be reused for every digit combination.
            for ordinal, site in enumerate(slots):
                idx = site - ordinal
                segments.append(clean[start:idx])
                start = idx
            segments.append(clean[start:])
            for digits in itertools.product("0123456789abcdef", repeat=deficit):
                pieces = [segments[0]]
                for j, digit in enumerate(digits):
                    pieces.extend((digit, segments[j + 1]))
                yield "".join(pieces), f"inserted {deficit} hex nibble(s)"
    elif length == 64 and not is_canonical_scalar(clean):
        for position, old in enumerate(clean):
            for replacement in "0123456789abcdef":
                if replacement != old:
                    yield (clean[:position] + replacement + clean[position + 1:],
                           f"replaced corrupted hex nibble at offset {position}")
    elif 64 < length <= 66:
        # Also recover a spurious one or two hex characters from exports.
        for positions in itertools.combinations(range(length), length - 64):
            removed = set(positions)
            yield ("".join(ch for i, ch in enumerate(clean) if i not in removed),
                   f"removed {length - 64} extra hex nibble(s)")


def search_advanced_spend_key(spend: str, supplied_view: str | None,
                              supplied_address: str | None, network: str,
                              references: dict[bytes, list[tuple[str, bytes, int]]],
                              *, max_missing: int, max_candidates: int,
                              progress_every: int, lineno: int
                              ) -> tuple[tuple[str, str, str, str, int] | None, int, bool]:
    """Return (verified repair, candidates examined, budget exhausted).

    Verified result: (spend, view, primary address, reason, reference line).
    No reference means no repair, regardless of the apparent plausibility.
    """
    view_clean = clean_key_hex(supplied_view)[0] if supplied_view else ""
    valid_view = view_clean if is_canonical_scalar(view_clean) else None
    view_pub = (crypto_scalarmult_ed25519_base_noclamp(bytes.fromhex(valid_view))
                if valid_view else None)
    checked = 0
    exhausted = False
    for candidate, explanation in advanced_nibble_candidates(spend, max_missing):
        if checked >= max_candidates:
            exhausted = True
            break
        checked += 1
        if progress_every and checked % progress_every == 0:
            TerminalColor.info("ADVANCED RECOVERY line %d examined %d/%d candidate formats",
                               lineno, checked, max_candidates)
        if not is_canonical_scalar(candidate):
            continue
        # The supplied private view key is strong independent evidence for
        # deterministic keys, including rows with NO supplied address.
        deterministic = None
        if valid_view:
            deterministic = derive_view_key(candidate)
            if deterministic == valid_view:
                address = derive_address(valid_view, candidate, network)
                return ((candidate, valid_view, address,
                         explanation + "; verified by supplied deterministic view key", 0),
                        checked, False)
        if not references:
            continue
        public_spend = crypto_scalarmult_ed25519_base_noclamp(bytes.fromhex(candidate))
        possible = references.get(public_spend)
        if not possible:
            continue
        if deterministic is None:
            deterministic = derive_view_key(candidate)
        derived_view_pub = crypto_scalarmult_ed25519_base_noclamp(bytes.fromhex(deterministic))
        verified = []
        for address, target_view_pub, target_line in possible:
            if view_pub is not None and view_pub == target_view_pub:
                verified.append((candidate, valid_view, address,
                                 explanation + "; matched supplied view key and address from line "
                                 + str(target_line), target_line))
            elif derived_view_pub == target_view_pub:
                verified.append((candidate, deterministic, address,
                                 explanation + "; matched deterministic view and address from line "
                                 + str(target_line), target_line))
        if verified:
            # Prefer this row's own address; otherwise prefer a unique match.
            own = [x for x in verified if x[2] == supplied_address]
            if own:
                return own[0], checked, False
            different_keys = {(x[1], x[2]) for x in verified}
            if len(different_keys) == 1:
                return verified[0], checked, False
            TerminalColor.warning("ADVANCED RECOVERY line %d has ambiguous matches to multiple "
                                  "different wallets; no guessed wallet accepted", lineno)
            return None, checked, False
    return None, checked, exhausted


def advanced_recover_file(keys_path: Path, jobs: list[WalletJob],
                          invalid: list[dict], network: str,
                          *, max_missing: int = 2,
                          max_candidates: int = 750000,
                          progress_every: int = 50000,
                          duplicate_jobs: list[WalletJob] | None = None
                          ) -> tuple[list[WalletJob], list[dict], list[WalletJob]]:
    """Recover previously rejected key rows using all supplied addresses.

    Does not reorder rows or treat an unrelated address as proof of ownership.
    Repairs remain visible in key_recovery and are never applied in place.
    """
    original = keys_path.read_text(encoding="utf-8-sig").splitlines()
    refs = primary_address_index(keys_path, network)
    seen = {job.address for job in jobs if job.address}
    recovered: list[WalletJob] = []
    remaining: list[dict] = []
    TerminalColor.info("ADVANCED RECOVERY %d valid primary-address references from the key file",
                       sum(len(v) for v in refs.values()))
    for row in invalid:
        line = int(row["line"])
        if "private spend key" not in str(row.get("error", "")).lower():
            remaining.append(row)
            continue
        fields = [part.strip() for part in original[line - 1].strip().split(":")]
        if len(fields) not in (2, 3):
            remaining.append(row)
            continue
        supplied_address = fields[0] if len(fields[0]) == 95 else None
        supplied_view = fields[-2] if len(fields) == 3 or supplied_address is None else None
        spend = fields[-1]
        clean_spend, _ = clean_key_hex(spend)
        missing = 64 - len(clean_spend)
        if 0 < missing and missing > max_missing:
            TerminalColor.warning("ADVANCED RECOVERY line %d skipped: %d missing nibbles "
                                  "exceeds --advanced-max-missing-nibbles=%d",
                                  line, missing, max_missing)
            remaining.append({**row, "error": str(row["error"]) +
                                              f"; advanced search skipped ({missing} missing hex nibbles)"})
            continue
        TerminalColor.info("ADVANCED RECOVERY line %d: testing damaged spend key against all "
                           "validated primary addresses", line)
        repair, checked, exhausted = search_advanced_spend_key(
            spend, supplied_view, supplied_address, network, refs,
            max_missing=max_missing, max_candidates=max_candidates,
            progress_every=progress_every, lineno=line)
        if repair is None:
            suffix = (f"; advanced recovery budget reached after {checked} candidates"
                      if exhausted else f"; advanced recovery found no verified match in {checked} candidates")
            remaining.append({**row, "error": str(row["error"]) + suffix})
            continue
        fixed_spend, fixed_view, address, explanation, target_line = repair
        is_duplicate = address in seen
        digest = hashlib.sha256((network + ":" + address).encode()).hexdigest()[:40]
        job = WalletJob(line, fixed_view, fixed_spend, address, f"xmr_{digest}",
                        supplied_address=supplied_address,
                        key_recovery="advanced: " + explanation,
                        seed_format="keys")
        if is_duplicate:
            TerminalColor.warning("ADVANCED RECOVERY line %d matched an existing wallet; "
                                  "will not scan twice%s", line,
                                  "; repaired entry retained in corrected keys output"
                                  if duplicate_jobs is not None else "")
            if duplicate_jobs is not None:
                duplicate_jobs.append(job)
            continue
        seen.add(address)
        jobs.append(job)
        recovered.append(job)
        TerminalColor.warning("ADVANCED RECOVERY line %d recovered a cryptographically verified "
                              "key pair after %d candidates%s", line, checked,
                              f" (reference address on line {target_line})" if target_line else "")
    return jobs, remaining, recovered


def backup_existing_output(path: Path) -> Path | None:
    """Preserve an existing report/export before replacing or truncating it.

    Backups go into a sibling ``backups/`` directory, normally ``data/backups/``.
    Backups are written to a temporary file, fsynced, then atomically renamed;
    failure aborts the overwrite and leaves the original output untouched.
    Every replacement gets its own unique timestamped backup (no rotation).
    """
    path = path.expanduser().absolute()
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Refusing to overwrite non-regular output or symlink: {path}")
    backup_dir = path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        backup_dir.chmod(0o700)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    backup = backup_dir / f"{path.name}.{timestamp}.{secrets.token_hex(5)}.bak"
    fd, temporary_name = tempfile.mkstemp(prefix=".backup-", dir=backup_dir)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with path.open("rb") as source, os.fdopen(fd, "wb") as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_name, backup)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    TerminalColor.info("Backed up existing output %s -> %s", path, backup)
    return backup


def resolve_data_output(path: Path, data_dir: Path) -> Path:
    """Put relative output paths under data/, preserving explicit absolute paths.

    An explicitly supplied relative path that already resolves inside data/
    is not prefixed again (so --output data/results.csv works as expected).
    """
    target = path.expanduser()
    if target.is_absolute():
        return target.resolve()
    cwd_path = target.resolve()
    root = data_dir.expanduser().resolve()
    if cwd_path.is_relative_to(root):
        return cwd_path
    return (root / target).resolve()


def configure_output_paths(args: argparse.Namespace) -> None:
    """Centralize ALL generated report, journal, and cache paths under data/."""
    root = args.data_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        root.chmod(0o700)
    args.data_dir = root
    for name in (
            "output", "transactions_output", "verify_output", "cache_dir",
            "sweep_journal", "watch_sweep_journal", "advanced_recovery_output",
            "crossmatch_output", "corrected_keys_output", "fixed_keys_output",
    ):
        selected = getattr(args, name)
        if selected is not None:
            setattr(args, name, resolve_data_output(selected, root))
    args.error_keys_path = root / ".error_keys"


def validate_output_collisions(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Prevent generated files from overwriting each other or inputs/secrets."""
    inputs = {v.expanduser().resolve() for v in (
        args.keys, args.rpcs, args.bip39_passphrase_file, args.seed_offset_file,
        args.cache_password_list, args.old_cache_password_file,
        args.new_cache_password_file,
    ) if v is not None}
    outputs = {
        "--output": args.output,
        "--transactions-output": args.transactions_output,
        "--verify-output": args.verify_output,
        "--sweep-journal": args.sweep_journal,
        "--watch-sweep-journal": args.watch_sweep_journal,
        ".error_keys": args.error_keys_path,
        "--advanced-recovery-output": args.advanced_recovery_output or args.data_dir / ".recovered_keys",
        "--crossmatch-output": args.crossmatch_output or args.data_dir / ".key_crossmatches.csv",
    }
    for name, selected in (("--corrected-keys-output", args.corrected_keys_output),
                           ("--fixed-keys-output", args.fixed_keys_output)):
        if selected is not None:
            outputs[name] = selected
    seen: dict[Path, str] = {}
    for name, path in outputs.items():
        resolved = path.expanduser().resolve()
        if resolved in inputs:
            parser.error(f"{name} must not overwrite an input, seed passphrase, or password file")
        if resolved in seen:
            parser.error(f"{name} conflicts with {seen[resolved]}: {resolved}")
        if resolved == args.cache_dir or resolved == args.data_dir:
            parser.error(f"{name} is a directory, not an output file: {resolved}")
        seen[resolved] = name


def atomic_private_text(path: Path, lines: list[str]) -> None:
    """Replace private-key output atomically, owner-readable only."""
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".keyrecovery-", dir=path.parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            for line in lines:
                out.write(line + "\n")
            out.flush()
            os.fsync(out.fileno())
        backup_existing_output(path)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def write_crossmatches(path: Path, keys_path: Path, jobs: list[WalletJob]) -> int:
    """Report supplied addresses paired with OTHER rows' derived wallets."""
    by_address: dict[str, list[int]] = {}
    for job in jobs:
        by_address.setdefault(job.address, []).append(job.line)
    source = keys_path.read_text(encoding="utf-8-sig").splitlines()
    result: list[dict] = []
    for line, raw in enumerate(source, 1):
        parts = raw.strip().split(":", 1)
        if len(parts) != 2 or len(parts[0]) != 95 or not ADDRESS_RE.fullmatch(parts[0]):
            continue
        owners = [owner for owner in by_address.get(parts[0], []) if owner != line]
        if owners:
            TerminalColor.warning("ADDRESS CROSS-MATCH line %d supplied address is derived "
                                  "from private keys on line(s) %s", line,
                                  ",".join(map(str, owners)))
            result.append({"input_line": line, "matched_key_lines": ",".join(map(str, owners)),
                           "supplied_address": parts[0], "status": "MATCHED_OTHER_KEY_ROW"})
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".crossmatch-", dir=path.parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=("input_line", "matched_key_lines",
                                                     "supplied_address", "status"))
            writer.writeheader()
            writer.writerows(result)
            out.flush()
            os.fsync(out.fileno())
        backup_existing_output(path)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    TerminalColor.info("Saved %d cross-referenced addresses to %s", len(result), path)
    return len(result)


def is_mainnet_compatible_subaddress(value: str, network: str) -> bool:
    """Keep a supplied subaddress hint even when the primary address differs.

    The existing adaptive subaddress lookup needs the ORIGINAL subaddress in
    order to search its account/index. This checks encoding/network/checksum,
    not ownership; ownership is verified separately by wallet RPC.
    """
    try:
        decoded = monero_b58decode(value)
        return (len(decoded) == 69 and
                decoded[0] == SUBADDRESS_PREFIX[network] and
                decoded[-4:] == keccak256(decoded[:-4])[:4])
    except (ValueError, TypeError):
        return False


def write_corrected_key_list(output_path: Path, keys_path: Path,
                             jobs: list[WalletJob], invalid: list[dict],
                             network: str, *, only_fixed: bool = False) -> dict[str, int]:
    """Export an importable corrected key list, in original input order.

    Locally derived/recovered pairs are normalized to ADDRESS:VIEW:SPEND;
    earlier primary-address mismatches are replaced with the actual derived
    primary. Valid supplied SUBADDRESSES are retained as discovery hints even
    if currently unverified. Legacy mnemonics without local key derivation are
    copied verbatim; they still require RPC validation at restoration.

    Rows that remain invalid are excluded, but persist in .error_keys. Duplicate
    raw input rows that load_wallets intentionally collapsed are preserved,
    rather than silently losing user input. Blank/comment lines are preserved.
    When only_fixed=True, omit originally valid, unmodified keypairs,
    regardless of whether a 2-field input gains a derived address or view key
    during export. Include only actual key repairs and mismatched supplied
    primary-address corrections (including cross-matches to other rows).
    Unverified subaddress hints are NOT treated as primary-address repairs.
    Neither the original key file nor existing journal/cache files are edited.
    """
    raw_lines = keys_path.read_text(encoding="utf-8-sig").splitlines()
    by_line = {job.line: job for job in jobs}
    bad = {int(row['line']) for row in invalid}
    emitted: list[str] = []
    totals = {"key_pairs": 0, "changed": 0, "mnemonics_preserved": 0,
              "invalid_excluded": 0, "other_rows_preserved": 0,
              "subaddress_hints_preserved": 0, "unchanged_excluded": 0}
    for lineno, raw in enumerate(raw_lines, 1):
        if not raw.strip() or raw.lstrip().startswith('#'):
            if not only_fixed:
                emitted.append(raw)
            continue
        if lineno in bad:
            totals['invalid_excluded'] += 1
            continue
        job = by_line.get(lineno)
        if job is None:
            # E.g. a duplicate deliberately deduplicated by load_wallets.
            # Only the full export keeps unclassified source lines.
            if not only_fixed:
                emitted.append(raw)
                totals['other_rows_preserved'] += 1
            continue
        if job.view is None or job.spend is None or not job.address:
            if not only_fixed:
                emitted.append(raw)
                totals['mnemonics_preserved'] += 1
            else:
                totals['unchanged_excluded'] += 1
            continue
        if not (is_canonical_scalar(job.view) and is_canonical_scalar(job.spend)):
            raise ValueError(f"Refusing corrected key export for line {lineno}: "
                             "wallet key scalar is not canonical")
        supplied = job.supplied_address or ''
        is_subaddress_hint = bool(supplied and is_mainnet_compatible_subaddress(supplied, network))
        export_address = supplied if is_subaddress_hint else job.address
        # A normalized, previously valid 2-field line is NOT a repaired key.
        # A supplied subaddress is also not a proven discrepancy; we preserve
        # it as a hint but do not count it as a correction without RPC proof.
        primary_address_corrected = bool(
            supplied and supplied != job.address and not is_subaddress_hint)
        key_material_repaired = bool(job.key_recovery)
        # Include view-key normalization (0x prefix, control characters etc.)
        # even if the input spend key was canonical and key_recovery is empty.
        source_parts = raw.strip().split(':')
        if (not key_material_repaired and job.seed_format == 'keys'
                and len(source_parts) == 3):
            source_view = source_parts[1].strip()
            canonical_view, _ = clean_key_hex(source_view)
            key_material_repaired = bool(
                canonical_view == job.view and source_view.lower() != job.view)
        if only_fixed and not (primary_address_corrected or key_material_repaired):
            totals['unchanged_excluded'] += 1
            continue
        if is_subaddress_hint:
            totals['subaddress_hints_preserved'] += 1
        line = f'{export_address}:{job.view}:{job.spend}'
        emitted.append(line)
        totals['key_pairs'] += 1
        if line != raw:
            totals['changed'] += 1
    atomic_private_text(output_path, emitted)
    TerminalColor.info('%s: %d locally derived keypairs (%d changed), '
                       '%d mnemonics preserved, %d unresolved entries excluded, '
                       '%d unchanged entries excluded, %d deduplicated source entries preserved, '
                       '%d subaddress hints retained; file=%s',
                       'Fixed-only keys' if only_fixed else 'Corrected keys',
                       totals['key_pairs'], totals['changed'], totals['mnemonics_preserved'],
                       totals['invalid_excluded'], totals['unchanged_excluded'],
                       totals['other_rows_preserved'], totals['subaddress_hints_preserved'], output_path)
    if totals['invalid_excluded']:
        TerminalColor.warning('Corrected keys output excludes %d unrecoverable input line(s); '
                              'originals remain in %s', totals['invalid_excluded'],
                              output_path.expanduser().resolve().parent / '.error_keys')
    if totals['subaddress_hints_preserved']:
        TerminalColor.warning('Corrected keys retained %d checksum-valid supplied subaddress hint(s). '
                              'A checksum cannot establish that a subaddress belongs to the '
                              'exported keys; use --verify-addresses-only for ownership checks.',
                              totals['subaddress_hints_preserved'])
    if totals['mnemonics_preserved']:
        TerminalColor.warning('Corrected keys retained %d legacy mnemonic line(s) without private '
                              'key conversion; these require wallet RPC validation on restoration.',
                              totals['mnemonics_preserved'])
    return totals


def _private_export_path(args: argparse.Namespace, selected: Path | None,
                         default_basename: str, flag: str) -> Path | None:
    """Resolve export paths and reject collisions with all sensitive files."""
    if selected is None:
        return None
    base = args.data_dir
    dest = (base / default_basename if selected == Path(default_basename)
            else selected.expanduser()).resolve()
    protected = [args.keys, args.error_keys_path,
                 args.rpcs, args.output, args.transactions_output,
                 args.sweep_journal, args.watch_sweep_journal, args.verify_output,
                 args.bip39_passphrase_file, args.seed_offset_file,
                 args.advanced_recovery_output or base / '.recovered_keys',
                 args.crossmatch_output or base / '.key_crossmatches.csv']
    for candidate in protected:
        if candidate is not None and dest == candidate.expanduser().resolve():
            raise ValueError(f'{flag} must not overwrite inputs, private passphrase '
                             'files, other exports or journals')
    if dest.is_dir():
        raise ValueError(f'{flag} must be a file path, not a directory')
    return dest


def corrected_output_path(args: argparse.Namespace) -> Path | None:
    return _private_export_path(args, args.corrected_keys_output,
                                '.corrected_keys', '--corrected-keys-output')


def fixed_keys_output_path(args: argparse.Namespace) -> Path | None:
    return _private_export_path(args, args.fixed_keys_output,
                                '.fixed_keys', '--fixed-keys-output')


def refresh_corrected_export_after_mnemonic_rejection(args: argparse.Namespace) -> None:
    """Re-export without legacy seed entries rejected by wallet RPC."""
    rejected = [{"line": lineno} for lineno in args.error_key_line_numbers]
    jobs = getattr(args, 'corrected_export_jobs', [])
    for path, only_fixed in (
            (getattr(args, 'corrected_export_path', None), False),
            (getattr(args, 'fixed_export_path', None), True),
    ):
        if path is not None:
            write_corrected_key_list(path, args.keys, jobs, rejected,
                                     args.network, only_fixed=only_fixed)


def write_error_keys(keys_path: Path, invalid: list[dict],
                     output_path: Path | None = None) -> Path:
    """Save the verbatim source lines that remain invalid after key recovery.

    .error_keys defaults to data/.error_keys and is atomically replaced each run,
    including when the invalid list is empty (which removes stale entries).
    File permissions are owner-only because it contains private key material.

    Ordinary daemon, wallet-RPC, and network failures do NOT establish that
    an input key is bad and are deliberately excluded.
    """
    keys_path = keys_path.expanduser().resolve(strict=True)
    error_path = (output_path if output_path is not None else keys_path.parent / ".error_keys").expanduser().resolve()
    error_path.parent.mkdir(parents=True, exist_ok=True)
    if keys_path == error_path:
        raise ValueError("--keys must not point to .error_keys, which is an output file")

    # Read using the identical line splitting as load_wallets() so each
    # recorded source line number points to exactly the original input line.
    original_lines = keys_path.read_text(encoding="utf-8-sig").splitlines()
    failed_numbers = sorted({int(row["line"]) for row in invalid})
    for number in failed_numbers:
        if number < 1 or number > len(original_lines):
            raise ValueError(f"Invalid source line number in key errors: {number}")

    fd, temporary_name = tempfile.mkstemp(prefix=".error_keys.tmp.", dir=error_path.parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            for number in failed_numbers:
                stream.write(original_lines[number - 1])
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        backup_existing_output(error_path)
        os.replace(temporary_name, error_path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)

    if failed_numbers:
        TerminalColor.warning("Saved %d unrecoverable key-file entries to %s",
                              len(failed_numbers), error_path)
    else:
        TerminalColor.info("No unrecoverable key-file entries; %s is empty", error_path)
    return error_path


def is_permanent_mnemonic_error(job: WalletJob, error: Exception) -> bool:
    """Distinguish a rejected mnemonic from transient RPC/daemon failures.

    The official wallet RPC verifies the seed wordlist and checksum during
    restore_deterministic_wallet. Only errors explicitly identifying a bad
    seed are added to .error_keys; timeouts and daemon failures are excluded.
    """
    if job.mnemonic is None or not isinstance(error, RPCError) or isinstance(error, RPCTransportError):
        return False
    description = str(error).lower()
    if "rpc restore_deterministic_wallet error" not in description:
        return False
    return any(phrase in description for phrase in (
        "invalid seed", "invalid mnemonic", "invalid checksum",
        "seed checksum", "bad seed", "invalid word", "unknown word",
        "invalid electrum", "invalid phrase",
    ))


def xmr_amount(atomic: int) -> str:
    """Exact fixed-point XMR representation without binary floating-point."""
    return f"{Decimal(atomic) / ATOMIC:.12f}"


def utc_timestamp(timestamp: object) -> str:
    """UTC ISO-8601 string; unknown (zero) timestamps are left blank."""
    try:
        value = int(timestamp or 0)
        if value <= 0:
            return ""
        return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (OverflowError, ValueError, TypeError, OSError):
        return ""


class TransactionResults:
    """Persist wallet transfer history in a second, per-transfer CSV.

    The scanner uses a single asyncio event loop, so writes have no awaits and
    cannot interleave within an event-loop turn. Retried scans and an optional
    post-sweep requery are deduplicated by transfer identity, not confirmations.
    """

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        backup_existing_output(path)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self.fp = os.fdopen(descriptor, "w", newline="", encoding="utf-8")
        if os.name == "posix":
            os.chmod(path, 0o600)
        self.writer = csv.DictWriter(self.fp, fieldnames=TX_FIELDS)
        self.writer.writeheader()
        self.fp.flush()
        self.seen: set[tuple] = set()
        self.counts: dict[str, Counter[str]] = {}
        self.total_rows = 0

    def add_transfers(self, job: WalletJob, payload: dict,
                      wallet_height: int, daemon_height: int) -> int:
        """Store incoming, outgoing, pending, failed and mempool transfers.

        Monero's get_transfers 'in' list also includes mining rewards (type=block).
        Output addresses/destinations are only available when preserved in the
        wallet cache; restored historical sends often cannot reveal recipients.
        """
        new_rows: list[tuple[tuple, dict, str]] = []
        identity_occurrences: Counter[tuple] = Counter()
        for bucket in TX_BUCKETS:
            entries = payload.get(bucket, []) or []
            if not isinstance(entries, list):
                raise RPCError(f"get_transfers returned invalid {bucket!r} collection")
            for entry in entries:
                if not isinstance(entry, dict):
                    raise RPCError(f"get_transfers returned invalid transfer in {bucket!r}")
                txid = str(entry.get("txid") or "")
                amount = int(entry.get("amount", 0))
                fee = int(entry.get("fee", 0))
                timestamp = int(entry.get("timestamp", 0) or 0)
                height = int(entry.get("height", 0) or 0)
                index = entry.get("subaddr_index") or {}
                if not isinstance(index, dict):
                    index = {}
                major = int(index.get("major", entry.get("account_index", 0)))
                minor = int(index.get("minor", 0))
                kind = str(entry.get("type", bucket))
                identity_base = (job.address, bucket, txid, kind, amount, fee,
                                 timestamp, height, major, minor)
                ordinal = identity_occurrences[identity_base]
                identity_occurrences[identity_base] += 1
                identity = identity_base + (ordinal,)
                if identity in self.seen:
                    continue
                # 'pending' and 'failed' represent outgoing transfers.  A pool
                # entry may be incoming or outgoing, so prefer the RPC type.
                outgoing = bucket in ("out", "pending", "failed") or kind in ("out", "pending", "failed")
                signed_amount = -amount if outgoing else amount
                row = {
                    "line": job.line,
                    "wallet_address": job.address,
                    "supplied_address": job.supplied_address or "",
                    "address_mismatch": job.address_mismatch,
                    "txid": txid,
                    "direction": "out" if outgoing else "in",
                    "state": bucket,
                    "type": kind,
                    "timestamp_utc": utc_timestamp(timestamp),
                    "timestamp_unix": timestamp if timestamp > 0 else "",
                    "timestamp_source": ("block" if height > 0 else
                                         "submission_or_pool" if timestamp > 0 else "unknown"),
                    "block_height": height if height > 0 else "",
                    "confirmations": entry.get("confirmations", ""),
                    "amount_xmr": xmr_amount(amount),
                    "amount_atomic": amount,
                    "signed_amount_xmr": xmr_amount(signed_amount),
                    "fee_xmr": xmr_amount(fee),
                    "fee_atomic": fee,
                    "account_index": major,
                    "subaddress_index": minor,
                    "subaddress_indices_json": json.dumps(entry.get("subaddr_indices", []),
                                                          separators=(",", ":")),
                    "transfer_address": entry.get("address", ""),
                    "payment_id": entry.get("payment_id", ""),
                    "locked": entry.get("locked", ""),
                    "unlock_time": entry.get("unlock_time", ""),
                    "double_spend_seen": entry.get("double_spend_seen", ""),
                    "note": entry.get("note", ""),
                    "destinations_json": json.dumps(entry.get("destinations", []),
                                                    separators=(",", ":"), ensure_ascii=False),
                    "wallet_height": wallet_height,
                    "daemon_height": daemon_height,
                }
                new_rows.append((identity, row, bucket))
        # Sort the newly detected transfers within the wallet by event time.
        new_rows.sort(key=lambda item: (int(item[1]["timestamp_unix"] or 0),
                                        item[1]["txid"], item[1]["state"]))
        counts = self.counts.setdefault(job.address, Counter())
        for identity, row, bucket in new_rows:
            self.writer.writerow(row)
            self.seen.add(identity)
            counts[bucket] += 1
            self.total_rows += 1
        self.fp.flush()
        return len(new_rows)

    def wallet_summary(self, address: str) -> dict:
        counts = self.counts.get(address, Counter())
        return {
            "transaction_count": sum(counts.values()),
            "incoming_count": counts["in"],
            "outgoing_count": counts["out"],
            "pending_count": counts["pending"],
            "failed_count": counts["failed"],
            "pool_count": counts["pool"],
            "transactions_status": "EXPORTED",
        }

    def close(self) -> None:
        self.fp.close()


class SweepJournal:
    """Durable one-attempt-per-address/account/destination transaction journal.

    INTENT is fsynced before calling sweep_all. On restart, an unresolved INTENT
    is not automatically resubmitted. This prevents silent duplicate broadcasts
    when the RPC response is lost, at the cost of requiring manual reconciliation.
    """

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.state: dict[tuple[str, int, str], dict] = {}
        if path.exists():
            with path.open("r", encoding="utf-8") as reader:
                for lineno, raw in enumerate(reader, 1):
                    if not raw.strip():
                        continue
                    try:
                        event = json.loads(raw)
                        key = (event["source"], int(event["account_index"]), event["destination"])
                        self.state[key] = event
                    except (ValueError, KeyError, TypeError) as exc:
                        raise ValueError(f"Invalid sweep journal line {lineno}: {exc}") from exc
        self.fp = path.open("a", encoding="utf-8")
        if os.name == "posix":
            os.chmod(path, 0o600)
            import fcntl
            try:
                fcntl.flock(self.fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.fp.close()
                raise RuntimeError(f"Sweep journal is already in use by another process: {path}")

    def get(self, source: str, account: int, destination: str) -> dict | None:
        return self.state.get((source, account, destination))

    def record(self, source: str, account: int, destination: str,
               status: str, **details: object) -> dict:
        event = {"source": source, "account_index": account,
                 "destination": destination, "status": status,
                 "recorded_at": time.time(), **details}
        self.fp.write(json.dumps(event, separators=(",", ":"), ensure_ascii=True) + "\n")
        self.fp.flush()
        os.fsync(self.fp.fileno())
        self.state[(source, account, destination)] = event
        return event

    def close(self) -> None:
        self.fp.close()


class WatchSweepJournal:
    """Persist every sweep attempt by the exact unlocked outputs it may spend.

    An attempt is written to disk *before* `sweep_all` is sent. Until those
    outputs disappear from the wallet's available outputs, no further sweep
    involving any of them is attempted, even across process restarts.
    The ledger does not automatically retry a rejected/ambiguous transaction:
    this avoids accidental double-spends or broadcasts after an RPC timeout.
    """

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.attempts: dict[str, dict] = {}
        if path.is_file():
            with path.open("r", encoding="utf-8") as reader:
                for line_number, raw in enumerate(reader, 1):
                    if not raw.strip():
                        continue
                    try:
                        event = json.loads(raw)
                        if not isinstance(event.get("attempt_id"), str):
                            raise ValueError("missing attempt_id")
                        if not isinstance(event.get("output_ids"), list):
                            raise ValueError("missing output_ids")
                        self.attempts[event["attempt_id"]] = event
                    except (ValueError, TypeError, KeyError) as exc:
                        raise ValueError(f"Invalid watch sweep journal line {line_number}: {exc}") from exc
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        fd = os.open(path, flags, 0o600)
        self.fp = os.fdopen(fd, "a", encoding="utf-8")
        if os.name == "posix":
            import fcntl
            try:
                fcntl.flock(self.fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.fp.close()
                raise RuntimeError(f"Watch sweep journal in use: {path}")

    def conflicting(self, source: str, account: int, destination: str,
                    output_ids: set[str]) -> dict | None:
        """Return a previous intent overlapping any currently available output."""
        for item in self.attempts.values():
            if not (item.get("source") == source and
                    int(item.get("account_index", -1)) == account and
                    item.get("destination") == destination):
                continue
            previous_ids = set(item["output_ids"])
            if item.get("status") == "REJECTED":
                # A definitive RPC rejection did not submit a transaction.
                # Do not repeatedly retry the same outputs (e.g., insufficient
                # funds for fees), but allow a new deposit to change the set.
                if output_ids == previous_ids:
                    return item
            elif not output_ids.isdisjoint(previous_ids):
                # INTENT/UNKNOWN/SUBMITTED all reserve those exact outputs.
                return item
        return None

    def record(self, attempt_id: str, source: str, account: int,
               destination: str, output_ids: list[str], status: str,
               **details: object) -> None:
        event = {"attempt_id": attempt_id, "source": source,
                 "account_index": account, "destination": destination,
                 "output_ids": output_ids, "status": status,
                 "recorded_at": datetime.now(timezone.utc).isoformat(),
                 **details}
        self.fp.write(json.dumps(event, separators=(",", ":")) + "\n")
        self.fp.flush()
        os.fsync(self.fp.fileno())
        self.attempts[attempt_id] = event

    def close(self) -> None:
        self.fp.close()


def unlocked_output_ids(transfers: list[dict]) -> set[str]:
    """Identify spendable outputs using their stable public output keys.

    Reject malformed or ambiguous data rather than constructing a transaction
    on an unverified output snapshot.
    """
    ids: set[str] = set()
    for output in transfers:
        if not isinstance(output, dict):
            raise RPCError("Invalid incoming_transfers output")
        if output.get("spent") or output.get("frozen") or output.get("unlocked") is not True:
            continue
        pubkey = output.get("pubkey", "")
        key_image = output.get("key_image", "")
        if isinstance(pubkey, str) and TX_HASH_RE.fullmatch(pubkey):
            identity = "pubkey:" + pubkey.lower()
        elif isinstance(key_image, str) and TX_HASH_RE.fullmatch(key_image):
            identity = "key_image:" + key_image.lower()
        else:
            raise RPCError("Spendable output missing pubkey/key image; cannot journal safely")
        ids.add(identity)
    return ids


def normalize_url(line: str) -> tuple[str, str, int, str]:
    candidate = line if "://" in line else "http://" + line
    parts = urlsplit(candidate)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("Expected an HTTP(S) URL or hostname:port")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError("Use direct daemon URLs without credentials, paths, queries, or fragments")
    default_port = 443 if parts.scheme == "https" else 18081
    port = parts.port or default_port
    host = parts.hostname.lower().rstrip(".")
    bracketed = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{bracketed}:{port}", host, port, parts.scheme


def daemon_ca_bundle(args: argparse.Namespace) -> str | None:
    """Find a PEM CA bundle for wallet-RPC TLS verification.

    Monero does not automatically accept the OS trust store when --daemon-ssl
    is enabled. An explicit CA file plus --daemon-ssl-allow-chained is needed.
    """
    if getattr(args, "daemon_ssl_allow_any_cert", False):
        return None
    explicit = getattr(args, "daemon_ssl_ca_certificates", None)
    if explicit is not None:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"Daemon TLS CA bundle not found: {path}")
        return str(path)
    defaults = ssl.get_default_verify_paths()
    paths = (
        defaults.cafile,
        "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Arch
        "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora, RHEL
        "/etc/ssl/cert.pem",  # macOS, others
    )
    for candidate in paths:
        if candidate is not None and Path(candidate).is_file():
            return str(Path(candidate).resolve())
    return None


def daemon_ssl_options(node: Node, args: argparse.Namespace) -> tuple[list[str], dict]:
    """Return Monero CLI flags and matching set_daemon JSON-RPC fields."""
    if node.scheme != "https":
        return [], {}
    if getattr(args, "daemon_ssl_allow_any_cert", False):
        return ["--daemon-ssl-allow-any-cert"], {"ssl_allow_any_cert": True}
    ca_bundle = daemon_ca_bundle(args)
    if not ca_bundle:
        raise ValueError(
            "HTTPS daemon requires a CA certificate bundle; specify "
            "--daemon-ssl-ca-certificates /path/to/ca-bundle.pem, or explicitly "
            "use --daemon-ssl-allow-any-cert for an unverified certificate"
        )
    return (["--daemon-ssl-ca-certificates", ca_bundle, "--daemon-ssl-allow-chained"],
            {"ssl_ca_file": ca_bundle, "ssl_allow_any_cert": False})


def daemon_probe_ssl(args: argparse.Namespace) -> ssl.SSLContext | bool:
    """Keep aiohttp's TLS policy consistent with the wallet daemon connection."""
    if getattr(args, "daemon_ssl_allow_any_cert", False):
        return False
    ca = getattr(args, "daemon_ssl_ca_certificates", None)
    if ca is not None:
        bundle = daemon_ca_bundle(args)
        return ssl.create_default_context(cafile=bundle)
    return ssl.create_default_context()


def load_rpc_urls(path: Path) -> list[tuple[str, str, int, str]]:
    found: dict[str, tuple[str, str, int, str]] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            endpoint = normalize_url(raw)
        except ValueError as exc:
            TerminalColor.warning("RPC line %d skipped: %s", number, exc)
            continue
        found[endpoint[0]] = endpoint
    return list(found.values())


async def json_rpc(session: aiohttp.ClientSession, url: str, method: str,
                   params: dict | None = None, timeout: aiohttp.ClientTimeout | None = None) -> dict:
    payload: dict = {"jsonrpc": "2.0", "id": "0", "method": method}
    if params is not None:
        payload["params"] = params
    started = time.monotonic()
    try:
        async with session.post(url, json=payload, timeout=timeout) as response:
            if response.status != 200:
                raise RPCTransportError(f"RPC {method}: HTTP {response.status} from {url}")
            try:
                body = await response.json(content_type=None)
            except (ValueError, aiohttp.ContentTypeError) as exc:
                raise RPCTransportError(f"RPC {method}: invalid JSON RPC response") from exc
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        elapsed = time.monotonic() - started
        raise RPCTransportError(
            f"RPC {method} transport error after {elapsed:.1f}s: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(body, dict):
        raise RPCError("RPC response was not an object")
    if body.get("error"):
        error = body["error"]
        if isinstance(error, dict):
            raise RPCError(f"RPC {method} error {error.get('code')}: {error.get('message')}")
        raise RPCError(f"RPC {method} error: {error}")
    if not isinstance(body.get("result"), dict):
        raise RPCError(f"RPC {method} response missing result")
    return body["result"]


async def resolve_ips(host: str, port: int) -> frozenset[str]:
    try:
        ipaddress.ip_address(host)
        return frozenset((host,))
    except ValueError:
        pass
    try:
        records = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM)
        return frozenset(record[4][0] for record in records)
    except OSError:
        return frozenset((host,))


async def probe_node(session: aiohttp.ClientSession,
                     endpoint: tuple[str, str, int, str], network: str) -> Node | None:
    url, host, port, scheme = endpoint
    try:
        info = await json_rpc(session, f"{url}/json_rpc", "get_info")
        height = int(info.get("height", 0))
        if info.get("status", "OK") != "OK" or height <= 0 or info.get("offline", False):
            raise RPCError("RPC not reporting an online blockchain")
        network_flags = {"mainnet": "mainnet", "testnet": "testnet", "stagenet": "stagenet"}
        if info.get("nettype") not in (None, network):
            raise RPCError(f"Daemon reports network {info['nettype']}")
        if info.get(network_flags[network]) is False:
            raise RPCError("Daemon is on a different network")
        for other_net, flag in network_flags.items():
            if other_net != network and info.get(flag) is True:
                raise RPCError(f"Daemon reports network {other_net}")
        aliases = await resolve_ips(host, port)
        TerminalColor.info("WORKING %s height=%d", url, height)
        return Node(url, host, port, scheme, height, aliases)
    except (RPCError, ValueError) as exc:
        TerminalColor.warning("NOT WORKING %s (%s)", url, exc)
        return None


async def find_nodes(endpoints: list[tuple[str, str, int, str]], args: argparse.Namespace,
                     daemon_session: aiohttp.ClientSession) -> list[Node]:
    probes = await asyncio.gather(*(probe_node(daemon_session, endpoint, args.network)
                                    for endpoint in endpoints))
    healthy = sorted((item for item in probes if item is not None), key=lambda n: n.height, reverse=True)
    if not healthy:
        return []
    highest = healthy[0].height
    unique: list[Node] = []
    for node in healthy:
        if highest - node.height > args.max_node_lag:
            TerminalColor.warning("STALE %s height=%d (tip among nodes: %d)", node.url, node.height, highest)
            continue
        if any(node.port == old.port and node.scheme == old.scheme
               and node.aliases.intersection(old.aliases) for old in unique):
            TerminalColor.info("DUPLICATE %s (same resolved IP/port as an accepted RPC)", node.url)
            continue
        unique.append(node)
    return unique


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass(slots=True)
class NodeState:
    node: Node
    target_limit: int
    allowed: int
    active: int = 0
    failures: int = 0
    successes: int = 0
    disabled_until: float = 0.0
    recovering: bool = False
    next_recovery_probe: float = 0.0
    generation: int = 0  # Prevent a stale health probe from undoing a later failure.


class NodePool:
    """Schedule wallet scans across nodes while enforcing adaptive capacities.

    Acquiring a node reserves one slot for the duration of exactly one wallet
    scan. A worker may change daemons between wallets, never during a scan.
    """

    def __init__(self, nodes: list[Node], args: argparse.Namespace):
        self.args = args
        self.states = [NodeState(node, args.workers_per_rpc, args.workers_per_rpc)
                       for node in nodes]
        self.by_url = {state.node.url: state for state in self.states}
        self.condition = asyncio.Condition()

    async def acquire(self, preferred: str | None) -> Node:
        async with self.condition:
            while True:
                candidates = [state for state in self.states
                              if not state.recovering and
                              state.disabled_until == 0 and
                              state.active < state.allowed]
                if candidates:
                    # Stick to a currently healthy daemon to avoid excessive
                    # set_daemon requests, but avoid recently failing nodes.
                    preferred_state = self.by_url.get(preferred) if preferred else None
                    min_failures = min(state.failures for state in candidates)
                    least_loaded = min(candidates,
                                       key=lambda state: (state.failures,
                                                          state.active / state.allowed,
                                                          state.active, state.node.url))
                    # Keep the process on its current node unless another
                    # healthy node is substantially less loaded. This also
                    # lets recovered nodes attract work again after failover.
                    if (preferred_state in candidates and
                            preferred_state.failures == min_failures and
                            preferred_state.active / preferred_state.allowed <=
                            least_loaded.active / least_loaded.allowed + 0.20):
                        chosen = preferred_state
                    else:
                        chosen = least_loaded
                    chosen.active += 1
                    return chosen.node
                await self.condition.wait()

    async def release(self, node: Node) -> None:
        async with self.condition:
            state = self.by_url[node.url]
            if state.active <= 0:
                raise RuntimeError(f"Unbalanced release for node {node.url}")
            state.active -= 1
            self.condition.notify_all()

    async def failure(self, node: Node, reason: str) -> None:
        async with self.condition:
            state = self.by_url[node.url]
            state.generation += 1
            state.failures += 1
            state.successes = 0
            previous = state.allowed
            state.allowed = max(1, (state.allowed + 1) // 2)
            if state.failures >= self.args.node_failure_threshold:
                state.disabled_until = time.monotonic() + self.args.node_cooldown
                state.allowed = 0
                state.next_recovery_probe = 0.0
                TerminalColor.warning("NODE COOLDOWN %s failures=%d for %.0fs: %s",
                                      node.url, state.failures, self.args.node_cooldown, reason)
            else:
                # A partially throttled node must also recover without waiting
                # for an entire wallet refresh to finish.
                state.next_recovery_probe = (
                        time.monotonic() + self.args.node_recovery_ramp_seconds)
                TerminalColor.warning("NODE THROTTLED %s capacity %d -> %d: %s",
                                      node.url, previous, state.allowed, reason)
            self.condition.notify_all()

    async def success(self, node: Node) -> None:
        async with self.condition:
            state = self.by_url[node.url]
            state.failures = 0
            state.successes += 1
            # Wallet completions can still accelerate recovery, but are NOT
            # required. The independent health monitor expands capacity even
            # while every active wallet is doing a long genesis-height refresh.
            if (state.disabled_until == 0 and not state.recovering and
                    state.allowed < state.target_limit and
                    state.successes >= self.args.node_recovery_successes):
                old = state.allowed
                state.allowed += 1
                state.successes = 0
                state.next_recovery_probe = (
                    time.monotonic() + self.args.node_recovery_ramp_seconds
                    if state.allowed < state.target_limit else 0.0)
                TerminalColor.info("NODE RECOVERING %s capacity %d -> %d/%d (wallet successes)",
                                   node.url, old, state.allowed, state.target_limit)
            self.condition.notify_all()

    async def monitor(self, session: aiohttp.ClientSession) -> None:
        """Recover disabled AND throttled nodes using independent health probes.

        A successful get_info probe first lets a disabled node rejoin. While
        its capacity is below target, further probes progressively restore
        slots without waiting for any wallet scan to complete.
        """
        poll_interval = min(3.0, self.args.node_cooldown,
                            self.args.node_recovery_ramp_seconds or 1.0)
        while True:
            await asyncio.sleep(poll_interval)
            due: list[tuple[NodeState, str, int]] = []
            async with self.condition:
                now = time.monotonic()
                for state in self.states:
                    if state.recovering:
                        continue
                    if state.disabled_until:
                        if now < state.disabled_until:
                            continue
                        kind = "rejoin"
                    elif (state.allowed < state.target_limit and
                          state.next_recovery_probe and
                          now >= state.next_recovery_probe):
                        kind = "ramp"
                    else:
                        continue
                    state.recovering = True
                    due.append((state, kind, state.generation))
            if not due:
                continue

            async def attempt(state: NodeState, kind: str, generation: int) -> None:
                healthy = False
                error = "unknown error"
                try:
                    result = await json_rpc(session, state.node.url + "/json_rpc", "get_info")
                    healthy = (result.get("status", "OK") == "OK"
                               and not result.get("offline", False)
                               and int(result.get("height", 0)) > 0
                               and result.get("nettype", self.args.network) == self.args.network)
                    if not healthy:
                        error = "daemon returned unhealthy status or wrong network"
                except (RPCError, ValueError) as exc:
                    error = str(exc)
                async with self.condition:
                    state.recovering = False
                    # A worker may have observed a fresh daemon error while
                    # this probe was in flight. Never overwrite that failure
                    # with an earlier successful health response.
                    if state.generation != generation:
                        self.condition.notify_all()
                        return
                    now = time.monotonic()
                    if healthy:
                        old = state.allowed
                        state.allowed = (state.target_limit
                                         if self.args.node_recovery_ramp_seconds == 0
                                         else min(state.target_limit,
                                                  1 if kind == "rejoin" else state.allowed + 1))
                        state.failures = 0
                        state.successes = 0
                        state.disabled_until = 0.0
                        state.next_recovery_probe = (
                            now + self.args.node_recovery_ramp_seconds
                            if state.allowed < state.target_limit else 0.0)
                        if kind == "rejoin":
                            TerminalColor.info("NODE REJOINED %s at capacity %d/%d%s",
                                               state.node.url, state.allowed, state.target_limit,
                                               "; remaining slots recover via health probes"
                                               if state.allowed < state.target_limit else
                                               "; full capacity restored")
                        elif state.allowed != old:
                            TerminalColor.info("NODE RECOVERING %s capacity %d -> %d/%d "
                                               "(health probe; no wallet completion required)",
                                               state.node.url, old, state.allowed, state.target_limit)
                    else:
                        # If the daemon is unstable during the ramp, stop new
                        # assignments and retry after the normal cooldown.
                        state.generation += 1
                        state.failures += 1
                        state.allowed = 0
                        state.disabled_until = now + self.args.node_cooldown
                        state.next_recovery_probe = 0.0
                        TerminalColor.warning("NODE STILL DOWN %s; next check in %.0fs: %s",
                                              state.node.url, self.args.node_cooldown, error)
                    self.condition.notify_all()

            await asyncio.gather(*(attempt(state, kind, generation)
                                   for state, kind, generation in due))


def is_node_related_failure(exc: Exception) -> bool:
    """Throttle only on evidence of a daemon issue, not a local wallet timeout."""
    if isinstance(exc, WalletRPCTransportError):
        return False
    message = str(exc).lower()
    hints = (
        "daemon", "node ", "busy", "rate limit", "overload", "too many requests",
        "http 429", "http 502", "http 503", "http 504", "timed out",
        "timeout", "failed to get blocks", "failed to get height", "connection refused",
        "connection reset", "connection failed", "connection error", "network error",
        "incomplete scan", "rpc transport error",
    )
    return any(hint in message for hint in hints)


def is_wallet_password_error(exc: Exception) -> bool:
    """Recognize wrong-password replies, including Monero's generic open failure.

    Some monero-wallet-rpc versions report incorrect passwords only as
    'Failed to open wallet', so that particular generic failure is also
    retried. After exhausting candidates the original cache is untouched.
    """
    if isinstance(exc, RPCTransportError):
        return False
    message = str(exc).lower()
    return any(part in message for part in (
        "invalid password", "wrong password", "incorrect password",
        "bad password", "password is incorrect", "password is wrong",
        "password mismatch", "password does not match", "password is not correct",
        "failed to decrypt", "decryption failed", "could not decrypt",
        "error decrypting wallet", "wallet password invalid",
        "failed to open wallet",  # Some RPC releases mask invalid_password.
    ))


class WalletRPC:
    """One local monero-wallet-rpc process; daemon can change between scans."""

    def __init__(self, number: int, node: Node, args: argparse.Namespace,
                 wallet_dir: Path, wallet_password: str):
        self.number = number
        self.node = node
        self.args = args
        self.wallet_dir = wallet_dir
        self.wallet_password = wallet_password
        self.proc: asyncio.subprocess.Process | None = None
        self.session: aiohttp.ClientSession | None = None
        self.endpoint = ""
        self._log_handle = None
        self._rpc_login = secrets.token_urlsafe(32)
        self._rpc_username = f"scanner{number}"
        self.open_wallet = False
        self.supplied_address_verified = True
        self.supplied_address_verification: dict = {}

    async def call(self, method: str, params: dict | None = None,
                   timeout_seconds: float | None = None) -> dict:
        if self.session is None:
            raise WalletRPCTransportError("Wallet RPC client is not initialized")
        timeout = (aiohttp.ClientTimeout(total=timeout_seconds, connect=15)
                   if timeout_seconds is not None else
                   aiohttp.ClientTimeout(total=None, connect=15, sock_read=None))
        started = time.monotonic()
        try:
            result = await json_rpc(self.session, self.endpoint, method, params, timeout)
        except RPCTransportError as exc:
            raise WalletRPCTransportError(
                f"local wallet-RPC worker {self.number}, method={method}: {exc}"
            ) from exc
        elapsed = time.monotonic() - started
        if elapsed >= 5:
            TerminalColor.info("WORKER %d RPC %s completed in %.1fs", self.number, method, elapsed)
        else:
            TerminalColor.debug("WORKER %d RPC %s completed in %.3fs", self.number, method, elapsed)
        return result

    async def call_with_progress(self, method: str, params: dict | None = None) -> dict:
        """Never time out a historical scan; report progress while its RPC is pending.

        This reports elapsed time rather than chain height because a wallet-RPC
        server may be busy processing refresh and unable to respond to get_height.
        """
        task = asyncio.create_task(self.call(method, params),
                                   name=f"wallet-{self.number}-{method}")
        started = time.monotonic()
        try:
            while not task.done():
                await asyncio.wait({task}, timeout=self.args.progress_interval)
                if not task.done():
                    TerminalColor.info("WORKER %d waiting for wallet-RPC %s: %.0fs elapsed "
                                       "(daemon=%s)", self.number, method,
                                       time.monotonic() - started, self.node.url)
            return await task
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    def build_command(self, port: int, log_path: Path) -> list[str]:
        ssl_flags, _ = daemon_ssl_options(self.node, self.args)
        cmd = [
            self.args.wallet_rpc_bin, "--wallet-dir", str(self.wallet_dir),
            "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(port),
            "--rpc-login", f"{self._rpc_username}:{self._rpc_login}",
            "--daemon-address", self.node.daemon_address,
            "--daemon-ssl", "enabled" if self.node.scheme == "https" else "disabled",
            *ssl_flags,
            "--untrusted-daemon", "--max-concurrency", str(self.args.wallet_threads),
            "--log-file", str(log_path), "--log-level", "0",
            "--non-interactive",
        ]
        if (self.args.verify_addresses_only or self.args.migrate_cache_passwords
                or getattr(self.args, "rebuild_offline_only", False)):
            # Key/address derivation is local. Do not connect to a daemon, DNS,
            # or the blockchain, even while opening an existing cached wallet.
            cmd.append("--offline")
        if self.args.watch_transfers:
            hook_file = self.wallet_dir / f"tx-notify-worker-{self.number}.txt"
            script_path = Path(__file__).resolve()
            notification_cmd = " ".join((
                shlex.quote(sys.executable),
                shlex.quote(str(script_path)),
                "--tx-notify-event",
                shlex.quote(str(hook_file)),
                "%s",
            ))
            cmd.extend(("--tx-notify", notification_cmd))
        if self.args.network != "mainnet":
            cmd.append("--testnet" if self.args.network == "testnet" else "--stagenet")
        return cmd

    async def start(self) -> None:
        port = pick_free_port()
        self.endpoint = f"http://127.0.0.1:{port}/json_rpc"
        digest = aiohttp.DigestAuthMiddleware(self._rpc_username, self._rpc_login)
        self.session = aiohttp.ClientSession(middlewares=(digest,),
                                             timeout=aiohttp.ClientTimeout(total=None, connect=15))
        log_path = self.wallet_dir / f"wallet-rpc-{self.number}.log"
        self._log_handle = log_path.open("ab")
        cmd = self.build_command(port, log_path)
        self.proc = await asyncio.create_subprocess_exec(
            *cmd, stdin=asyncio.subprocess.DEVNULL,
            stdout=self._log_handle, stderr=asyncio.subprocess.STDOUT)
        deadline = time.monotonic() + self.args.startup_timeout
        while time.monotonic() < deadline:
            if self.proc.returncode is not None:
                raise RPCTransportError(f"monero-wallet-rpc exited ({self.proc.returncode}); see {log_path}")
            try:
                await self.call("get_version", timeout_seconds=2)
                TerminalColor.info("WORKER %d ready on local port %d -> %s", self.number, port, self.node.url)
                return
            except (RPCError, asyncio.TimeoutError):
                await asyncio.sleep(0.5)
        raise RPCTransportError(f"Wallet RPC did not start; see {log_path}")

    async def set_node(self, node: Node) -> None:
        if self.node.url == node.url:
            return
        if self.open_wallet:
            raise RuntimeError("Cannot change daemon with an open wallet")
        if node.scheme == "https":
            raise RuntimeError("Switching to HTTPS requires restarting wallet-RPC for CA-chain verification")
        _, ssl_fields = daemon_ssl_options(node, self.args)
        await self.call("set_daemon", {
            "address": node.url,
            "trusted": False,
            "ssl_support": "enabled" if node.scheme == "https" else "disabled",
            **ssl_fields,
        }, timeout_seconds=30)
        TerminalColor.info("WORKER %d moved %s -> %s", self.number, self.node.url, node.url)
        self.node = node

    async def close_current(self) -> None:
        if self.open_wallet:
            await self.call("close_wallet", timeout_seconds=120)
            self.open_wallet = False

    async def open_cached_wallet(self, filename: str) -> str:
        """Open an encrypted wallet with a list of possible passwords, in order.

        Only password-authentication failures lead to the next candidate.
        Corruption, missing files, daemon errors, and RPC transport failures
        remain real errors, rather than being hidden by more password attempts.
        Returns the successful password in memory (never persisted or logged).
        Fresh wallets always use self.wallet_password, not a guessed password.
        """
        candidates = list(getattr(self.args, "cache_password_candidates", ()))
        candidates.append(self.wallet_password)  # Fallback to the local cache secret.
        unique: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                unique.append(candidate)
        if self.open_wallet:
            raise RuntimeError("Cannot open another cached wallet until current wallet is closed")
        for number, candidate in enumerate(unique, 1):
            try:
                await self.call_with_progress("open_wallet", {
                    "filename": filename, "password": candidate})
            except RPCTransportError:
                raise
            except RPCError as exc:
                if not is_wallet_password_error(exc):
                    raise
                TerminalColor.debug(
                    "WORKER %d cached wallet %s rejected password candidate %d/%d",
                    self.number, filename, number, len(unique))
                continue
            self.open_wallet = True
            TerminalColor.info("WORKER %d opened cached wallet %s with password "
                               "candidate %d/%d", self.number, filename,
                               number, len(unique))
            return candidate
        raise RPCError(
            f"Cached wallet {filename}: none of {len(unique)} candidate "
            "password(s) could open this wallet (wrong password, corrupt or "
            "unsupported cache); original cache preserved")

    def delete_mismatched_cached_key_wallet(self, job: WalletJob,
                                            cached_address: str) -> tuple[Path, Path]:
        """Remove an incorrectly associated key-wallet cache after RPC verification.

        Preconditions: `get_address` returned a valid, nonmatching primary
        address for a previously opened, now CLOSED, key-based cached wallet.
        Never delete on the basis of a *supplied-address* mismatch alone.
        Never touch a mnemonic cache, an unrelated basename, or shared secrets.
        """
        if job.mnemonic is not None or not job.spend or not job.view:
            raise RPCError("Cache cleanup is restricted to key-derived wallets")
        if self.open_wallet:
            raise RPCError("Refusing to delete wallet cache while wallet is open")
        if not ADDRESS_RE.fullmatch(cached_address):
            raise RPCError("Cannot verify mismatched cache: invalid reported wallet address")
        if cached_address == job.address:
            raise RPCError("Refusing to delete cache: cached address matches derived address")
        expected_name = "xmr_" + hashlib.sha256(
            (self.args.network + ":" + job.address).encode("utf-8")
        ).hexdigest()[:40]
        if job.name != expected_name:
            raise RPCError("Refusing to delete wallet cache with unexpected filename")

        wallet_path = self.wallet_dir / job.name
        keys_path = self.wallet_dir / (job.name + ".keys")
        root = self.wallet_dir.resolve(strict=True)
        for path in (wallet_path, keys_path):
            if path.parent.resolve(strict=True) != root or path.is_symlink():
                raise RPCError("Refusing to delete symlinked or out-of-directory wallet cache")
            if not path.is_file():
                raise RPCError(f"Refusing partial cache cleanup: required file missing: {path.name}")

        # The wallet RPC has already closed the wallet, ensuring it is no
        # longer using these files. No cache belonging to another job is touched.
        wallet_path.unlink()
        keys_path.unlink()
        TerminalColor.warning(
            "WORKER %d line %d deleted mismatched key-wallet cache %s "
            "(cached address=%s, derived address=%s); restoring from input keys",
            self.number, job.line, job.name, cached_address, job.address,
        )
        return wallet_path, keys_path

    async def generate_key_wallet(self, job: WalletJob) -> None:
        """Re-create and verify the key-based wallet after cache removal."""
        result = await self.call_with_progress("generate_from_keys", {
            "restore_height": self.args.restore_height,
            "filename": job.name,
            "address": job.address,
            "viewkey": job.view,
            "spendkey": job.spend,
            "password": self.wallet_password,
            "autosave_current": True,
        })
        self.open_wallet = True
        if result.get("address") != job.address:
            raise RPCError("Restored address did not match locally derived address")
        write_restore_height_metadata(self.wallet_dir, job, self.args.restore_height,
                                      self.args.network)

    async def sweep_wallet(self, job: WalletJob) -> dict:
        """Optionally sweep all unlocked accounts/subaddresses in this wallet.

        A connected daemon may process a submitted transaction even when this
        RPC call times out; the durable journal prevents blind resubmission.
        """
        accounts_result = await self.call("get_accounts", timeout_seconds=self.args.wallet_control_timeout)
        accounts = accounts_result.get("subaddress_accounts", [])
        eligible = [(int(entry["account_index"]), int(entry.get("unlocked_balance", 0)))
                    for entry in accounts if int(entry.get("unlocked_balance", 0)) > 0]
        if not eligible:
            return {"sweep_status": "NOTHING_UNLOCKED", "sweep_txids": "",
                    "sweep_amount_atomic": 0, "sweep_fee_atomic": 0, "sweep_error": ""}
        if job.address == self.args.sweep_to:
            return {"sweep_status": "SKIPPED_SELF", "sweep_txids": "",
                    "sweep_amount_atomic": 0, "sweep_fee_atomic": 0,
                    "sweep_error": "Destination is the source wallet"}
        if not self.args.execute_sweeps:
            TerminalColor.info("WORKER %d DRY RUN line %d: %d account(s), %s unlocked XMR -> %s",
                               self.number, job.line, len(eligible),
                               f"{Decimal(sum(amount for _, amount in eligible)) / ATOMIC:.12f}",
                               self.args.sweep_to)
            return {"sweep_status": "DRY_RUN", "sweep_txids": "",
                    "sweep_amount_atomic": 0, "sweep_fee_atomic": 0,
                    "sweep_error": ""}

        journal: SweepJournal = self.args.sweep_journal_instance
        txids: list[str] = []
        amount = fee = 0
        issues: list[str] = []
        submitted = skipped = 0
        for account_index, unlocked in eligible:
            previous = journal.get(job.address, account_index, self.args.sweep_to)
            if previous is not None:
                skipped += 1
                issues.append(f"account {account_index} already journaled ({previous['status']})")
                continue
            # Recording INTENT *before* network submission is deliberate.
            journal.record(job.address, account_index, self.args.sweep_to, "INTENT",
                           unlocked_at_scan=unlocked)
            try:
                response = await self.call_with_progress("sweep_all", {
                    "address": self.args.sweep_to,
                    "account_index": account_index,
                    "subaddr_indices_all": True,
                    "priority": self.args.sweep_priority,
                    "do_not_relay": False,
                    "get_tx_keys": False,
                    "get_tx_hex": False,
                    "get_tx_metadata": False,
                })
            except asyncio.CancelledError:
                # The INTENT remains as an ambiguous submission on disk.
                raise
            except WalletRPCTransportError as exc:
                journal.record(job.address, account_index, self.args.sweep_to,
                               "UNKNOWN", error=str(exc))
                issues.append(f"account {account_index} sweep outcome UNKNOWN: {exc}")
                break
            except RPCError as exc:
                journal.record(job.address, account_index, self.args.sweep_to,
                               "RPC_ERROR", error=str(exc))
                issues.append(f"account {account_index} rejected: {exc}")
                continue
            hashes = response.get("tx_hash_list", [])
            if not isinstance(hashes, list):
                hashes = []
            hashes = [str(txid) for txid in hashes]
            if not hashes:
                journal.record(job.address, account_index, self.args.sweep_to,
                               "UNKNOWN", error="RPC returned without transaction hashes")
                issues.append(f"account {account_index}: RPC returned without transaction hashes")
                break
            sent = sum(int(n) for n in response.get("amount_list", []))
            paid = sum(int(n) for n in response.get("fee_list", []))
            journal.record(job.address, account_index, self.args.sweep_to,
                           "SUBMITTED", txids=hashes,
                           amount_atomic=sent, fee_atomic=paid)
            amount += sent
            fee += paid
            submitted += 1
            txids.extend(hashes)
            TerminalColor.good("WORKER %d line %d account %d sweep submitted %d tx(s), "
                               "amount=%s XMR, fee=%s XMR, txids=%s", self.number, job.line,
                               account_index, len(hashes), f"{Decimal(sent) / ATOMIC:.12f}",
                               f"{Decimal(paid) / ATOMIC:.12f}", ",".join(hashes))
        if issues:
            status = "PARTIAL" if submitted else ("SKIPPED_RECORDED" if skipped == len(eligible) else "ERROR")
        else:
            status = "SUBMITTED" if submitted else "NOTHING_UNLOCKED"
        return {"sweep_status": status, "sweep_txids": ";".join(txids),
                "sweep_amount_atomic": amount, "sweep_fee_atomic": fee,
                "sweep_error": "; ".join(issues)}

    @staticmethod
    def use_restored_address(job: WalletJob, address: str) -> None:
        """Trust the wallet's mnemonic-derived address, not an input hint.

        This applies only to mnemonic wallets. For a private-key pair the
        locally derived address remains a strict check against the RPC wallet
        to avoid mistakenly opening an unrelated cached wallet.
        """
        if not isinstance(address, str) or not ADDRESS_RE.fullmatch(address):
            raise RPCError("Wallet RPC returned an invalid restored primary address")
        if (job.supplied_address and address != job.supplied_address
                and job.address != address):
            TerminalColor.warning(
                "Line %d: supplied address %s does not match mnemonic-derived "
                "address %s; scanning derived address",
                job.line, job.supplied_address, address)
        job.address = address

    async def setup_subaddresses(self, job: WalletJob, opened_cached_wallet: bool,
                                 *, rescan_if_needed: bool = True) -> tuple[dict, Path]:
        """Expand the RPC discovery map, verify the supplied subaddress, and
        rebuild cached history when a newly enlarged map could have missed
        outputs in blocks already scanned. The source wallet is never deleted.
        """
        metadata_path = self.wallet_dir / (job.name + ".subaddress-lookahead.json")
        prior: dict | None = None
        if metadata_path.is_file():
            try:
                candidate = json.loads(metadata_path.read_text(encoding="utf-8"))
                if (isinstance(candidate, dict)
                        and candidate.get("address") == job.address
                        and candidate.get("network") == self.args.network
                        and candidate.get("synchronized") is True):
                    prior = candidate
            except (OSError, ValueError, TypeError):
                TerminalColor.warning("Line %d: invalid lookahead metadata; will recheck cached history", job.line)

        major, minor = self.args.subaddress_lookahead
        max_major, max_minor = self.args.subaddress_search_limit
        # Restore a previously expanded map even when this run specifies a
        # smaller default; shrinking silently might hide earlier subaddresses.
        if prior is not None:
            major = max(major, int(prior.get("major", 0)))
            minor = max(minor, int(prior.get("minor", 0)))
        if major * minor > 500000:
            raise RPCError("Saved subaddress lookahead exceeds safe allocation limit")
        supplied = job.supplied_address
        kind = supplied_address_kind(supplied, self.args.network) if supplied else "not_supplied"
        verification = {
            "supplied_address_status": "NOT_SUPPLIED" if not supplied else "UNVERIFIED",
            "supplied_account_index": "", "supplied_subaddress_index": "",
        }
        last_address_error = ""
        # No discovery table is necessary when all we need is the primary
        # address. Avoid spending CPU/memory building tens of thousands of
        # subaddresses for no reason in address-only mode.
        if self.args.verify_addresses_only and kind != "subaddress":
            if not supplied:
                verification["supplied_address_status"] = "NOT_SUPPLIED"
            elif kind == "invalid":
                verification["supplied_address_status"] = "INVALID_SUPPLIED_ADDRESS"
            elif supplied == job.address:
                verification.update(supplied_address_status="PRIMARY_MATCH",
                                    supplied_account_index=0, supplied_subaddress_index=0)
            else:
                verification["supplied_address_status"] = "DIFFERENT_PRIMARY_WALLET"
            verification["lookahead_accounts"] = major
            verification["lookahead_subaddresses"] = minor
            self.supplied_address_verified = verification["supplied_address_status"] in (
                "NOT_SUPPLIED", "PRIMARY_MATCH")
            self.supplied_address_verification = verification
            return verification, metadata_path
        while True:
            TerminalColor.info("WORKER %d line %d setting subaddress lookahead to %d:%d",
                               self.number, job.line, major, minor)
            await self.call_with_progress("set_subaddress_lookahead", {
                "major_idx": major, "minor_idx": minor,
                "password": self.wallet_password,
            })
            if not supplied:
                break
            if kind == "invalid":
                verification["supplied_address_status"] = "INVALID_SUPPLIED_ADDRESS"
                break
            if supplied == job.address:
                verification.update(supplied_address_status="PRIMARY_MATCH",
                                    supplied_account_index=0, supplied_subaddress_index=0)
                break
            if kind == "primary":
                # A distinct standard address cannot be a subaddress of this wallet.
                verification["supplied_address_status"] = "DIFFERENT_PRIMARY_WALLET"
                break
            try:
                index_result = await self.call(
                    "get_address_index", {"address": supplied},
                    timeout_seconds=self.args.wallet_control_timeout)
                index = index_result.get("index", {})
                account, subaddress = int(index["major"]), int(index["minor"])
                verification.update(supplied_address_status="VERIFIED_SUBADDRESS",
                                    supplied_account_index=account,
                                    supplied_subaddress_index=subaddress)
                break
            except RPCTransportError:
                raise
            except (RPCError, KeyError, ValueError, TypeError) as exc:
                # Only an explicit "not in this wallet" RPC error justifies
                # increasing the lookahead. All other RPC failures are real errors.
                last_address_error = str(exc)
                if not isinstance(exc, RPCError) or not any(
                        term in last_address_error.lower() for term in
                        ("doesn't belong", "does not belong", "wrong address")):
                    raise RPCError(f"get_address_index failed: {exc}") from exc
            # Adaptive search for a supplied subaddress outside the ordinary
            # Monero gap. This can be expensive, so obey a finite user limit.
            next_major = min(max_major, max(major * 2, major + 1)) if major < max_major else major
            next_minor = min(max_minor, max(minor * 2, minor + 1)) if minor < max_minor else minor
            if next_major == major and next_minor == minor:
                verification["supplied_address_status"] = "UNRESOLVED_SUBADDRESS"
                break
            major, minor = next_major, next_minor
            if major * minor > 500000:
                verification["supplied_address_status"] = "UNRESOLVED_SUBADDRESS"
                TerminalColor.warning("Line %d: lookahead search hit address allocation cap", job.line)
                break

        verification["lookahead_accounts"] = major
        verification["lookahead_subaddresses"] = minor
        verified = verification["supplied_address_status"] in (
            "NOT_SUPPLIED", "PRIMARY_MATCH", "VERIFIED_SUBADDRESS")
        self.supplied_address_verified = verified
        self.supplied_address_verification = verification
        if supplied:
            if verified:
                TerminalColor.info("WORKER %d line %d VERIFIED supplied address at (%s,%s)",
                                   self.number, job.line,
                                   verification["supplied_account_index"],
                                   verification["supplied_subaddress_index"])
            else:
                TerminalColor.warning("WORKER %d line %d supplied address=%s does not verify "
                                      "against restored primary=%s (status=%s, lookahead=%d:%d). "
                                      "Continuing to scan and, if explicitly enabled, sweep the "
                                      "restored wallet. Check derivation, seed offset and "
                                      "subaddress range if this discrepancy is unexpected. %s",
                                      self.number, job.line, supplied, job.address,
                                      verification["supplied_address_status"], major, minor,
                                      last_address_error)

        # No automatic history rewrite on fresh restores; they haven't scanned
        # blocks under an older discovery window. Cached wallets need an actual
        # blockchain re-evaluation if the saved window is missing or smaller.
        existing_major = int(prior.get("major", 0)) if prior else 50
        existing_minor = int(prior.get("minor", 0)) if prior else 200
        needs_rescan = opened_cached_wallet and (
                (prior is None and (major > 50 or minor > 200)) or
                (prior is not None and (major > existing_major or minor > existing_minor)))
        if needs_rescan and not rescan_if_needed:
            TerminalColor.warning("Line %d: expanded cached-wallet subaddress lookahead "
                                  "during address verification only. Historical outputs "
                                  "have NOT been rescanned; the next normal scan will "
                                  "still perform its backup and rescan.", job.line)
        if needs_rescan and rescan_if_needed:
            TerminalColor.warning("WORKER %d line %d: expanded subaddress lookahead on cached "
                                  "wallet (%d:%d -> %d:%d); backing up cached wallet then "
                                  "running rescan_blockchain BEFORE any sweep",
                                  self.number, job.line, existing_major, existing_minor, major, minor)
            # rescan_blockchain can discard wallet-only metadata such as tx
            # destinations and notes. A fresh, exclusive backup of both cache
            # files is mandatory before doing anything destructive.
            await self.call("store", timeout_seconds=self.args.wallet_control_timeout)
            backup_root = self.wallet_dir / ".lookahead_backups"
            backup_root.mkdir(mode=0o700, exist_ok=True)
            if os.name == "posix":
                backup_root.chmod(0o700)
            backup_dir = Path(tempfile.mkdtemp(prefix=job.name + "-", dir=backup_root))
            if os.name == "posix":
                backup_dir.chmod(0o700)
            for suffix in ("", ".keys"):
                original = self.wallet_dir / (job.name + suffix)
                if not original.is_file() or original.is_symlink():
                    raise RPCError("Refusing to rescan: cached wallet file missing or symlinked")
                backup = backup_dir / original.name
                shutil.copy2(original, backup)
                if os.name == "posix":
                    backup.chmod(0o600)
            TerminalColor.warning("WORKER %d line %d wallet backup before rescan: %s",
                                  self.number, job.line, backup_dir)
            await self.call_with_progress("rescan_blockchain", {"hard": False})
        return verification, metadata_path

    def save_subaddress_metadata(self, job: WalletJob, path: Path, verified: dict) -> None:
        """Only mark range synchronized after full refresh and successful wallet store."""
        payload = {"address": job.address, "network": self.args.network,
                   "major": verified["lookahead_accounts"],
                   "minor": verified["lookahead_subaddresses"],
                   "synchronized": True, "timestamp": time.time()}
        fd, name = tempfile.mkstemp(prefix=".lookahead-", dir=self.wallet_dir)
        try:
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    async def verify_addresses_only(self, job: WalletJob) -> dict:
        """Verify wallet ownership of a supplied address with NO blockchain scan.

        This routine never invokes refresh, rescan_blockchain, get_balance,
        get_transfers, or any transfer method. Expanded lookahead is *not*
        marked synchronized, preserving the ordinary scanner's rescan safety.
        A mismatched cached key wallet is reported, not automatically deleted.
        """
        if not self.args.verify_addresses_only:
            raise RuntimeError("Address-only verification requires offline mode")
        await self.close_current()
        self.supplied_address_verified = True
        self.supplied_address_verification = {}
        path = self.wallet_dir / job.name
        cached = path.is_file() and (self.wallet_dir / (job.name + ".keys")).is_file()
        if cached:
            await self.open_cached_wallet(job.name)
        elif job.mnemonic is not None:
            params = {"restore_height": self.args.restore_height,
                      "filename": job.name, "seed": job.mnemonic,
                      "password": self.wallet_password, "autosave_current": True}
            if self.args.mnemonic_language:
                params["language"] = self.args.mnemonic_language
            if self.args.seed_offset_value:
                params["seed_offset"] = self.args.seed_offset_value
            restored = await self.call_with_progress("restore_deterministic_wallet", params)
            self.open_wallet = True
            self.use_restored_address(job, restored.get("address"))
            write_restore_height_metadata(self.wallet_dir, job, self.args.restore_height,
                                          self.args.network)
        else:
            await self.generate_key_wallet(job)

        # Verify the RPC wallet itself before checking its subaddresses. For
        # non-mnemonic jobs, never silently accept a mismatched saved cache.
        address_response = await self.call(
            "get_address", {"account_index": 0},
            timeout_seconds=self.args.wallet_control_timeout)
        actual_address = address_response.get("address")
        if job.mnemonic is not None:
            self.use_restored_address(job, actual_address)
        elif actual_address != job.address:
            raise RPCError("Cached/restored wallet primary address does not match "
                           "the keys supplied on this line; cache left untouched")

        await self.call("auto_refresh", {"enable": False},
                        timeout_seconds=self.args.wallet_control_timeout)
        verification, _ = await self.setup_subaddresses(
            job, cached, rescan_if_needed=False)
        # close_wallet persists the requested lookahead, but we intentionally
        # do not write .subaddress-lookahead.json synchronized metadata.
        await self.close_current()
        state = verification["supplied_address_status"]
        return {
            "line": job.line,
            "supplied_address": job.supplied_address or "",
            "derived_address": job.address,
            "address_mismatch": job.address_mismatch,
            **verification,
            "seed_format": job.seed_format,
            "key_recovery": job.key_recovery,
            "status": ("UNVERIFIED" if state in (
                "UNRESOLVED_SUBADDRESS", "DIFFERENT_PRIMARY_WALLET",
                "INVALID_SUPPLIED_ADDRESS") else
                       "NO_SUPPLIED_ADDRESS" if state == "NOT_SUPPLIED" else "VERIFIED"),
            "error": "",
        }

    async def scan(self, job: WalletJob, daemon_session: aiohttp.ClientSession,
                   transactions: TransactionResults | None = None) -> dict:
        # Only one wallet is open in this process at any instant.
        await self.close_current()
        wallet_file = self.wallet_dir / job.name
        restored_address: str | None = None
        opened_cached_wallet = (wallet_file.is_file() and
                                (self.wallet_dir / (job.name + ".keys")).is_file())
        if opened_cached_wallet:
            await self.open_cached_wallet(job.name)
        elif job.mnemonic is not None:
            params = {"restore_height": self.args.restore_height,
                      "filename": job.name, "seed": job.mnemonic,
                      "password": self.wallet_password, "autosave_current": True}
            if self.args.mnemonic_language:
                params["language"] = self.args.mnemonic_language
            if self.args.seed_offset_value:
                params["seed_offset"] = self.args.seed_offset_value
            restored = await self.call_with_progress("restore_deterministic_wallet", params)
            self.open_wallet = True
            restored_address = restored.get("address")
            self.use_restored_address(job, restored_address)
            write_restore_height_metadata(self.wallet_dir, job, self.args.restore_height,
                                          self.args.network)
        else:
            await self.generate_key_wallet(job)
        self.open_wallet = True
        # Verify the address for both restored and cached wallets.
        address_response = await self.call("get_address", {"account_index": 0},
                                           timeout_seconds=self.args.wallet_control_timeout)
        actual_address = address_response["address"]
        if job.mnemonic is not None:
            if restored_address is not None and actual_address != restored_address:
                raise RPCError(
                    "Wallet RPC get_address disagrees with mnemonic restoration; "
                    "refusing to use an inconsistent wallet cache")
            self.use_restored_address(job, actual_address)
        else:
            if actual_address != job.address:
                if not opened_cached_wallet:
                    raise RPCError(
                        "Newly restored wallet address does not match the derived "
                        "address; refusing to delete an unverified cache")
                # get_address positively identified a different cached wallet.
                # Close it first, then remove its wallet and .keys files.
                # Rebuild once; the rebuilt address must match before scanning
                # or any optional sweep takes place.
                await self.close_current()
                self.delete_mismatched_cached_key_wallet(job, actual_address)
                await self.generate_key_wallet(job)
                verified = await self.call(
                    "get_address", {"account_index": 0},
                    timeout_seconds=self.args.wallet_control_timeout)
                if verified.get("address") != job.address:
                    raise RPCError("Regenerated wallet does not match derived address ")

        await self.call("auto_refresh", {"enable": False},
                        timeout_seconds=self.args.wallet_control_timeout)
        verification, lookahead_path = await self.setup_subaddresses(job, opened_cached_wallet)
        wallet_height = daemon_height = 0
        for _ in range(3):
            await self.call_with_progress("refresh")
            height_result = await self.call(
                "get_height", timeout_seconds=self.args.wallet_control_timeout)
            wallet_height = int(height_result["height"])
            node_info = await json_rpc(daemon_session, self.node.url + "/json_rpc", "get_info")
            daemon_height = int(node_info["height"])
            if wallet_height >= daemon_height - 2:
                break
        else:
            raise RPCError(f"Incomplete scan: wallet at {wallet_height}, daemon at {daemon_height}")

        result = await self.call("get_balance", {"all_accounts": True},
                                 timeout_seconds=self.args.wallet_control_timeout)
        total_atomic = int(result["balance"])
        unlocked_atomic = int(result["unlocked_balance"])
        # Export the history after refresh, before any optional sweep, so a
        # sweep error cannot erase a successfully captured transaction history.
        tx_summary = {"transaction_count": 0, "incoming_count": 0,
                      "outgoing_count": 0, "pending_count": 0,
                      "failed_count": 0, "pool_count": 0,
                      "transactions_status": "DISABLED"}
        if transactions is not None:
            transfers = await self.call_with_progress("get_transfers", {
                "in": True, "out": True, "pending": True, "failed": True,
                "pool": True, "all_accounts": True,
            })
            new_rows = transactions.add_transfers(job, transfers, wallet_height, daemon_height)
            tx_summary = transactions.wallet_summary(job.address)
            TerminalColor.info("WORKER %d line %d exported %d new transaction rows (%d total)",
                               self.number, job.line, new_rows, tx_summary["transaction_count"])

        sweep = {"sweep_status": "NOT_REQUESTED", "sweep_txids": "",
                 "sweep_amount_atomic": 0, "sweep_fee_atomic": 0, "sweep_error": ""}
        if self.args.sweep_to and not self.args.watch_transfers:
            # The supplied address is a hint, NOT the authority for the source
            # wallet. We have already checked that wallet RPC's primary address
            # agrees with the wallet derived/restored from the provided keys.
            # Preserve the mismatch status in the CSV, but do not suppress a
            # user-requested dry run or an explicitly enabled sweep.
            sweep = await self.sweep_wallet(job)
            if transactions is not None and sweep["sweep_txids"]:
                # Submitted sweeps may be represented as pending or pool entries.
                # Query again to capture them without duplicating earlier rows.
                try:
                    latest = await self.call_with_progress("get_transfers", {
                        "in": True, "out": True, "pending": True, "failed": True,
                        "pool": True, "all_accounts": True,
                    })
                    new_rows = transactions.add_transfers(job, latest, wallet_height, daemon_height)
                    tx_summary = transactions.wallet_summary(job.address)
                    TerminalColor.info("WORKER %d line %d exported %d new post-sweep transaction rows",
                                       self.number, job.line, new_rows)
                except Exception as exc:
                    # A submitted sweep must never be retried just because
                    # transaction-history reporting failed afterward.
                    TerminalColor.warning("WORKER %d line %d post-sweep history refresh failed: %s",
                                          self.number, job.line, exc)
                    tx_summary["transactions_status"] = "PARTIAL_POST_SWEEP"
        await self.call("store", timeout_seconds=self.args.wallet_control_timeout)
        self.save_subaddress_metadata(job, lookahead_path, verification)
        if not self.args.watch_transfers:
            await self.close_current()
        else:
            # The wallet must remain loaded for --tx-notify to fire later.
            await self.call("auto_refresh", {
                "enable": True,
                "period": self.args.watch_refresh_seconds,
            }, timeout_seconds=self.args.wallet_control_timeout)
        return {
            "line": job.line, "address": job.address,
            "supplied_address": job.supplied_address or "",
            "address_mismatch": job.address_mismatch,
            **verification,
            "key_recovery": job.key_recovery,
            "seed_format": job.seed_format,
            "balance_xmr": f"{Decimal(total_atomic) / ATOMIC:.12f}",
            "unlocked_xmr": f"{Decimal(unlocked_atomic) / ATOMIC:.12f}",
            "balance_atomic": total_atomic, "unlocked_atomic": unlocked_atomic,
            "wallet_height": wallet_height, "daemon_height": daemon_height,
            "rpc": self.node.url, "status": "OK", "error": "", **sweep, **tx_summary,
        }

    async def sweep_unlocked_watch(self, job: WalletJob,
                                   daemon_session: aiohttp.ClientSession) -> None:
        """Sweep each account's currently unlocked outputs at most once.

        Rechecks daemon/wallet heights, checks exact spendable output IDs, then
        fsyncs an INTENT prior to broadcasting. New outputs can be swept in a
        later round once previously submitted outputs are no longer available.
        """
        if not self.args.watch_auto_sweep:
            return
        # Supplied address mismatches remain visible in the verification
        # results but do not inhibit sweeping the key-derived wallet. The
        # existing unlocked-output, sync, destination and journal safeguards
        # below continue to apply.
        if job.address == self.args.sweep_to:
            TerminalColor.warning("WATCH line %d destination is the source wallet; skipping", job.line)
            return
        wallet_status = await self.call("get_height", timeout_seconds=self.args.wallet_control_timeout)
        daemon_info = await json_rpc(daemon_session, self.node.url + "/json_rpc", "get_info")
        wallet_height = int(wallet_status["height"])
        daemon_height = int(daemon_info["height"])
        if daemon_info.get("status", "OK") != "OK" or daemon_info.get("offline"):
            TerminalColor.warning("WATCH line %d daemon not healthy; deferring sweep", job.line)
            return
        if wallet_height < daemon_height - 2:
            TerminalColor.info("WATCH line %d waiting for wallet sync (%d/%d), not sweeping",
                               job.line, wallet_height, daemon_height)
            return

        journal: WatchSweepJournal = self.args.watch_sweep_journal_instance
        accounts_result = await self.call("get_accounts", timeout_seconds=self.args.wallet_control_timeout)
        accounts = accounts_result.get("subaddress_accounts", [])
        if not isinstance(accounts, list):
            raise RPCError("get_accounts returned invalid accounts")
        for account in accounts:
            index = int(account["account_index"])
            unlocked = int(account.get("unlocked_balance", 0))
            if unlocked <= 0:
                continue
            response = await self.call("incoming_transfers", {
                "transfer_type": "available", "account_index": index,
            }, timeout_seconds=self.args.wallet_control_timeout)
            entries = response.get("transfers", [])
            if not isinstance(entries, list):
                raise RPCError("incoming_transfers returned invalid transfers")
            output_ids = unlocked_output_ids(entries)
            if not output_ids:
                TerminalColor.warning("WATCH line %d account %d has %s unlocked XMR but no "
                                      "verifiable spendable outputs; no sweep attempted",
                                      job.line, index, xmr_amount(unlocked))
                continue
            collision = journal.conflicting(job.address, index, self.args.sweep_to, output_ids)
            if collision is not None:
                TerminalColor.debug("WATCH line %d account %d skipping outputs reserved by %s (%s)",
                                    job.line, index, collision["attempt_id"][:16], collision["status"])
                continue
            ids = sorted(output_ids)
            digest = hashlib.sha256(json.dumps(
                [job.address, index, self.args.sweep_to, ids],
                separators=(",", ":")).encode("ascii")).hexdigest()
            journal.record(digest, job.address, index, self.args.sweep_to, ids,
                           "INTENT", unlocked_at_attempt=unlocked)
            TerminalColor.info("WATCH sweep line %d account %d: %s unlocked XMR (%d outputs) -> %s",
                               job.line, index, xmr_amount(unlocked), len(ids), self.args.sweep_to)
            try:
                tx = await self.call_with_progress("sweep_all", {
                    "address": self.args.sweep_to,
                    "account_index": index,
                    "subaddr_indices_all": True,
                    "priority": self.args.sweep_priority,
                    "do_not_relay": False,
                    "get_tx_keys": False,
                    "get_tx_hex": False,
                    "get_tx_metadata": False,
                })
            except asyncio.CancelledError:
                # Keep INTENT: daemon may have received request before interruption.
                raise
            except WalletRPCTransportError as exc:
                journal.record(digest, job.address, index, self.args.sweep_to, ids,
                               "UNKNOWN", error=str(exc))
                TerminalColor.error("WATCH line %d account %d sweep outcome UNKNOWN: %s", job.line, index, exc)
                return
            except RPCError as exc:
                journal.record(digest, job.address, index, self.args.sweep_to, ids,
                               "REJECTED", error=str(exc))
                TerminalColor.error("WATCH line %d account %d sweep rejected: %s", job.line, index, exc)
                continue
            hashes = tx.get("tx_hash_list", [])
            if not isinstance(hashes, list) or not hashes or not all(
                    isinstance(h, str) and TX_HASH_RE.fullmatch(h) for h in hashes):
                journal.record(digest, job.address, index, self.args.sweep_to, ids,
                               "UNKNOWN", error="RPC did not return valid transaction hashes")
                TerminalColor.error("WATCH line %d account %d sweep response missing valid tx hashes",
                                    job.line, index)
                return
            hashes = [h.lower() for h in hashes]
            amount = sum(int(v) for v in tx.get("amount_list", []))
            fee = sum(int(v) for v in tx.get("fee_list", []))
            journal.record(digest, job.address, index, self.args.sweep_to, ids,
                           "SUBMITTED", txids=hashes, amount_atomic=amount, fee_atomic=fee)
            TerminalColor.info("WATCH SWEEP SENT line %d account %d amount=%s fee=%s txids=%s",
                               job.line, index, xmr_amount(amount), xmr_amount(fee), ",".join(hashes))
            # Transaction is journaled even if wallet saving subsequently fails.
            try:
                await self.call("store", timeout_seconds=self.args.wallet_control_timeout)
            except RPCError as exc:
                TerminalColor.warning("WATCH sweep submitted but wallet store failed line %d: %s",
                                      job.line, exc)

    async def watch_wallet(self, job: WalletJob,
                           daemon_session: aiohttp.ClientSession,
                           transactions: TransactionResults | None) -> None:
        """Monitor an open wallet and optionally sweep unlocked funds.

        A callback prompts early reconciliation; periodic checks also catch
        outputs unlocking without any new notification event.
        """
        if not self.open_wallet:
            raise RuntimeError("Cannot watch a closed wallet")
        ledger = WatchedTxLedger(self.wallet_dir / (job.name + ".watch-txids"))
        hook_path = self.wallet_dir / f"tx-notify-worker-{self.number}.txt"
        # The RPC may have fired historical events during initial sync, so
        # establish the callback file offset only after full wallet sync.
        offset = hook_path.stat().st_size if hook_path.is_file() else 0

        async def reconcile(first: bool = False) -> None:
            nonlocal offset
            history = await self.call_with_progress("get_transfers", {
                "in": True, "out": True, "pending": True,
                "failed": True, "pool": True, "all_accounts": True,
            })
            txids = set()
            for bucket in ("in", "pool"):
                for tx in history.get(bucket, []) or []:
                    if tx.get("type", bucket) in ("in", "block", "pool"):
                        txid = tx.get("txid", "")
                        if isinstance(txid, str) and TX_HASH_RE.fullmatch(txid):
                            txids.add(txid)
            new = ledger.apply(txids)
            height = await self.call("get_height", timeout_seconds=self.args.wallet_control_timeout)
            node = await json_rpc(daemon_session, self.node.url + "/json_rpc", "get_info")
            if transactions is not None:
                transactions.add_transfers(job, history, int(height["height"]), int(node["height"]))
            for tx in history.get("in", []) + history.get("pool", []):
                if str(tx.get("txid", "")).lower() in new:
                    TerminalColor.info("WATCH new incoming wallet=%s txid=%s amount=%s XMR "
                                       "confirmations=%s locked=%s time=%s",
                                       job.address, tx.get("txid"),
                                       xmr_amount(int(tx.get("amount", 0))),
                                       tx.get("confirmations", 0),
                                       tx.get("locked", True),
                                       utc_timestamp(tx.get("timestamp", 0)))
            if first:
                TerminalColor.info("WATCH active worker=%d line=%d wallet=%s; "
                                   "initial historical transactions=%d; new receipts are logged",
                                   self.number, job.line, job.address, len(ledger.seen))

        await reconcile(first=True)
        if self.args.watch_auto_sweep:
            await self.sweep_unlocked_watch(job, daemon_session)
        last_poll = time.monotonic()
        while True:
            if self.proc is None or self.proc.returncode is not None:
                raise WalletRPCTransportError("Watched wallet RPC process has stopped")
            await asyncio.sleep(self.args.watch_check_seconds)
            # Callback file is append-only; read newly written hashes only.
            notify = False
            if hook_path.is_file():
                with hook_path.open("r", encoding="ascii", errors="replace") as stream:
                    stream.seek(offset)
                    chunk = stream.read()
                    offset = stream.tell()
                notify = any(TX_HASH_RE.fullmatch(t) for t in chunk.splitlines())
            if notify or time.monotonic() - last_poll >= self.args.watch_poll_seconds:
                await reconcile()
                if self.args.watch_auto_sweep:
                    await self.sweep_unlocked_watch(job, daemon_session)
                last_poll = time.monotonic()

    async def stop(self) -> None:
        if self.proc is not None and self.proc.returncode is None:
            if self.session is not None:
                try:
                    await self.call("stop_wallet", timeout_seconds=20)
                except (Exception, asyncio.CancelledError):
                    pass
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=15)
            except asyncio.TimeoutError:
                self.proc.terminate()
                try:
                    await asyncio.wait_for(self.proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    self.proc.kill()
                    await self.proc.wait()
        if self.session is not None:
            await self.session.close()
            self.session = None
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None


class Results:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        backup_existing_output(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self.fp = os.fdopen(fd, "w", newline="", encoding="utf-8")
        if os.name == "posix":
            os.chmod(path, 0o600)
        self.writer = csv.DictWriter(self.fp, fieldnames=FIELDS)
        self.writer.writeheader()
        self.success = 0
        self.failures = 0
        self.nonzero = 0

    def add(self, data: dict) -> None:
        self.writer.writerow({key: data.get(key, "") for key in FIELDS})
        self.fp.flush()
        if data.get("status") == "OK":
            self.success += 1
            if int(data.get("balance_atomic", 0)) > 0:
                self.nonzero += 1
            if data.get("sweep_status") in ("ERROR", "PARTIAL"):
                self.failures += 1
        else:
            self.failures += 1

    def close(self) -> None:
        self.fp.close()


VERIFY_FIELDS = (
    "line", "supplied_address", "derived_address", "address_mismatch",
    "supplied_address_status", "supplied_account_index", "supplied_subaddress_index",
    "lookahead_accounts", "lookahead_subaddresses", "seed_format",
    "key_recovery", "status", "error",
)


class VerificationResults:
    """Dedicated offline verification report; never contains spend/view keys."""

    def __init__(self, path: Path):
        path = path.expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        backup_existing_output(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self.fp = os.fdopen(fd, "w", newline="", encoding="utf-8")
        if os.name == "posix":
            os.chmod(path, 0o600)
        self.writer = csv.DictWriter(self.fp, fieldnames=VERIFY_FIELDS)
        self.writer.writeheader()
        self.fp.flush()
        self.counts: Counter[str] = Counter()

    def add(self, row: dict) -> None:
        self.writer.writerow({key: row.get(key, "") for key in VERIFY_FIELDS})
        self.fp.flush()
        self.counts[str(row.get("status", "ERROR"))] += 1

    def close(self) -> None:
        self.fp.close()


async def verification_worker(number: int, queue: asyncio.Queue[WalletJob],
                              results: VerificationResults, args: argparse.Namespace,
                              cache: Path, password: str) -> None:
    """Reuse one local *offline* wallet RPC per worker; never contact monerod."""
    offline_node = Node("http://127.0.0.1:18081", "127.0.0.1", 18081,
                        "http", 0, frozenset(("127.0.0.1",)))
    rpc: WalletRPC | None = None
    try:
        while True:
            try:
                job = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                for attempt in range(args.retries + 1):
                    try:
                        if rpc is None:
                            rpc = WalletRPC(number, offline_node, args, cache, password)
                            await rpc.start()
                        TerminalColor.info("VERIFY worker=%d line=%d checking supplied address", number, job.line)
                        row = await rpc.verify_addresses_only(job)
                        results.add(row)
                        TerminalColor.info("VERIFY line=%d %s %s (%s,%s)", job.line,
                                           row["status"], row.get("supplied_address_status", ""),
                                           row.get("supplied_account_index", ""),
                                           row.get("supplied_subaddress_index", ""))
                        break
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        # Reset the local RPC on any uncertain state. Never
                        # delete the user's wallet files during verification.
                        TerminalColor.warning("VERIFY line %d attempt %d/%d: %s",
                                              job.line, attempt + 1, args.retries + 1, exc)
                        if rpc is not None:
                            await rpc.stop()
                            rpc = None
                        if is_permanent_mnemonic_error(job, exc):
                            if job.line not in args.error_key_line_numbers:
                                args.error_key_line_numbers.add(job.line)
                                write_error_keys(args.keys, [
                                    {"line": i} for i in args.error_key_line_numbers],
                                                 args.error_keys_path)
                                refresh_corrected_export_after_mnemonic_rejection(args)
                            results.add({"line": job.line, "supplied_address": job.supplied_address or "",
                                         "derived_address": job.address, "seed_format": job.seed_format,
                                         "status": "INVALID", "error": str(exc)})
                            break
                        if attempt == args.retries:
                            results.add({"line": job.line, "supplied_address": job.supplied_address or "",
                                         "derived_address": job.address, "seed_format": job.seed_format,
                                         "status": "ERROR", "error": str(exc)})
            finally:
                queue.task_done()
    finally:
        if rpc is not None:
            await rpc.stop()


async def run_verification_only(args: argparse.Namespace,
                                jobs: list[WalletJob], invalid: list[dict]) -> int:
    """Standalone, offline, no-refresh address verification workflow."""
    cache = args.cache_dir.expanduser().resolve()
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        cache.chmod(0o700)
    password = cache_password(cache)
    report = VerificationResults(args.verify_output)
    try:
        for row in invalid:
            report.add({"line": row["line"], "status": "INVALID", "error": row["error"]})
        if not jobs:
            TerminalColor.warning("No recoverable wallets for address verification")
            return 1
        if args.rebuild_cache:
            rebuild_selected_wallet_caches(cache, jobs, args.restore_height)
        elif args.rebuild_if_lower:
            rebuild_caches_if_lower(cache, jobs, args.restore_height,
                                    args.network, args.rebuild_unknown_height)
        count = min(len(jobs), args.max_total_workers)
        TerminalColor.info("Verifying %d wallet(s) offline with %d wallet RPC process(es); "
                           "no daemon connection or blockchain synchronization", len(jobs), count)
        queue: asyncio.Queue[WalletJob] = asyncio.Queue()
        for job in jobs:
            queue.put_nowait(job)
        workers = [asyncio.create_task(verification_worker(i, queue, report, args, cache, password),
                                       name=f"verification-worker-{i}")
                   for i in range(1, count + 1)]
        worker_results = await asyncio.gather(*workers, return_exceptions=True)
        for outcome in worker_results:
            if isinstance(outcome, BaseException):
                TerminalColor.error("Address verification worker crashed: %r", outcome)
        # Any jobs not processed due to a worker crash must appear in the report.
        while not queue.empty():
            job = queue.get_nowait()
            report.add({"line": job.line, "supplied_address": job.supplied_address or "",
                        "derived_address": job.address, "status": "ERROR",
                        "error": "Verification worker exited unexpectedly"})
            queue.task_done()
        TerminalColor.info("Verification finished: %s. CSV: %s",
                           dict(report.counts), args.verify_output.expanduser().resolve())
        return 1 if (report.counts["INVALID"] or report.counts["ERROR"] or
                     report.counts["UNVERIFIED"] or
                     any(isinstance(x, BaseException) for x in worker_results)) else 0
    finally:
        report.close()


async def scanner_worker(number: int, initial_node: Node, pool: NodePool,
                         queue: asyncio.Queue[WalletJob], results: Results,
                         daemon_session: aiohttp.ClientSession,
                         args: argparse.Namespace, cache: Path,
                         password: str, transactions: TransactionResults | None) -> None:
    rpc: WalletRPC | None = None
    preferred: str | None = initial_node.url
    startup_failures = 0
    try:
        while True:
            node = await pool.acquire(preferred)
            # A reservation is held until the wallet is finished (or the
            # worker is cancelled). It is never held across a queued retry.
            try:
                if rpc is None:
                    rpc = WalletRPC(number, node, args, cache, password)
                    try:
                        await rpc.start()
                        startup_failures = 0
                    except Exception as exc:
                        startup_failures += 1
                        TerminalColor.error("WORKER %d failed to start (%d/%d): %s", number,
                                            startup_failures, args.worker_start_retries, exc)
                        await rpc.stop()
                        rpc = None
                        preferred = None
                        if startup_failures >= args.worker_start_retries:
                            return
                        await asyncio.sleep(min(2 * startup_failures, 5))
                        continue
                elif rpc.node.url != node.url:
                    try:
                        if node.scheme == "https":
                            # Monero's set_daemon RPC cannot request user_ca
                            # (certificate-chain) verification. Restart this
                            # process so --daemon-ssl-allow-chained is honored.
                            # No wallet is open between scans at this point.
                            await rpc.stop()
                            rpc = None
                            rpc = WalletRPC(number, node, args, cache, password)
                            await rpc.start()
                        else:
                            await rpc.set_node(node)
                    except Exception as exc:
                        TerminalColor.warning("WORKER %d daemon switch failed: %s", number, exc)
                        if rpc is not None:
                            await rpc.stop()
                        rpc = None
                        preferred = None
                        continue

                job = await queue.get()
                try:
                    TerminalColor.info("[%d/%s] scanning line %d %s", number, node.url,
                                       job.line, job.address or "<mnemonic wallet>")
                    result = await rpc.scan(job, daemon_session, transactions)
                    results.add(result)
                    await pool.success(node)
                    preferred = node.url
                    TerminalColor.info("[%d] line=%d balance=%s XMR unlocked=%s XMR (%d/%d)",
                                       number, job.line, result["balance_xmr"], result["unlocked_xmr"],
                                       result["wallet_height"], result["daemon_height"])
                    if args.watch_transfers:
                        await rpc.watch_wallet(job, daemon_session, transactions)
                except Exception as exc:
                    TerminalColor.error("[%d] line=%d failed on %s: %s", number, job.line,
                                        node.url, exc)
                    if is_node_related_failure(exc):
                        await pool.failure(node, str(exc))
                    elif isinstance(exc, WalletRPCTransportError):
                        TerminalColor.warning("WORKER %d wallet RPC failed, but local wallet "
                                              "timeout does not prove monerod is down; "
                                              "node cooldown not applied", number)
                    # Ensure the cache file has been released before requeue.
                    # On any uncertain wallet-RPC state, restart the process.
                    uncertain_wallet_state = not rpc.open_wallet
                    try:
                        await rpc.close_current()
                    except Exception as close_exc:
                        TerminalColor.error("WORKER %d close_wallet failed: %s", number, close_exc)
                        await rpc.stop()
                        rpc = None
                    if (isinstance(exc, RPCTransportError) or uncertain_wallet_state) and rpc is not None:
                        await rpc.stop()
                        rpc = None
                    preferred = None  # retries should favor other healthy nodes
                    transient_watch_failure = (args.watch_transfers and
                                               (is_node_related_failure(exc) or
                                                isinstance(exc, WalletRPCTransportError)))
                    if transient_watch_failure:
                        queue.put_nowait(job)
                        TerminalColor.warning("WATCH requeued line %d after transient disconnect; "
                                              "continuing to monitor after node recovery", job.line)
                    elif job.retries < args.retries:
                        job.retries += 1
                        queue.put_nowait(job)
                        TerminalColor.info("Requeued line %d (retry %d/%d)",
                                           job.line, job.retries, args.retries)
                    else:
                        results.add({
                            "line": job.line, "address": job.address,
                            "supplied_address": job.supplied_address or "",
                            "address_mismatch": job.address_mismatch,
                            "key_recovery": job.key_recovery,
                            "rpc": node.url, "status": "ERROR", "error": str(exc)})
                        if is_permanent_mnemonic_error(job, exc):
                            invalid_lines = args.error_key_line_numbers
                            if job.line not in invalid_lines:
                                invalid_lines.add(job.line)
                                write_error_keys(args.keys, [{"line": number}
                                                             for number in invalid_lines],
                                                 args.error_keys_path)
                                refresh_corrected_export_after_mnemonic_rejection(args)
                                TerminalColor.warning(
                                    "Line %d: permanently rejected mnemonic saved to data/.error_keys",
                                    job.line)
                finally:
                    queue.task_done()
            finally:
                await pool.release(node)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        TerminalColor.exception("Worker %d stopped unexpectedly: %s", number, exc)
    finally:
        if rpc is not None:
            await rpc.stop()


def restore_height_metadata_path(cache: Path, job: WalletJob) -> Path:
    if not re.fullmatch(r"xmr_[0-9a-f]{40}", job.name):
        raise ValueError("Unsafe wallet cache basename")
    return cache / (job.name + ".restore-height.json")


def write_restore_height_metadata(cache: Path, job: WalletJob, height: int,
                                  network: str) -> None:
    """Record height known at wallet creation, NOT the current synced height.

    Monero wallet-RPC doesn't expose a get_restore_height method. Do not infer
    restore height from get_height: that is the *current* chain scan cursor.
    """
    dest = restore_height_metadata_path(cache, job)
    if dest.is_symlink():
        raise ValueError(f"Refusing symlinked restore-height metadata: {dest}")
    record = {"schema": 1, "address": job.address, "network": network,
              "restore_height": int(height),
              "recorded_utc": datetime.now(timezone.utc).isoformat()}
    fd, tmp = tempfile.mkstemp(prefix=".restore-height-", dir=cache)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(record, fp, separators=(",", ":"))
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def cached_restore_height(cache: Path, job: WalletJob, network: str) -> int | None:
    """Return proven wallet-creation height from scanner metadata or None.

    Imported/old caches without metadata are UNKNOWN, not silently assumed to
    have restore height 0. A .keys file does not expose this through wallet-RPC.
    """
    path = restore_height_metadata_path(cache, job)
    if path.is_symlink():
        raise ValueError(f"Refusing symlinked restore-height metadata: {path}")
    if not path.exists():
        return None
    item = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(item, dict) or item.get("schema") != 1 or
            item.get("network") != network or
            (job.address and item.get("address") != job.address) or
            type(item.get("restore_height")) is not int or item["restore_height"] < 0):
        raise ValueError(f"Invalid restore-height metadata: {path}")
    return item["restore_height"]


def rebuild_caches_if_lower(cache: Path, jobs: list[WalletJob],
                            height: int, network: str,
                            rebuild_unknown: bool) -> list[WalletJob]:
    """Archive and return caches whose known original restore height is too high.

    Unknown imported caches require explicit --rebuild-unknown-height, which
    prevents accidentally treating the wallet's sync cursor as restore height.
    """
    to_rebuild: list[WalletJob] = []
    for job in jobs:
        wallet = cache / job.name
        keys = cache / (job.name + ".keys")
        for f in (wallet, keys):
            if f.is_symlink():
                raise ValueError(f"Refusing symlinked wallet cache: {f}")
        if not wallet.exists() and not keys.exists():
            continue
        if wallet.exists() != keys.exists():
            raise ValueError(f"Partial wallet cache for line {job.line}; "
                             "restore backup or repair before rebuilding")
        original = cached_restore_height(cache, job, network)
        if original is None:
            if rebuild_unknown:
                TerminalColor.warning("Line %d: cached restore height UNKNOWN; "
                                      "--rebuild-unknown-height requested, archiving cache",
                                      job.line)
                to_rebuild.append(job)
            else:
                TerminalColor.warning("Line %d: cached restore height UNKNOWN; "
                                      "not rebuilding. Use --rebuild-unknown-height to archive "
                                      "and recreate this wallet at height %d", job.line, height)
        elif original > height:
            TerminalColor.info("Line %d: cached restore height %d > requested %d; rebuilding",
                               job.line, original, height)
            to_rebuild.append(job)
        else:
            TerminalColor.info("Line %d: cached restore height %d <= requested %d; keeping cache",
                               job.line, original, height)
    if to_rebuild:
        rebuild_selected_wallet_caches(cache, to_rebuild, height)
    return to_rebuild


def rebuild_selected_wallet_caches(cache: Path, jobs: list[WalletJob],
                                   restore_height: int) -> Path | None:
    """Archive ONLY selected wallet caches; the normal restore path recreates them.

    This runs once before any local wallet-RPC processes are spawned, not once
    per worker or per retry. The original files are moved into a private backup
    directory. Never alter the wallet password, journals, watcher ledgers,
    unrelated wallet caches, or RPC logs.

    The selected wallets must be closed by any OTHER scanner before invoking
    this operation; an existing wallet-RPC process cannot be safely evicted.
    """
    if not jobs:
        return None
    cache = cache.resolve(strict=True)
    selected: list[tuple[WalletJob, list[Path]]] = []
    for job in jobs:
        if not re.fullmatch(r"xmr_[0-9a-f]{40}", job.name):
            raise ValueError(f"Unsafe wallet cache basename for line {job.line}")
        files = [cache / (job.name + suffix)
                 for suffix in ("", ".keys", ".subaddress-lookahead.json", ".restore-height.json")]
        present = []
        for path in files:
            # is_symlink catches dangling links as well as links to files.
            if path.is_symlink():
                raise ValueError(f"Refusing cache rebuild: symlink {path}")
            if path.exists():
                if not path.is_file() or path.parent != cache:
                    raise ValueError(f"Refusing cache rebuild: unexpected file type {path}")
                present.append(path)
        if present:
            selected.append((job, present))
    if not selected:
        TerminalColor.info("--rebuild-cache: no existing wallet cache files for %d selected wallet(s); "
                           "new wallets will be generated at restore height %d", len(jobs), restore_height)
        return None

    # File moves within the same filesystem avoid copying private-key material
    # unnecessarily, and preserve the originals if restoration later fails.
    root = cache / ".restore_height_backups"
    if root.is_symlink():
        raise ValueError(f"Refusing symlinked backup directory: {root}")
    root.mkdir(mode=0o700, exist_ok=True)
    if os.name == "posix":
        root.chmod(0o700)
    backup = Path(tempfile.mkdtemp(prefix=f"height-{restore_height}-", dir=root))
    if os.name == "posix":
        backup.chmod(0o700)

    moved: list[tuple[Path, Path]] = []
    try:
        # Each filename is unique across selected jobs; no replacement of an
        # existing backup is permitted. Roll back any ordinary move failure.
        for job, files in selected:
            for original in files:
                archived = backup / original.name
                if archived.exists() or archived.is_symlink():
                    raise ValueError(f"Backup collision: {archived}")
                original.rename(archived)
                moved.append((original, archived))
        manifest = {
            "restore_height": restore_height,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "wallets": [{"line": job.line, "name": job.name,
                         "files": [f.name for f in files]} for job, files in selected],
        }
        manifest_path = backup / "manifest.json"
        with manifest_path.open("x", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            manifest_path.chmod(0o600)
    except Exception:
        for original, archived in reversed(moved):
            if archived.exists() and not original.exists():
                archived.rename(original)
        try:
            backup.rmdir()
        except OSError:
            pass
        raise
    TerminalColor.warning("REBUILD CACHE: archived %d selected wallet(s), %d file(s) at %s. "
                          "They will be recreated using --restore-height %d; saved journals "
                          "and unrelated caches were not changed.",
                          len(selected), len(moved), backup, restore_height)
    return backup


async def recreate_wallets_offline(args: argparse.Namespace,
                                   cache: Path, jobs: list[WalletJob],
                                   password: str) -> int:
    """Recreate selected wallets offline without scanning blocks.

    Used after the backup-first height comparison in --validate-only mode.
    If one restore fails the archived original is kept, not silently deleted.
    """
    if not jobs:
        return 0
    offline = Node("http://127.0.0.1:18081", "127.0.0.1", 18081,
                   "http", 0, frozenset(("127.0.0.1",)))
    args.rebuild_offline_only = True
    failures = 0
    rpc: WalletRPC | None = None
    try:
        for number, job in enumerate(jobs, 1):
            try:
                if rpc is None:
                    rpc = WalletRPC(1, offline, args, cache, password)
                    await rpc.start()
                await rpc.close_current()
                if job.mnemonic is not None:
                    params = {"restore_height": args.restore_height,
                              "filename": job.name, "seed": job.mnemonic,
                              "password": password, "autosave_current": True}
                    if args.mnemonic_language:
                        params["language"] = args.mnemonic_language
                    if args.seed_offset_value:
                        params["seed_offset"] = args.seed_offset_value
                    result = await rpc.call_with_progress("restore_deterministic_wallet", params)
                    rpc.open_wallet = True
                    rpc.use_restored_address(job, result.get("address"))
                    write_restore_height_metadata(cache, job, args.restore_height, args.network)
                else:
                    await rpc.generate_key_wallet(job)
                actual = await rpc.call("get_address", {"account_index": 0},
                                        timeout_seconds=args.wallet_control_timeout)
                if job.address and actual.get("address") != job.address:
                    raise RPCError("Offline recreation returned unexpected primary address")
                await rpc.close_current()
                TerminalColor.good("Offline recreated line %d cache at restore height %d "
                                   "(no blockchain scan)", job.line, args.restore_height)
            except Exception as exc:
                failures += 1
                TerminalColor.error("Offline cache recreation failed on line %d: %s. "
                                    "Original wallet retained in restore-height backups",
                                    job.line, exc)
                if rpc is not None:
                    await rpc.stop()
                    rpc = None
    finally:
        args.rebuild_offline_only = False
        if rpc is not None:
            await rpc.stop()
    return failures


async def migrate_cached_wallet_passwords(args: argparse.Namespace) -> int:
    """Re-encrypt ALL xmr_* cached wallets offline using the target cache password.

    Explicit standalone operation. Does not need --keys, --rpcs or any daemon.
    Each wallet is backed up, migrated, closed and reopened with target password.
    Never overwrites an existing .wallet-password with a different value.
    """
    cache = args.cache_dir.expanduser().resolve()
    if not cache.is_dir():
        raise ValueError(f"Wallet cache directory does not exist: {cache}")
    if cache.is_symlink():
        raise ValueError("Refusing symlinked wallet cache directory")
    old_password = (read_secret_file(args.old_cache_password_file)
                    if args.old_cache_password_file else "")
    if args.old_cache_password_file and not old_password:
        raise ValueError("Old wallet password file must contain a nonempty password")
    # The password list is tried first, in the exact order supplied by the user.
    # The previous single-password option is appended as a fallback.
    args.cache_password_candidates = tuple(args.cache_password_candidates) + (
        (old_password,) if old_password else ())
    pw_path = cache / ".wallet-password"
    if pw_path.is_symlink():
        raise ValueError("Refusing symlinked .wallet-password")
    supplied_target = (read_secret_file(args.new_cache_password_file)
                       if args.new_cache_password_file else None)
    present_target = (pw_path.read_text(encoding="utf-8").rstrip("\r\n")
                      if pw_path.is_file() else None)
    target = supplied_target or present_target
    replace_target_file = bool(supplied_target and present_target and
                               supplied_target != present_target)
    if replace_target_file:
        TerminalColor.warning("Existing .wallet-password differs from requested target; "
                              "it will be backed up and replaced ONLY after EVERY wallet "
                              "successfully opens with the new password")
    if not target:
        raise ValueError("No target password: provide --new-cache-password-file "
                         "or an existing cache/.wallet-password")
    if old_password and target == old_password and not args.cache_password_list:
        TerminalColor.warning("Old and target passwords are identical; wallets will be verified only")
    names = sorted(f.stem for f in cache.glob("xmr_*.keys")
                   if re.fullmatch(r"xmr_[0-9a-f]{40}", f.stem))
    if not names:
        TerminalColor.warning("No xmr_*.keys files found in %s", cache)
        return 0
    backup_root = cache / ".password_migration_backups"
    if backup_root.is_symlink():
        raise ValueError("Refusing symlinked password backup directory")
    backup_root.mkdir(mode=0o700, exist_ok=True)
    if os.name == "posix":
        backup_root.chmod(0o700)
    backup = Path(tempfile.mkdtemp(prefix="migration-", dir=backup_root))
    if os.name == "posix":
        backup.chmod(0o700)
    # Keep processes isolated and sequential to prevent a concurrent wallet
    # RPC from touching caches while key-file encryption is changing.
    offline = Node("http://127.0.0.1:18081", "127.0.0.1", 18081,
                   "http", 0, frozenset(("127.0.0.1",)))
    successes = failures = already = 0
    for i, name in enumerate(names, 1):
        wallet = cache / name
        keyfile = cache / (name + ".keys")
        if any(f.is_symlink() or not f.is_file() for f in (wallet, keyfile)):
            TerminalColor.error("Password migration %s: incomplete/unsafe cache pair", name)
            failures += 1
            continue
        rpc = WalletRPC(i, offline, args, cache, target)
        try:
            for source in (wallet, keyfile):
                dest = backup / source.name
                with source.open("rb") as reader, dest.open("xb") as writer:
                    shutil.copyfileobj(reader, writer)
                    writer.flush()
                    os.fsync(writer.fileno())
                if os.name == "posix":
                    dest.chmod(0o600)
            await rpc.start()
            # Recover the encrypted wallet with a candidate from the list (or
            # the older single-password option), then migrate only if needed.
            matched_password = await rpc.open_cached_wallet(name)
            if matched_password == target:
                already += 1
                TerminalColor.info("Password migration %s: already uses target password", name)
            else:
                await rpc.call("change_wallet_password", {
                    "old_password": matched_password, "new_password": target},
                               timeout_seconds=args.wallet_control_timeout)
                await rpc.call("store", timeout_seconds=args.wallet_control_timeout)
                await rpc.close_current()
                # Verify actual readability after modifying wallet encryption.
                await rpc.call("open_wallet", {"filename": name, "password": target},
                               timeout_seconds=args.wallet_control_timeout)
                rpc.open_wallet = True
                TerminalColor.good("Password migrated and verified: %s", name)
                successes += 1
            await rpc.close_current()
        except Exception as exc:
            TerminalColor.error("Password migration failed for %s: %s; "
                                "original encrypted backup is in %s", name, exc, backup)
            failures += 1
        finally:
            await rpc.stop()
    # Never silently replace an existing target secret. A new .wallet-password
    # is created only when *every* cached wallet was verified with target.
    if failures == 0 and (not pw_path.exists() or replace_target_file):
        if replace_target_file:
            old_backup = backup / ".wallet-password.previous"
            with pw_path.open("rb") as reader, old_backup.open("xb") as writer:
                shutil.copyfileobj(reader, writer)
                writer.flush()
                os.fsync(writer.fileno())
            if os.name == "posix":
                old_backup.chmod(0o600)
        fd, temp_name = tempfile.mkstemp(prefix=".wallet-password-", dir=cache)
        try:
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(target + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, pw_path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
    TerminalColor.info("Password migration: changed=%d already-target=%d failed=%d "
                       "backups=%s", successes, already, failures, backup)
    return 1 if failures else 0


def read_cache_password_list(path: Path | None) -> tuple[str, ...]:
    """Read candidate encryption passwords, one per line, preserving spaces.

    Empty lines are ignored, but all other characters (including # and spaces)
    are literal password characters. Remove only line endings. Never log values.
    """
    if path is None:
        return ()
    path = path.expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"Cache password list not found: {path}")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Cache password list exceeds 1 MiB")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        TerminalColor.warning("Cache password list %s is accessible to other users; "
                              "recommend chmod 600", path)
    candidates = []
    seen = set()
    for value in path.read_text(encoding="utf-8-sig").splitlines():
        if value and value not in seen:
            seen.add(value)
            candidates.append(value)
    if not candidates:
        raise ValueError(f"No nonempty passwords found in {path}")
    if len(candidates) > 10000:
        raise ValueError("Cache password list contains more than 10000 unique passwords")
    return tuple(candidates)


def cache_password(cache: Path) -> str:
    path = cache / ".wallet-password"
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError("Cache password file is empty")
        return value
    value = secrets.token_urlsafe(48)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value + "\n")
    return value


def create_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scan Monero balances with multiple adaptive wallet workers per remote daemon")
    p.add_argument("--data-dir", type=Path, default=Path("data"),
                   help="Root directory for generated reports, journals, recovery files and "
                        "wallet caches (default: data). Relative output paths are placed here")
    p.add_argument("--keys", type=Path,
                   help="Key pairs, 16-word Polyseed, Monero legacy, or BIP39 phrases, one per line")
    p.add_argument("--key-format", choices=("auto", "address-view-spend", "address-spend", "view-spend",
                                            "mnemonic", "address-mnemonic"),
                   default="auto", help="Input format; default auto-detect")
    p.add_argument("--mnemonic-language", default=None,
                   help="Optional Monero seed language override (e.g. English)")
    p.add_argument("--mnemonic-format", choices=("auto", "polyseed", "legacy", "mymonero", "bip39"),
                   default="auto", help="Auto: validate BIP39 checksum and Monero wordlists; "
                                        "explicit per-line prefixes override detection")
    p.add_argument("--bip39-scheme", choices=("auto", "cake", "ledger", "trezor"),
                   default="auto", help="Auto: match Cake/Ledger/Trezor using supplied address; "
                                        "without an address default to Cake")
    p.add_argument("--bip39-account", type=int, default=0,
                   help="BIP39 derivation account index (default 0)")
    p.add_argument("--bip39-passphrase-file", type=Path,
                   help="Optional BIP39 passphrase read locally from file; not printed/logged")
    p.add_argument("--seed-offset-file", type=Path,
                   help="Optional Monero legacy/Polyseed seed-offset passphrase read from file")
    p.add_argument("--watch-transfers", action="store_true",
                   help="Keep selected wallets open; use --tx-notify and periodic transaction reconciliation")
    p.add_argument("--watch-auto-sweep", action="store_true",
                   help="Automatically sweep newly unlocked wallet outputs during watch mode; "
                        "requires --watch-transfers, --sweep-to and --execute-sweeps")
    p.add_argument("--watch-sweep-journal", type=Path,
                   default=Path(".xmr_watch_sweep_journal.jsonl"),
                   help="Durable journal of unlocked-output sweep attempts during watch mode")
    p.add_argument("--watch-lines", type=str,
                   help="Optional keys.lst line selection, e.g. 561-566; for dedicated long-lived watchers")
    p.add_argument("--watch-refresh-seconds", type=int, default=20,
                   help="Monero wallet auto_refresh period during watch mode (default 20)")
    p.add_argument("--watch-poll-seconds", type=float, default=60.0,
                   help="Reconcile wallet transactions even if tx-notify is missed (default 60s)")
    p.add_argument("--watch-check-seconds", type=float, default=2.0,
                   help="Check --tx-notify callback spool this often (default 2s)")
    p.add_argument("--sweep-to", type=str,
                   help="Consolidation destination; defaults to DRY RUN until --execute-sweeps is set")
    p.add_argument("--execute-sweeps", action="store_true",
                   help="Actually broadcast sweep_all transactions to --sweep-to (irreversible)")
    p.add_argument("--sweep-priority", type=int, choices=(0, 1, 2, 3, 4), default=0,
                   help="Transaction priority 0-4 (default 0)")
    p.add_argument("--sweep-journal", type=Path, default=Path(".xmr_sweep_journal.jsonl"),
                   help="Append-only sweep journal; existing INTENTs prevent automatic resubmissions")
    p.add_argument("--advanced-key-recovery", action="store_true",
                   help="Cross-match all input addresses and exhaustively test small spend-key hex gaps")
    p.add_argument("--advanced-max-missing-nibbles", type=int, default=2,
                   help="Max missing hex digits to attempt (default 2; 3 is very expensive)")
    p.add_argument("--advanced-max-candidates", type=int, default=750000,
                   help="Per-invalid-key search budget (default 750000; two missing digits covered)")
    p.add_argument("--advanced-progress-every", type=int, default=50000,
                   help="Log advanced recovery progress every N candidates (0 disables progress)")
    p.add_argument("--advanced-recovery-output", type=Path,
                   help="Verified recovered key pairs (default data/.recovered_keys)")
    p.add_argument("--crossmatch-output", type=Path,
                   help="Address cross-reference report (default data/.key_crossmatches.csv)")
    p.add_argument("--corrected-keys-output", type=Path, nargs="?",
                   const=Path(".corrected_keys"), metavar="PATH",
                   help="Export corrected scanner-ready key list (default data/.corrected_keys); leaves unrecoverable lines in .error_keys")
    p.add_argument("--fixed-keys-output", type=Path, nargs="?",
                   const=Path(".fixed_keys"), metavar="PATH",
                   help="Export ONLY repaired key pairs and corrected mismatched primary "
                        "addresses (default data/.fixed_keys); omit unchanged "
                        "valid keys, unchanged mnemonic lines and comments")
    p.add_argument("--no-key-recovery", action="store_true",
                   help="Disable private spend-key repairs and invalid private view-key fallback")
    p.add_argument("--validate-only", action="store_true",
                   help="Validate input and derive addresses offline; repair candidates need verification")
    p.add_argument("--verify-addresses-only", action="store_true",
                   help="Offline verification of supplied primary/subaddresses using wallet RPC; "
                        "no blockchain synchronization, balance checks or transfers")
    p.add_argument("--verify-output", type=Path,
                   default=Path("xmr_address_verification.csv"),
                   help="CSV report for --verify-addresses-only (default xmr_address_verification.csv)")
    p.add_argument("--rpcs", type=Path, help="Remote daemon HTTP(S) URLs, one per line")
    p.add_argument("--output", type=Path, default=Path("xmr_balances.csv"))
    p.add_argument("--transactions-output", type=Path, default=Path("xmr_transactions.csv"),
                   help="CSV transaction-history export (default: xmr_transactions.csv)")
    p.add_argument("--no-transactions", action="store_true",
                   help="Disable transaction-history RPC calls and CSV export")
    p.add_argument("--cache-dir", type=Path, default=Path(".xmr_wallet_cache"))
    p.add_argument("--wallet-rpc-bin", default="monero-wallet-rpc")
    p.add_argument("--restore-height", type=int, default=0,
                   help="Earliest block to scan; 0 scans from genesis (default: 0)")
    p.add_argument("--rebuild-cache", action="store_true",
                   help="Archive selected cached wallet files, then recreate them using "
                        "--restore-height. Does not remove passwords, journals, or other wallets")
    p.add_argument("--rebuild-if-lower", action="store_true",
                   help="Rebuild selected cached wallets only when their recorded original "
                        "restore height is GREATER than --restore-height")
    p.add_argument("--rebuild-unknown-height", action="store_true",
                   help="With --rebuild-if-lower, also rebuild older/imported caches "
                        "whose original restore height cannot be verified")
    p.add_argument("--migrate-cache-passwords", action="store_true",
                   help="Offline-only: back up and change the passwords of ALL xmr_* cached "
                        "wallets to the cache's common target password, then verify reopening")
    p.add_argument("--cache-password-list", type=Path, metavar="FILE",
                   help="Try candidate cached-wallet passwords in FILE order (one per line). "
                        "Falls back to cache/.wallet-password; never changes encryption "
                        "unless --migrate-cache-passwords is also specified")
    p.add_argument("--old-cache-password-file", type=Path,
                   help="Text file containing the password used by imported cached wallets")
    p.add_argument("--new-cache-password-file", type=Path,
                   help="Optional target password; must match cache/.wallet-password if present")
    p.add_argument("--subaddress-lookahead", type=parse_subaddress_lookahead,
                   default=(50, 200), metavar="ACCOUNTS:SUBADDRESSES",
                   help="Initial subaddress discovery window (default 50:200). "
                        "For unknown higher indices consider 50:1000, at additional CPU/RAM cost")
    p.add_argument("--subaddress-search-limit", type=parse_subaddress_lookahead,
                   default=(50, 3200), metavar="ACCOUNTS:SUBADDRESSES",
                   help="Max lookahead when automatically resolving supplied subaddresses "
                        "outside the ordinary gap (default 50:3200). "
                        "Cannot prove non-ownership beyond this window")
    p.add_argument("--network", choices=tuple(NETWORK_PREFIX), default="mainnet")
    p.add_argument("--max-node-lag", type=int, default=20,
                   help="Exclude nodes more than this many blocks behind best node (default: 20)")
    p.add_argument("--probe-timeout", type=float, default=15.0)
    p.add_argument("--startup-timeout", type=float, default=40.0)
    p.add_argument("--wallet-control-timeout", type=float, default=180.0,
                   help="Timeout for short wallet-RPC commands; refresh itself has no overall timeout")
    p.add_argument("--progress-interval", type=float, default=60.0,
                   help="Log elapsed time this often during long wallet-RPC restore/refresh calls")
    p.add_argument("--retries", type=int, default=2,
                   help="Number of additional wallet attempts after the first failure")
    p.add_argument("--workers-per-rpc", type=int, default=4,
                   help="Maximum simultaneous wallet scans per remote daemon (default: 4)")
    p.add_argument("--max-total-workers", type=int, default=32,
                   help="Maximum local wallet-RPC processes overall (default: 32)")
    p.add_argument("--node-failure-threshold", type=int, default=2,
                   help="Node-related failures before temporary disable (default: 2)")
    p.add_argument("--node-cooldown", type=float, default=45,
                   help="Seconds to pause a repeatedly failing node (default: 45)")
    p.add_argument("--node-recovery-successes", type=int, default=3,
                   help="Successful scans per additional recovery slot; health probes also "
                        "restore slots without waiting for wallet completions (default: 3)")
    p.add_argument("--node-recovery-ramp-seconds", type=float, default=5.0,
                   help="Seconds between independent health-checked capacity increases "
                        "after RPC recovery (default: 5; 0 restores full capacity immediately)")
    p.add_argument("--worker-start-retries", type=int, default=3,
                   help="Maximum startup failures per worker (default: 3)")
    p.add_argument("--daemon-ssl-ca-certificates", type=Path,
                   help="PEM CA bundle for HTTPS daemons (auto-detect system CA bundle by default)")
    p.add_argument("--daemon-ssl-allow-any-cert", action="store_true",
                   help="Accept unverified TLS certificates from HTTPS daemons (explicit opt-in)")
    p.add_argument("--wallet-threads", type=int, default=2,
                   help="Maximum internal worker threads per monero-wallet-rpc process")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
    configure_output_paths(args)
    validate_output_collisions(args, p)
    if args.migrate_cache_passwords:
        if not (args.old_cache_password_file or args.cache_password_list):
            p.error("--migrate-cache-passwords requires --old-cache-password-file "
                    "and/or --cache-password-list")
        if args.rebuild_if_lower or args.rebuild_cache or args.validate_only or args.verify_addresses_only or args.watch_transfers or args.execute_sweeps:
            p.error("Password migration is standalone; run scanning/validation/rebuilding separately")
    elif args.keys is None:
        p.error("--keys is required unless --migrate-cache-passwords is set")
    if args.rebuild_if_lower and args.rebuild_cache:
        p.error("Choose --rebuild-if-lower OR --rebuild-cache, not both")
    if args.rebuild_unknown_height and not args.rebuild_if_lower:
        p.error("--rebuild-unknown-height requires --rebuild-if-lower")
    if args.rebuild_if_lower:
        if not any(a == "--restore-height" or a.startswith("--restore-height=")
                   for a in sys.argv[1:]):
            p.error("--rebuild-if-lower requires explicit --restore-height")
    if args.advanced_key_recovery:
        if not 1 <= args.advanced_max_missing_nibbles <= 3:
            p.error("--advanced-max-missing-nibbles must be 1, 2 or 3")
        if args.advanced_max_candidates <= 0 or args.advanced_progress_every < 0:
            p.error("Advanced recovery candidate budget must be positive and progress interval nonnegative")
    if args.no_key_recovery and args.advanced_key_recovery:
        p.error("--advanced-key-recovery cannot be combined with --no-key-recovery")
    if args.rebuild_cache:
        if args.validate_only:
            p.error("--rebuild-cache cannot be used with --validate-only (no wallets are opened)")
        if not any(a == "--restore-height" or a.startswith("--restore-height=")
                   for a in sys.argv[1:]):
            p.error("--rebuild-cache requires an explicit --restore-height N (including 0)")
    if args.verify_addresses_only and (args.validate_only or args.watch_transfers or
                                       args.watch_auto_sweep or args.execute_sweeps or
                                       args.sweep_to or args.watch_lines):
        p.error("--verify-addresses-only cannot be combined with validation, "
                "watch, sweep, or watch-lines options")
    if args.verify_addresses_only:
        report_path = args.verify_output.expanduser().resolve()
        for name, path in (("--keys", args.keys), ("--rpcs", args.rpcs),
                           ("--output", args.output),
                           ("--transactions-output", args.transactions_output),
                           ("--sweep-journal", args.sweep_journal),
                           ("--watch-sweep-journal", args.watch_sweep_journal)):
            if path is not None and report_path == path.expanduser().resolve():
                p.error(f"--verify-output must differ from {name}")
        if report_path == args.error_keys_path:
            p.error("--verify-output must not overwrite .error_keys")
    if args.execute_sweeps and not args.sweep_to:
        p.error("--execute-sweeps requires --sweep-to")
    if args.watch_auto_sweep and not (args.watch_transfers and args.execute_sweeps and args.sweep_to):
        p.error("--watch-auto-sweep requires --watch-transfers, --sweep-to and --execute-sweeps")
    if args.watch_transfers and args.execute_sweeps and not args.watch_auto_sweep:
        p.error("--execute-sweeps in watch mode requires --watch-auto-sweep")
    if args.watch_lines and not args.watch_transfers:
        p.error("--watch-lines requires --watch-transfers")
    if args.watch_refresh_seconds < 1 or args.watch_poll_seconds <= 0 or args.watch_check_seconds <= 0:
        p.error("Watch intervals must be positive")
    if args.sweep_to:
        try:
            args.sweep_to = validate_sweep_address(args.sweep_to, args.network)
        except ValueError as _exc:
            p.error(str(_exc))
    if not 0 <= args.bip39_account < 2 ** 31:
        p.error("--bip39-account must be between 0 and 2147483647")
    try:
        args.bip39_passphrase_value = read_secret_file(args.bip39_passphrase_file)
        args.seed_offset_value = read_secret_file(args.seed_offset_file)
    except (OSError, ValueError) as _exc:
        p.error(str(_exc))
    if (args.subaddress_search_limit[0] < args.subaddress_lookahead[0] or
            args.subaddress_search_limit[1] < args.subaddress_lookahead[1]):
        p.error("--subaddress-search-limit must cover --subaddress-lookahead")
    if args.restore_height < 0 or args.max_node_lag < 0 or args.retries < 0:
        p.error("--restore-height, --max-node-lag and --retries must be nonnegative")
    if any(getattr(args, option) < 1 for option in
           ("wallet_threads", "workers_per_rpc", "max_total_workers",
            "node_failure_threshold", "node_recovery_successes", "worker_start_retries")):
        p.error("Worker counts, failure thresholds and recovery successes must be positive")
    if args.node_cooldown <= 0:
        p.error("--node-cooldown must be positive")
    if not 0 <= args.node_recovery_ramp_seconds < float("inf"):
        p.error("--node-recovery-ramp-seconds must be a finite nonnegative number")
    if (args.probe_timeout <= 0 or args.startup_timeout <= 0 or
            args.wallet_control_timeout <= 0 or args.progress_interval <= 0):
        p.error("Timeout and progress interval values must be positive")
    if not args.no_transactions:
        tx_path = args.transactions_output.expanduser().resolve()
        for name, other in (("--output", args.output), ("--keys", args.keys),
                            ("--rpcs", args.rpcs), ("--sweep-journal", args.sweep_journal)):
            if other is not None and tx_path == other.expanduser().resolve():
                p.error(f"--transactions-output must differ from {name}")
    if args.daemon_ssl_allow_any_cert and args.daemon_ssl_ca_certificates is not None:
        p.error("Choose either --daemon-ssl-ca-certificates or --daemon-ssl-allow-any-cert")
    if args.daemon_ssl_ca_certificates is not None:
        try:
            daemon_ca_bundle(args)
        except ValueError as _exc:
            p.error(str(_exc))
    return args


async def run(args: argparse.Namespace) -> int:
    # Secrets are loaded only in memory and kept out of diagnostic output.
    args.cache_password_candidates = read_cache_password_list(args.cache_password_list)
    if args.migrate_cache_passwords:
        return await migrate_cached_wallet_passwords(args)
    corrected_path = corrected_output_path(args)
    fixed_path = fixed_keys_output_path(args)
    if corrected_path is not None and corrected_path == fixed_path:
        raise ValueError('--corrected-keys-output and --fixed-keys-output '
                         'must point to different files')
    any_key_export = corrected_path is not None or fixed_path is not None
    duplicate_jobs: list[WalletJob] = []
    jobs, invalid = load_wallets(
        args.keys, args.network, args.key_format,
        recover_keys=not args.no_key_recovery,
        mnemonic_format=args.mnemonic_format,
        bip39_passphrase=args.bip39_passphrase_value,
        bip39_account=args.bip39_account,
        bip39_scheme=args.bip39_scheme,
        seed_offset=args.seed_offset_value,
        duplicate_jobs=duplicate_jobs if any_key_export else None)
    if args.advanced_key_recovery:
        base = args.data_dir
        recovered_path = (args.advanced_recovery_output or base / ".recovered_keys").expanduser().resolve()
        crossmatch_path = (args.crossmatch_output or base / ".key_crossmatches.csv").expanduser().resolve()
        restricted = {args.keys.expanduser().resolve(), args.error_keys_path}
        if args.rpcs is not None:
            restricted.add(args.rpcs.expanduser().resolve())
        restricted.update(p.expanduser().resolve() for p in (args.output, args.transactions_output,
                                                             args.sweep_journal, args.watch_sweep_journal,
                                                             args.verify_output))
        if recovered_path in restricted or crossmatch_path in restricted or recovered_path == crossmatch_path:
            raise ValueError("Advanced recovery outputs must not overwrite key inputs, journals or CSV outputs")
        jobs, invalid, recovered = advanced_recover_file(
            args.keys, jobs, invalid, args.network,
            max_missing=args.advanced_max_missing_nibbles,
            max_candidates=args.advanced_max_candidates,
            progress_every=args.advanced_progress_every,
            duplicate_jobs=duplicate_jobs if any_key_export else None)
        atomic_private_text(recovered_path, [f"{job.address}:{job.view}:{job.spend}" for job in recovered])
        TerminalColor.info("Saved %d verified repaired key pair(s) to %s (private; mode 0600)",
                           len(recovered), recovered_path)
        write_crossmatches(crossmatch_path, args.keys, jobs)
    # Write rejected input lines before any RPC/network activity so the file
    # is also available in --validate-only mode and after a daemon failure.
    args.error_key_line_numbers = {int(row["line"]) for row in invalid}
    write_error_keys(args.keys, invalid, args.error_keys_path)
    if any_key_export:
        # Preserve verified repaired duplicate rows even when the scanner
        # intentionally schedules only one RPC scan for each distinct wallet.
        args.corrected_export_jobs = jobs + duplicate_jobs
        args.corrected_export_path = corrected_path
        args.fixed_export_path = fixed_path
        if corrected_path is not None:
            write_corrected_key_list(corrected_path, args.keys,
                                     args.corrected_export_jobs, invalid, args.network)
        if fixed_path is not None:
            write_corrected_key_list(fixed_path, args.keys,
                                     args.corrected_export_jobs, invalid,
                                     args.network, only_fixed=True)
    if args.watch_transfers:
        jobs = select_watch_lines(jobs, args.watch_lines)
        TerminalColor.info("Watch mode selected %d wallet(s); one wallet RPC process per wallet", len(jobs))
    if args.validate_only:
        if args.rebuild_if_lower and jobs:
            cache = args.cache_dir.expanduser().resolve()
            cache.mkdir(parents=True, exist_ok=True, mode=0o700)
            if shutil.which(args.wallet_rpc_bin) is None and not Path(args.wallet_rpc_bin).is_file():
                TerminalColor.error("--validate-only --rebuild-if-lower requires "
                                    "monero-wallet-rpc for offline wallet recreation: %s; "
                                    "caches unchanged", args.wallet_rpc_bin)
                return 2
            password = cache_password(cache)
            selected = rebuild_caches_if_lower(cache, jobs, args.restore_height,
                                               args.network, args.rebuild_unknown_height)
            if selected:
                failed = await recreate_wallets_offline(args, cache, selected, password)
                if failed:
                    TerminalColor.error("%d wallet cache(s) could not be recreated offline", failed)
                    return 2
            TerminalColor.info("--validate-only: %d cache(s) recreated offline; "
                               "wallets were NOT synchronized", len(selected))
        for row in invalid:
            TerminalColor.warning("Line %s INVALID: %s", row["line"], row["error"])
        TerminalColor.info("Validated %d unique wallet input(s); %d invalid entries", len(jobs), len(invalid))
        if any(job.mnemonic for job in jobs):
            TerminalColor.info("--validate-only verifies Polyseed checksums locally, validates "
                               "BIP39 checksums and disambiguates 12/24-word phrases where possible. "
                               "Monero RPC validates remaining legacy mnemonics at restoration")
        return 0 if jobs and not invalid else 1
    if args.verify_addresses_only:
        if shutil.which(args.wallet_rpc_bin) is None and not Path(args.wallet_rpc_bin).is_file():
            TerminalColor.error("Cannot find monero-wallet-rpc binary: %s", args.wallet_rpc_bin)
            return 2
        return await run_verification_only(args, jobs, invalid)
    if not args.rpcs:
        TerminalColor.error("--rpcs is required unless --validate-only is supplied")
        return 2
    if shutil.which(args.wallet_rpc_bin) is None and not Path(args.wallet_rpc_bin).is_file():
        TerminalColor.error("Cannot find monero-wallet-rpc binary: %s", args.wallet_rpc_bin)
        return 2
    endpoints = load_rpc_urls(args.rpcs)
    if not jobs and not invalid:
        TerminalColor.error("No wallet entries in %s", args.keys)
        return 2
    if not endpoints and jobs:
        TerminalColor.error("No valid remote daemon RPC endpoints in %s", args.rpcs)
        return 2
    TerminalColor.info("Loaded %d unique valid wallets, %d malformed lines, %d unique RPC URLs",
                       len(jobs), len(invalid), len(endpoints))
    if args.restore_height == 0:
        TerminalColor.warning("Restore height is 0: each uncached wallet must scan Monero history "
                              "from genesis. Initial wallet scans may take a very long time.")
    cache = args.cache_dir.expanduser().resolve()
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        cache.chmod(0o700)
    password = cache_password(cache)
    results = Results(args.output)
    transactions: TransactionResults | None = None
    if not args.no_transactions:
        transactions = TransactionResults(args.transactions_output.expanduser().resolve())
        TerminalColor.info("Transaction history enabled: %s (UTC dates)", args.transactions_output)
    sweep_journal: SweepJournal | None = None
    watch_sweep_journal: WatchSweepJournal | None = None
    if args.watch_auto_sweep:
        watch_sweep_journal = WatchSweepJournal(args.watch_sweep_journal.expanduser().resolve())
        TerminalColor.warning("WATCH AUTO SWEEP ENABLED: unlocked outputs in the selected wallets "
                              "will be transferred to %s; journal=%s",
                              args.sweep_to, args.watch_sweep_journal)
    elif args.execute_sweeps:
        sweep_journal = SweepJournal(args.sweep_journal.expanduser().resolve())
        TerminalColor.warning("LIVE SWEEP MODE ENABLED: unlocked outputs in each wallet account "
                              "will be sent to %s; journal=%s", args.sweep_to, args.sweep_journal)
    elif args.sweep_to:
        TerminalColor.warning("SWEEP DRY RUN: no transactions will be broadcast; "
                              "add --execute-sweeps to enable transfers to %s", args.sweep_to)
    args.sweep_journal_instance = sweep_journal
    args.watch_sweep_journal_instance = watch_sweep_journal
    workers_exhausted = False
    try:
        for row in invalid:
            results.add(row)
        if not jobs:
            return 1
        timeout = aiohttp.ClientTimeout(total=args.probe_timeout)
        connector = aiohttp.TCPConnector(ssl=daemon_probe_ssl(args))
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as daemon_session:
            nodes = await find_nodes(endpoints, args, daemon_session)
            if not nodes:
                TerminalColor.error("No healthy, sufficiently current %s remote RPC nodes found", args.network)
                for job in jobs:
                    results.add({"line": job.line, "address": job.address,
                                 "supplied_address": job.supplied_address or "",
                                 "address_mismatch": job.address_mismatch,
                                 "status": "ERROR", "error": "No working RPC nodes"})
                return 2
            total_workers = min(len(jobs), args.max_total_workers,
                                len(nodes) * args.workers_per_rpc)
            if args.watch_transfers and len(jobs) > total_workers:
                TerminalColor.error("Watch mode requires one dedicated RPC worker per wallet. "
                                    "Selected %d wallets, but current node/worker limits allow %d. "
                                    "Use --watch-lines to select a subset or increase both worker limits "
                                    "and host capacity.", len(jobs), total_workers)
                return 2
            if total_workers < 1:
                TerminalColor.error("No wallet workers configured: max_total_workers=%s, workers_per_rpc=%s",
                                    args.max_total_workers, args.workers_per_rpc)
                for job in jobs:
                    results.add({"line": job.line, "address": job.address,
                                 "supplied_address": job.supplied_address or "",
                                 "address_mismatch": job.address_mismatch,
                                 "status": "ERROR", "error": "No wallet workers configured"})
                return 2
            if args.rebuild_cache:
                rebuild_selected_wallet_caches(cache, jobs, args.restore_height)
            elif args.rebuild_if_lower:
                rebuild_caches_if_lower(cache, jobs, args.restore_height,
                                        args.network, args.rebuild_unknown_height)
            TerminalColor.info("Starting %d wallet workers across %d healthy remote nodes "
                               "(up to %d per node)", total_workers, len(nodes), args.workers_per_rpc)
            queue: asyncio.Queue[WalletJob] = asyncio.Queue()
            for job in jobs:
                queue.put_nowait(job)
            pool = NodePool(nodes, args)
            monitor = asyncio.create_task(pool.monitor(daemon_session), name="node-health-monitor")
            workers = {
                asyncio.create_task(scanner_worker(i, nodes[(i - 1) % len(nodes)], pool,
                                                   queue, results, daemon_session,
                                                   args, cache, password, transactions), name=f"worker-{i}")
                for i in range(1, total_workers + 1)
            }
            all_workers = set(workers)
            all_done = asyncio.create_task(queue.join(), name="queue-join")
            try:
                while True:
                    completed, _ = await asyncio.wait(workers | {all_done},
                                                      return_when=asyncio.FIRST_COMPLETED)
                    if all_done in completed:
                        break
                    finished_workers = workers & completed
                    for worker in finished_workers:
                        if worker.cancelled():
                            TerminalColor.error("Wallet worker %s was cancelled unexpectedly", worker.get_name())
                            continue
                        _exc = worker.exception()
                        if _exc is not None:
                            TerminalColor.error("Wallet worker %s crashed: %s", worker.get_name(), _exc,
                                                exc_info=(type(_exc), _exc, _exc.__traceback__))
                        else:
                            TerminalColor.warning("Wallet worker %s exited before the queue was complete",
                                                  worker.get_name())
                    workers.difference_update(finished_workers)
                    if not workers:
                        # Give queue.join() a scheduling turn in case the last
                        # worker has just called task_done() and exited.
                        await asyncio.wait({all_done}, timeout=0.1)
                        if all_done.done():
                            break
                        workers_exhausted = True
                        TerminalColor.error("All wallet-RPC workers stopped before queue completion")
                        while not queue.empty():
                            job = queue.get_nowait()
                            try:
                                results.add({"line": job.line, "address": job.address,
                                             "status": "ERROR", "error": "All workers stopped"})
                            finally:
                                queue.task_done()
                        # Do not await queue.join(): a crashed worker may have left
                        # a dequeued job without a corresponding task_done().
                        break
            finally:
                all_done.cancel()
                monitor.cancel()
                for worker in all_workers:
                    worker.cancel()
                await asyncio.gather(*all_workers, monitor, all_done, return_exceptions=True)
        TerminalColor.info("Complete: %d scanned, %d nonzero, %d errors/invalid. Balances CSV: %s",
                           results.success, results.nonzero, results.failures, args.output)
        if transactions is not None:
            TerminalColor.info("Exported %d transaction rows to %s", transactions.total_rows,
                               args.transactions_output)
        return 1 if results.failures or workers_exhausted else 0
    finally:
        results.close()
        if transactions is not None:
            transactions.close()
        if sweep_journal is not None:
            sweep_journal.close()
        if watch_sweep_journal is not None:
            watch_sweep_journal.close()


def main() -> int:
    args = create_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s",
                        datefmt="%H:%M:%S")
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        TerminalColor.warning("Interrupted. Partial CSV and saved wallet caches remain available.")
        return 130
    except (OSError, ValueError) as err:
        TerminalColor.error("%s", err)
        return 2


if __name__ == "__main__":

    if len(sys.argv) == 4 and sys.argv[1] == "--tx-notify-event":
        sys.exit(write_tx_notification(sys.argv[2], sys.argv[3]))
    sys.exit(main())
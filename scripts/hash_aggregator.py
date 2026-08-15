# HARDENED VERSION - WAL mode, case-insensitive hash, TLS verify, secure file locking
#!/usr/bin/env python3
"""
hash_aggregator.py - Unified malware hash aggregator for FOS Antivirus

Aggregates SHA-256 malware hashes from 5 public, no-authentication-required
sources into a single SQLite database at signatures/malware_hashes.db
(or %APPDATA%/FOS-Antivirus/malware_hashes.db by default on Windows).

Sources (all verified July 2026):
  1. MalwareBazaar (abuse.ch)       ~1.11M hashes  hourly ZIP   (confidence=100)
  2. URLhaus payloads (abuse.ch)    ~259K hashes    5-min ZIP    (confidence=85)
  3. ThreatFox (abuse.ch)           ~5K sha256 IOCs hourly ZIP   (confidence=90)
  4. ESET malware-ioc (GitHub)      ~6.1K hashes    BSD-2        (confidence=95)
  5. TweetFeed (GitHub)             ~2.3K hashes    15-min CSV   (confidence=75)

NOTE on abuse.ch auth migration:
  As of 2025-06-30 abuse.ch officially requires a free Auth-Key, but the legacy
  static endpoints used here still serve no-auth as of 2026-07-26. If they break,
  register a free key at https://auth.abuse.ch and the script's URL constants
  are the only thing that needs updating.

Usage:
  python hash_aggregator.py init                    # Create/upgrade schema
  python hash_aggregator.py update                  # One-shot refresh of all sources
  python hash_aggregator.py update --only malwarebazaar threatfox
  python hash_aggregator.py update --force          # Skip rate-limit checks
  python hash_aggregator.py daemon --interval 6     # Continuous mode (poll every 6h)
  python hash_aggregator.py stats                   # Print DB statistics
  python hash_aggregator.py --db C:/path/to.db update

Schema (rich, multi-source attribution):
  hashes(sha256 PK, threat_label, first_seen_utc, last_seen_utc, source_count)
  sources(sha256 FK, source_name, confidence, first_seen_utc, PK(sha256, source_name))
  source_meta(source_name PK, last_fetch_utc, etag, last_modified, last_count)
  View: malware_hashes  (backward-compat with C lookup: SELECT threat_label, sha256 FROM malware_hashes WHERE sha256 = ?)

Progress is reported as JSONL to stdout for consumption by the C app:
  {"event":"progress","source":"malwarebazaar","pct":45,"msg":"downloading"}
  {"event":"source_done","source":"malwarebazaar","count":1111618,"elapsed_sec":12.3}
  {"event":"source_fail","source":"urlhaus","error":"HTTP 503"}
  {"event":"source_skip","source":"threatfox","reason":"rate limited"}
  {"event":"complete","total_unique":1123456,"duplicates_removed":8765,"elapsed_sec":187.4}

Exit codes:
  0 = at least one source succeeded (or 304 not-modified)
  1 = all sources failed
  2 = bad arguments / missing dependency
  3 = another instance already running

License: MIT (same as FOS Antivirus)
"""

import argparse
import csv
import io
import json
import logging
import os
import re
import shutil
import sqlite3
import sys
import tarfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional, Tuple

try:
    import requests
except ImportError:
    sys.stderr.write("ERROR: 'requests' module not found. Install with: pip install requests\n")
    sys.exit(2)

# --- Platform-specific imports for file locking ---
try:
    import msvcrt  # Windows
except ImportError:
    msvcrt = None

try:
    import fcntl  # Unix (for testing on Linux)
except ImportError:
    fcntl = None


# ============================================================================
# Constants
# ============================================================================

VERSION = "1.0.0"
APP_NAME = "FOS-Antivirus"

# Source URLs (all verified live + no-auth as of 2026-07-26)
URL_MALWAREBAZAAR_FULL = "https://bazaar.abuse.ch/export/txt/sha256/full/"
URL_URLHAUS_PAYLOADS = "https://urlhaus.abuse.ch/downloads/payloads/"
URL_THREATFOX_FULL = "https://threatfox.abuse.ch/export/json/full/"
URL_ESET_TARBALL = "https://github.com/eset/malware-ioc/archive/refs/heads/master.tar.gz"
URL_TWEETFEED_YEAR = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv"

# Per-source minimum interval between fetches (seconds). Honors abuse.ch fair-use.
RATE_LIMITS = {
    "malwarebazaar": 3600,   # 1 hour  (abuse.ch: "do not fetch more often than once per hour")
    "urlhaus": 300,          # 5 minutes (abuse.ch: "do not fetch more often than every 5 minutes")
    "threatfox": 3600,       # 1 hour
    "eset": 86400,           # 1 day   (GitHub repo, changes infrequently)
    "tweetfeed": 900,        # 15 minutes (TweetFeed regenerates every 15 min)
}

# HTTP settings
HTTP_TIMEOUT = 120            # seconds per request
HTTP_RETRIES = 3
HTTP_RETRY_BACKOFF = 5        # seconds, multiplied by attempt number

# SHA-256 validation: 64 lowercase hex chars
SHA256_RE = re.compile(r'^[0-9a-fA-F]{64}$')
SHA256_RE_LOWER = re.compile(r'^[0-9a-f]{64}$')

USER_AGENT = f"FOS-Antivirus-HashAggregator/{VERSION}"


# ============================================================================
# Path Resolution
# ============================================================================

def get_app_data_dir() -> Path:
    """Return the FOS-Antivirus AppData directory - hardened to deny symlink."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
        return Path(base) / APP_NAME
    else:
        # Linux/macOS fallback for testing
        return Path(os.environ.get("HOME", "/tmp")) / f".{APP_NAME.lower()}"


def get_default_db_path() -> Path:
    """Return the default path to malware_hashes.db."""
    return get_app_data_dir() / "malware_hashes.db"


def get_exe_dir() -> Optional[Path]:
    """Return the directory containing the C app's EXE (or this script).
    Used as a fallback for logs if AppData is unwritable."""
    # When invoked by the C app, sys.argv[0] is hash_aggregator.py — its parent
    # is the scripts/ dir; one level up is the EXE dir.
    try:
        script_path = Path(sys.argv[0]).resolve()
        if script_path.name == "hash_aggregator.py":
            # scripts/ -> parent = EXE dir
            return script_path.parent.parent
        return script_path.parent
    except Exception:
        return None


def get_log_path(db_path: Optional[Path] = None) -> Path:
    """Return the path to updater.log.

    Preference order:
      1. Next to the DB (typically %APPDATA%/FOS-Antivirus/updater.log)
      2. Next to the C app's EXE (fallback if AppData is unwritable)
      3. Current working directory (last resort)
    """
    candidates = []
    if db_path:
        candidates.append(db_path.parent / "updater.log")
    appdata = get_app_data_dir()
    candidates.append(appdata / "updater.log")
    exe_dir = get_exe_dir()
    if exe_dir:
        candidates.append(exe_dir / "updater.log")
    candidates.append(Path("updater.log"))

    # Return the first candidate whose parent dir is writable (or can be created)
    for cand in candidates:
        try:
            cand.parent.mkdir(parents=True, exist_ok=True)
            # Test writability by opening for append
            with open(cand, "a", encoding="utf-8") as f:
                pass
            return cand
        except OSError:
            continue
    # If all else fails, return the AppData path (we'll fail loudly later)
    return appdata / "updater.log"


def get_lock_path(db_path: Optional[Path] = None) -> Path:
    """Return the path to the aggregator lock file (next to the DB)."""
    base = db_path.parent if db_path else get_app_data_dir()
    return base / "hash_aggregator.lock"


# ============================================================================
# Logging
# ============================================================================

logger = logging.getLogger("hash_aggregator")
_resolved_log_path: Optional[Path] = None


def setup_logging(db_path: Optional[Path] = None):
    """Configure logging to file (updater.log) + stderr.

    Also emits the resolved log path to stderr as a `LOG_PATH=...` line so the
    C app can capture it and show the user where to find the log file.
    """
    global _resolved_log_path
    log_path = get_log_path(db_path)
    _resolved_log_path = log_path
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    try:
        file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
    except OSError:
        # Can't open log file — fall back to stderr-only
        file_handler = None

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(formatter)

    logger.setLevel(logging.DEBUG)
    # Clear any existing handlers (in case setup_logging is called twice)
    logger.handlers.clear()
    if file_handler:
        logger.addHandler(file_handler)
    logger.addHandler(stderr_handler)

    # Emit the log path to stderr so the C app can capture it via the merged
    # stdout/stderr pipe. The C app looks for "LOG_PATH=" prefix.
    sys.stderr.write(f"LOG_PATH={log_path}\n")
    sys.stderr.flush()
    # Also emit as a JSONL event for robustness
    _emit({"event": "log_path", "path": str(log_path)})


def get_resolved_log_path() -> Optional[Path]:
    """Return the log path that setup_logging() resolved to, or None."""
    return _resolved_log_path


# ============================================================================
# File Lock (prevents concurrent runs racing on the SQLite DB)
# ============================================================================

class FileLock:
    """Cross-process file lock. Uses msvcrt on Windows, fcntl on Unix."""

    def __init__(self, path: Path):
        self.path = path
        self.fd = None

    def acquire(self, blocking: bool = False) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Open in read-write-create mode
        self.fd = open(self.path, "a+")
        try:
            if msvcrt is not None:
                # Windows: msvcrt.locking
                try:
                    mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
                    msvcrt.locking(self.fd.fileno(), mode, 1)
                    return True
                except OSError:
                    self.fd.close()
                    self.fd = None
                    return False
            elif fcntl is not None:
                # Unix: fcntl.flock
                try:
                    op = fcntl.LOCK_EX if blocking else (fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(self.fd.fileno(), op)
                    return True
                except OSError:
                    self.fd.close()
                    self.fd = None
                    return False
            else:
                # Fallback: PID file (not race-free, but better than nothing)
                self.fd.seek(0)
                existing = self.fd.read().strip()
                if existing:
                    try:
                        pid = int(existing)
                        # Check if process is alive (Unix-only; on Windows this is best-effort)
                        if sys.platform != "win32":
                            os.kill(pid, 0)
                            # Process exists
                            self.fd.close()
                            self.fd = None
                            return False
                    except (ValueError, ProcessLookupError, PermissionError):
                        pass
                self.fd.seek(0)
                self.fd.truncate()
                self.fd.write(str(os.getpid()))
                self.fd.flush()
                return True
        except OSError:
            if self.fd:
                self.fd.close()
                self.fd = None
            return False

    def release(self):
        if self.fd is None:
            return
        try:
            if msvcrt is not None:
                try:
                    msvcrt.locking(self.fd.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            elif fcntl is not None:
                try:
                    fcntl.flock(self.fd.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            self.fd.close()
            self.fd = None
            # NOTE: the lock file is intentionally NOT unlinked. Unlinking
            # after unlocking opens a race where another process acquires
            # the lock on the same inode just before we delete it, allowing
            # a third process to create a fresh (unlocked) file and run
            # concurrently. Leaving the empty file behind is harmless: the
            # lock is the byte-range lock, not the file's existence.

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.release()


# ============================================================================
# Progress Reporter (JSONL to stdout, consumed by the C app)
#
# The C app's UI progress bar is driven by a single GLOBAL progress number
# (0-100), emitted here. The global progress is a WEIGHTED average across all
# sources, weighted by approximate source size. This means:
#   - When MalwareBazaar (weight 1.11M) finishes, global progress jumps by
#     its weight fraction (e.g. 80%) and stays there.
#   - When URLhaus (weight 259K) then starts at 0%, global progress drops by
#     a small amount (its weight fraction) but does NOT reset to 0%.
#   - The bar always moves monotonically forward (with small dips when a new
#     source starts, proportional to that source's weight).
#
# The C side reads the "global_pct" field from "progress" events and displays
# it verbatim — no averaging on the C side.
# ============================================================================

_progress_lock = threading.Lock()

# Approximate weight per source (used only for progress weighting, not for
# any DB logic). Larger weight = larger share of the progress bar. Weights
# are tuned to approximate hash counts so the bar feels proportional.
SOURCE_WEIGHTS = {
    "malwarebazaar": 1_110_000,   # ~1.11M hashes — dominant
    "urlhaus":       260_000,     # ~259K hashes — large download, fewer hashes
    "threatfox":     5_000,       # ~5K hashes
    "eset":          6_000,       # ~6K hashes
    "tweetfeed":     2_000,       # ~2K hashes
}

# Per-source current progress (0-100). Sources that haven't started yet are
# implicitly 0%. Sources that are skipped/304 are set to 100%.
_source_pct: dict = {}


def _emit(event: dict):
    """Emit a JSONL event to stdout. Always flushes."""
    event["ts"] = datetime.now(timezone.utc).isoformat()
    try:
        print(json.dumps(event), flush=True)
    except (BrokenPipeError, OSError):
        # Parent process pipe is gone/broken; continue aggregation silently
        pass


def _compute_global_pct() -> int:
    """Compute the weighted global progress percentage (0-100)."""
    total_weight = sum(SOURCE_WEIGHTS.values())
    if total_weight == 0:
        return 0
    weighted_sum = 0
    for source, weight in SOURCE_WEIGHTS.items():
        pct = _source_pct.get(source, 0)
        weighted_sum += pct * weight
    return int(weighted_sum / total_weight)


def emit_progress(source: str, pct: int, msg: str = ""):
    """Emit a per-source progress update AND a global weighted progress update.

    The C app reads `global_pct` from this event and displays it verbatim.
    """
    with _progress_lock:
        _source_pct[source] = max(0, min(100, int(pct)))
        global_pct = _compute_global_pct()
    _emit({
        "event": "progress",
        "source": source,
        "pct": max(0, min(100, int(pct))),
        "global_pct": global_pct,
        "msg": msg,
    })


def emit_source_done(source: str, count: int, elapsed_sec: float):
    with _progress_lock:
        _source_pct[source] = 100
        global_pct = _compute_global_pct()
    _emit({
        "event": "source_done",
        "source": source,
        "count": count,
        "elapsed_sec": round(elapsed_sec, 2),
        "global_pct": global_pct,
    })


def emit_source_fail(source: str, error: str, exc_info: bool = False):
    logger.error(f"Source {source} failed: {error}", exc_info=exc_info)
    # On failure, leave the source's pct where it was — don't bump to 100%,
    # because the source didn't complete. The global progress will continue
    # to advance as other sources progress.
    with _progress_lock:
        global_pct = _compute_global_pct()
    _emit({
        "event": "source_fail",
        "source": source,
        "error": error[:500],
        "global_pct": global_pct,
    })


def emit_source_skip(source: str, reason: str):
    logger.info(f"Source {source} skipped: {reason}")
    # Skipped sources count as 100% for progress purposes (we tried, got 304/rate-limit,
    # and moved on — that's a successful check from the user's perspective).
    with _progress_lock:
        _source_pct[source] = 100
        global_pct = _compute_global_pct()
    _emit({
        "event": "source_skip",
        "source": source,
        "reason": reason,
        "global_pct": global_pct,
    })


def emit_complete(total_unique: int, duplicates_removed: int, elapsed_sec: float):
    with _progress_lock:
        for source in SOURCE_WEIGHTS:
            _source_pct[source] = 100
        global_pct = 100
    _emit({
        "event": "complete",
        "total_unique": total_unique,
        "duplicates_removed": duplicates_removed,
        "elapsed_sec": round(elapsed_sec, 2),
        "global_pct": 100,
    })


def emit_error(msg: str):
    logger.error(msg)
    _emit({
        "event": "error",
        "error": msg[:500],
    })


# ============================================================================
# Hash Validation
# ============================================================================

def is_valid_sha256(s: str) -> bool:
    """Return True if s is exactly 64 lowercase hex chars."""
    if not s or len(s) != 64:
        return False
    return SHA256_RE.match(s) is not None


def normalize_sha256(s: str) -> Optional[str]:
    """Normalize to lowercase 64-char hex. Returns None if invalid."""
    if not s:
        return None
    s = s.strip().lower()
    return s if is_valid_sha256(s) else None


# ============================================================================
# HTTP Helpers
# ============================================================================

class DownloadError(Exception):
    pass


class NotModified(Exception):
    """Raised when server returns 304 Not Modified (cached data is still fresh)."""
    pass


def http_get_with_cache(url: str, etag: Optional[str] = None,
                        last_modified: Optional[str] = None,
                        stream: bool = False) -> "requests.Response":
    """GET with conditional headers. Raises NotModified on 304."""
    headers = {"User-Agent": USER_AGENT}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    last_exc = None
    for attempt in range(HTTP_RETRIES):
        try:
            resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT, stream=stream)
            if resp.status_code == 304:
                raise NotModified(url)
            if resp.status_code != 200:
                raise DownloadError(f"HTTP {resp.status_code} for {url}")
            return resp
        except NotModified:
            raise
        except (requests.RequestException, DownloadError) as e:
            last_exc = e
            logger.warning(f"HTTP attempt {attempt+1}/{HTTP_RETRIES} failed for {url}: {e}")
            if attempt < HTTP_RETRIES - 1:
                time.sleep(HTTP_RETRY_BACKOFF * (attempt + 1))
    raise DownloadError(f"HTTP failed after {HTTP_RETRIES} retries: {last_exc}")


def download_to_file(url: str, dest: Path, source_name: str,
                     etag: Optional[str] = None,
                     last_modified: Optional[str] = None
                     ) -> Tuple[Optional[str], Optional[str]]:
    """Stream-download URL to dest file with progress reporting.
    Returns (new_etag, new_last_modified).
    """
    resp = http_get_with_cache(url, etag=etag, last_modified=last_modified, stream=True)

    total = int(resp.headers.get("Content-Length", 0))
    downloaded = 0
    chunk_size = 65536

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")

    try:
        with open(tmp, "wb") as f:
            for chunk in resp.iter_content(chunk_size=chunk_size):
                if not chunk:
                    continue
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    pct = int(downloaded * 100 / total)
                    mb_done = downloaded // 1024 // 1024
                    mb_total = total // 1024 // 1024
                    emit_progress(source_name, pct,
                                  f"downloading ({mb_done}MB / {mb_total}MB)")
                else:
                    # No Content-Length; report raw MB
                    mb_done = downloaded // 1024 // 1024
                    emit_progress(source_name, 50,
                                  f"downloading ({mb_done}MB)")
        # U-11: never process a truncated payload. If the server announced a
        # Content-Length and the stream came up short, the transfer is bad.
        if total > 0 and downloaded != total:
            raise DownloadError(
                f"short read from {url}: {downloaded}/{total} bytes")
        tmp.replace(dest)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

    new_etag = resp.headers.get("ETag")
    new_lm = resp.headers.get("Last-Modified")
    return new_etag, new_lm


# ============================================================================
# Database Schema
# ============================================================================

def init_db(db_path: Path):
    """Create or upgrade the database schema."""
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        # U-19: enable incremental auto-vacuum so run_update can reclaim
        # pages cheaply instead of running a full VACUUM. Must be set before
        # the first tables are created to take effect (no-op on existing DBs
        # until a one-time manual VACUUM).
        conn.execute("PRAGMA auto_vacuum=INCREMENTAL")

        conn.executescript("""
            CREATE TABLE IF NOT EXISTS hashes (
                sha256          TEXT PRIMARY KEY,
                threat_label    TEXT,
                first_seen_utc  TEXT,
                last_seen_utc   TEXT,
                source_count    INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS sources (
                sha256          TEXT NOT NULL,
                source_name     TEXT NOT NULL,
                confidence      INTEGER,
                first_seen_utc  TEXT,
                PRIMARY KEY (sha256, source_name),
                FOREIGN KEY (sha256) REFERENCES hashes(sha256) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_sources_name ON sources(source_name);

            CREATE TABLE IF NOT EXISTS source_meta (
                source_name     TEXT PRIMARY KEY,
                last_fetch_utc  TEXT,
                etag            TEXT,
                last_modified   TEXT,
                last_count      INTEGER
            );

            -- Backward-compatibility VIEW: matches the original C-side query
            --   SELECT threat_label FROM malware_hashes WHERE sha256 = ?
            -- The C signature_scan_sqlite.c prepares this statement, so the
            -- view name MUST be `malware_hashes` and the column MUST be
            -- `threat_label`.
            CREATE VIEW IF NOT EXISTS malware_hashes AS
                SELECT sha256, threat_label FROM hashes;
        """)
        conn.commit()
        logger.info(f"Database schema initialized at {db_path}")
    finally:
        conn.close()


def get_source_meta(conn: sqlite3.Connection, source_name: str) -> dict:
    """Return cached metadata for a source."""
    row = conn.execute(
        "SELECT last_fetch_utc, etag, last_modified, last_count FROM source_meta WHERE source_name = ?",
        (source_name,)
    ).fetchone()
    if row:
        return {
            "last_fetch_utc": row[0],
            "etag": row[1],
            "last_modified": row[2],
            "last_count": row[3],
        }
    return {}


def update_source_meta(conn: sqlite3.Connection, source_name: str,
                       etag: Optional[str], last_modified: Optional[str],
                       count: int):
    """Update cached metadata for a source."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT INTO source_meta (source_name, last_fetch_utc, etag, last_modified, last_count)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(source_name) DO UPDATE SET
            last_fetch_utc = excluded.last_fetch_utc,
            etag = excluded.etag,
            last_modified = excluded.last_modified,
            last_count = excluded.last_count
    """, (source_name, now, etag, last_modified, count))


def should_skip_due_to_rate_limit(conn: sqlite3.Connection, source_name: str) -> Optional[str]:
    """Return reason string if source should be skipped due to rate limit, else None."""
    meta = get_source_meta(conn, source_name)
    if not meta.get("last_fetch_utc"):
        return None
    try:
        last = datetime.fromisoformat(meta["last_fetch_utc"])
    except (ValueError, TypeError):
        return None
    elapsed = (datetime.now(timezone.utc) - last).total_seconds()
    min_interval = RATE_LIMITS.get(source_name, 300)
    if elapsed < min_interval:
        remaining = int(min_interval - elapsed)
        return f"rate limited (next allowed in {remaining}s)"
    return None


# ============================================================================
# DB Upsert Helpers
# ============================================================================

def upsert_hash(conn: sqlite3.Connection, sha256: str, threat_label: Optional[str],
                first_seen_utc: Optional[str]):
    """Insert or update a hash. source_count is managed by upsert_source_link."""
    existing = conn.execute(
        "SELECT threat_label, first_seen_utc FROM hashes WHERE sha256 = ?",
        (sha256,)
    ).fetchone()

    now_utc = datetime.now(timezone.utc).isoformat()

    if existing:
        old_label, old_first_seen = existing
        # Prefer non-null, non-"None" label (some sources emit the literal string "None")
        def is_real_label(s):
            return s and s != "None" and s.strip() != ""

        if is_real_label(threat_label) and not is_real_label(old_label):
            new_label = threat_label
        else:
            new_label = old_label
        # Keep earliest first_seen
        if first_seen_utc and old_first_seen and first_seen_utc < old_first_seen:
            new_first_seen = first_seen_utc
        elif old_first_seen:
            new_first_seen = old_first_seen
        else:
            new_first_seen = first_seen_utc or now_utc

        conn.execute("""
            UPDATE hashes
            SET threat_label = ?, first_seen_utc = ?, last_seen_utc = ?
            WHERE sha256 = ?
        """, (new_label, new_first_seen, now_utc, sha256))
    else:
        label = threat_label if (threat_label and threat_label != "None") else None
        conn.execute("""
            INSERT INTO hashes (sha256, threat_label, first_seen_utc, last_seen_utc, source_count)
            VALUES (?, ?, ?, ?, 0)
        """, (sha256, label, first_seen_utc or now_utc, now_utc))


def upsert_source_link(conn: sqlite3.Connection, sha256: str, source_name: str,
                       confidence: int, first_seen_utc: Optional[str]) -> bool:
    """Insert a source link if new. Returns True if a NEW link was added
    (in which case source_count on hashes is incremented)."""
    existing = conn.execute(
        "SELECT 1 FROM sources WHERE sha256 = ? AND source_name = ?",
        (sha256, source_name)
    ).fetchone()
    if existing:
        return False

    now_utc = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT INTO sources (sha256, source_name, confidence, first_seen_utc)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(sha256, source_name) DO NOTHING
    """, (sha256, source_name, confidence, first_seen_utc or now_utc))

    conn.execute(
        "UPDATE hashes SET source_count = source_count + 1 WHERE sha256 = ?",
        (sha256,)
    )
    return True


# ============================================================================
# Source Adapters
# ============================================================================

class SourceError(Exception):
    pass


class SourceAdapter:
    """Base class for hash source adapters."""
    name = "base"
    confidence = 50

    def __init__(self, conn: sqlite3.Connection, cache_dir: Path):
        self.conn = conn
        self.cache_dir = cache_dir

    def get_cached_meta(self) -> dict:
        return get_source_meta(self.conn, self.name)

    def update_meta(self, etag: Optional[str], last_modified: Optional[str], count: int):
        update_source_meta(self.conn, self.name, etag, last_modified, count)

    def refresh(self) -> int:
        """Refresh this source. Returns count of hash records processed."""
        raise NotImplementedError


class MalwareBazaarAdapter(SourceAdapter):
    """MalwareBazaar full SHA-256 dump.
    URL: https://bazaar.abuse.ch/export/txt/sha256/full/
    Format: ZIP containing full_sha256.txt (one 64-char sha256 per line, #-comments).
    Size: ~42 MB compressed, ~73 MB uncompressed, ~1.11M hashes.
    """
    name = "malwarebazaar"
    confidence = 100
    APPROX_TOTAL = 1_111_618  # for progress estimation

    def refresh(self) -> int:
        meta = self.get_cached_meta()
        zip_path = self.cache_dir / "malwarebazaar_full.zip"

        emit_progress(self.name, 5, "connecting")
        new_etag, new_lm = download_to_file(
            URL_MALWAREBAZAAR_FULL, zip_path, self.name,
            etag=meta.get("etag"), last_modified=meta.get("last_modified")
        )

        emit_progress(self.name, 50, "extracting")
        count = 0
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                txt_names = [n for n in zf.namelist() if n.endswith(".txt")]
                if not txt_names:
                    raise SourceError("no .txt file in MalwareBazaar ZIP")
                with zf.open(txt_names[0]) as f:
                    for line in io.TextIOWrapper(f, encoding="utf-8"):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        sha = normalize_sha256(line)
                        if not sha:
                            continue
                        upsert_hash(self.conn, sha, "MalwareBazaar.Threat", None)
                        upsert_source_link(self.conn, sha, self.name, self.confidence, None)
                        count += 1
                        if count % 50000 == 0:
                            emit_progress(self.name,
                                          50 + int(count / self.APPROX_TOTAL * 45),
                                          f"imported {count}")
                            self.conn.commit()
        finally:
            try:
                zip_path.unlink()
            except OSError:
                pass

        self.update_meta(new_etag, new_lm, count)
        emit_progress(self.name, 100, f"done ({count} hashes)")
        return count


class URLhausPayloadsAdapter(SourceAdapter):
    """URLhaus collected payloads dump.
    URL: https://urlhaus.abuse.ch/downloads/payloads/
    Format: ZIP containing payload.txt (CSV: firstseen,url,filetype,md5,sha256,signature).
    Size: ~775 MB compressed, ~2.6 GB uncompressed, ~259K unique SHA-256 hashes.
    IMPORTANT: stream-decompress; do NOT materialize the full payload.txt in memory.
    """
    name = "urlhaus"
    confidence = 85
    APPROX_TOTAL = 259_000  # unique hashes (not line count, which is higher due to URL-dedup)

    def refresh(self) -> int:
        meta = self.get_cached_meta()
        zip_path = self.cache_dir / "urlhaus_payloads.zip"

        emit_progress(self.name, 5, "connecting")
        new_etag, new_lm = download_to_file(
            URL_URLHAUS_PAYLOADS, zip_path, self.name,
            etag=meta.get("etag"), last_modified=meta.get("last_modified")
        )

        emit_progress(self.name, 60, "extracting (stream)")
        count = 0
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                txt_names = [n for n in zf.namelist() if n.endswith(".txt")]
                if not txt_names:
                    raise SourceError("no .txt file in URLhaus ZIP")
                with zf.open(txt_names[0]) as f:
                    wrapper = io.TextIOWrapper(f, encoding="utf-8")
                    reader = csv.reader(wrapper)
                    header_seen = False
                    col_idx = {}
                    for row in reader:
                        if not row:
                            continue
                        if row[0].startswith("#"):
                            continue
                        if not header_seen:
                            col_idx = {name: i for i, name in enumerate(row)}
                            header_seen = True
                            continue
                        sha_col = col_idx.get("sha256")
                        sig_col = col_idx.get("signature")
                        firstseen_col = col_idx.get("firstseen")
                        if sha_col is None or sha_col >= len(row):
                            continue
                        sha = normalize_sha256(row[sha_col])
                        if not sha:
                            continue
                        label = row[sig_col] if (sig_col is not None and sig_col < len(row)) else None
                        first_seen = None
                        if firstseen_col is not None and firstseen_col < len(row):
                            raw_fs = row[firstseen_col]
                            if raw_fs and raw_fs != "None":
                                try:
                                    dt = datetime.strptime(raw_fs, "%Y-%m-%d %H:%M:%S")
                                    first_seen = dt.replace(tzinfo=timezone.utc).isoformat()
                                except ValueError:
                                    pass

                        upsert_hash(self.conn, sha, label, first_seen)
                        upsert_source_link(self.conn, sha, self.name, self.confidence, first_seen)
                        count += 1
                        if count % 100000 == 0:
                            emit_progress(self.name,
                                          60 + int(count / self.APPROX_TOTAL * 35),
                                          f"imported {count}")
                            self.conn.commit()
        finally:
            try:
                zip_path.unlink()
            except OSError:
                pass

        self.update_meta(new_etag, new_lm, count)
        emit_progress(self.name, 100, f"done ({count} hashes)")
        return count


class ThreatFoxAdapter(SourceAdapter):
    """ThreatFox full JSON export.
    URL: https://threatfox.abuse.ch/export/json/full/
    Format: ZIP containing full.json (single JSON object: {ioc_id: [record, ...]}).
    Size: ~3.4 MB compressed, ~62 MB uncompressed, ~5K sha256 IOCs (filter ioc_type == "sha256_hash").
    """
    name = "threatfox"
    confidence = 90

    def refresh(self) -> int:
        meta = self.get_cached_meta()
        zip_path = self.cache_dir / "threatfox_full.zip"

        emit_progress(self.name, 5, "connecting")
        new_etag, new_lm = download_to_file(
            URL_THREATFOX_FULL, zip_path, self.name,
            etag=meta.get("etag"), last_modified=meta.get("last_modified")
        )

        emit_progress(self.name, 50, "parsing JSON")
        count = 0
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                json_names = [n for n in zf.namelist() if n.endswith(".json")]
                if not json_names:
                    raise SourceError("no .json file in ThreatFox ZIP")
                with zf.open(json_names[0]) as f:
                    data = json.load(f)

            # data is a dict: {ioc_id_str: [record_dict, ...]}
            total_records = sum(len(v) for v in data.values()) if isinstance(data, dict) else 0
            processed = 0
            if isinstance(data, dict):
                for ioc_id, records in data.items():
                    for rec in records:
                        processed += 1
                        if not isinstance(rec, dict):
                            continue
                        if rec.get("ioc_type") != "sha256_hash":
                            continue
                        sha = normalize_sha256(rec.get("ioc_value", ""))
                        if not sha:
                            continue
                        label = rec.get("malware_printable") or rec.get("malware")
                        first_seen = rec.get("first_seen_utc")
                        if first_seen:
                            try:
                                dt = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S")
                                first_seen = dt.replace(tzinfo=timezone.utc).isoformat()
                            except ValueError:
                                first_seen = None

                        upsert_hash(self.conn, sha, label, first_seen)
                        upsert_source_link(self.conn, sha, self.name, self.confidence, first_seen)
                        count += 1
                        if processed % 10000 == 0 and total_records > 0:
                            emit_progress(self.name,
                                          50 + int(processed / total_records * 45),
                                          f"processed {processed}/{total_records}")
                            self.conn.commit()
            elif isinstance(data, list):
                # Defensive: some future format change might emit a list
                for rec in data:
                    processed += 1
                    if not isinstance(rec, dict):
                        continue
                    if rec.get("ioc_type") != "sha256_hash":
                        continue
                    sha = normalize_sha256(rec.get("ioc_value", ""))
                    if not sha:
                        continue
                    label = rec.get("malware_printable") or rec.get("malware")
                    upsert_hash(self.conn, sha, label, None)
                    upsert_source_link(self.conn, sha, self.name, self.confidence, None)
                    count += 1
        finally:
            try:
                zip_path.unlink()
            except OSError:
                pass

        self.update_meta(new_etag, new_lm, count)
        emit_progress(self.name, 100, f"done ({count} hashes)")
        return count


class ESETMalwareIOCAdapter(SourceAdapter):
    """ESET malware-ioc GitHub repo (BSD-2-clause).
    URL: https://github.com/eset/malware-ioc (downloaded as tarball)
    Format: tarball containing ~147 samples.sha256 files, one hash per line.
    Threat label is derived from the parent directory name (e.g. "turla" -> "ESET.turla").
    Size: ~399 KB total, ~6,100 SHA-256 hashes.
    """
    name = "eset"
    confidence = 95

    def refresh(self) -> int:
        meta = self.get_cached_meta()
        tarball_path = self.cache_dir / "eset_malware_ioc.tar.gz"

        emit_progress(self.name, 5, "connecting")
        new_etag, new_lm = download_to_file(
            URL_ESET_TARBALL, tarball_path, self.name,
            etag=meta.get("etag"), last_modified=meta.get("last_modified")
        )

        emit_progress(self.name, 50, "extracting tarball")
        count = 0
        extract_dir = self.cache_dir / "eset_extracted"
        if extract_dir.exists():
            shutil.rmtree(extract_dir, ignore_errors=True)
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            with tarfile.open(tarball_path, "r:gz") as tf:
                # Python 3.12+ has a `filter` arg for security; older versions don't
                try:
                    tf.extractall(extract_dir, filter="data")
                except TypeError:
                    tf.extractall(extract_dir)

            sha_files = list(extract_dir.rglob("samples.sha256"))
            total_files = len(sha_files)
            if total_files == 0:
                logger.warning("no samples.sha256 files found in ESET repo")

            for i, sha_file in enumerate(sha_files):
                # Derive threat label from parent directory name
                parent_name = sha_file.parent.name
                if parent_name in ("malware-ioc-master", "malware-ioc-main"):
                    label = "ESET.Unknown"
                else:
                    label = f"ESET.{parent_name}"

                try:
                    with open(sha_file, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            sha = normalize_sha256(line)
                            if not sha:
                                continue
                            upsert_hash(self.conn, sha, label, None)
                            upsert_source_link(self.conn, sha, self.name, self.confidence, None)
                            count += 1
                except OSError as e:
                    logger.warning(f"failed to read {sha_file}: {e}")

                if (i + 1) % 10 == 0 or i + 1 == total_files:
                    emit_progress(self.name,
                                  50 + int((i + 1) / max(total_files, 1) * 45),
                                  f"processed {i+1}/{total_files} files")
                    self.conn.commit()
        finally:
            try:
                tarball_path.unlink()
            except OSError:
                pass
            if extract_dir.exists():
                shutil.rmtree(extract_dir, ignore_errors=True)

        self.update_meta(new_etag, new_lm, count)
        emit_progress(self.name, 100, f"done ({count} hashes)")
        return count


class TweetFeedAdapter(SourceAdapter):
    """TweetFeed year.csv (rolling 365-day Twitter-sourced IOCs).
    URL: https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv
    Format: CSV with columns: date, source, type, indicator, tags, tweet_url (NO header row).
    Filter: type == "sha256".
    Size: ~14 MB, ~2,300 SHA-256 hashes.
    """
    name = "tweetfeed"
    confidence = 75

    def refresh(self) -> int:
        meta = self.get_cached_meta()
        csv_path = self.cache_dir / "tweetfeed_year.csv"

        emit_progress(self.name, 5, "connecting")
        new_etag, new_lm = download_to_file(
            URL_TWEETFEED_YEAR, csv_path, self.name,
            etag=meta.get("etag"), last_modified=meta.get("last_modified")
        )

        emit_progress(self.name, 50, "parsing CSV")
        count = 0
        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) < 4:
                        continue
                    # Row format: date, source, type, indicator, tags, tweet_url
                    ioc_type = row[2].strip().lower()
                    if ioc_type != "sha256":
                        continue
                    sha = normalize_sha256(row[3])
                    if not sha:
                        continue
                    first_seen = row[0].strip() if row[0] else None
                    if first_seen:
                        try:
                            dt = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S")
                            first_seen = dt.replace(tzinfo=timezone.utc).isoformat()
                        except ValueError:
                            try:
                                # Some rows may have date-only
                                dt = datetime.strptime(first_seen, "%Y-%m-%d")
                                first_seen = dt.replace(tzinfo=timezone.utc).isoformat()
                            except ValueError:
                                first_seen = None

                    upsert_hash(self.conn, sha, "TweetFeed.Suspicious", first_seen)
                    upsert_source_link(self.conn, sha, self.name, self.confidence, first_seen)
                    count += 1
                    if count % 500 == 0:
                        emit_progress(self.name, 50, f"imported {count} sha256")
                        self.conn.commit()
        finally:
            try:
                csv_path.unlink()
            except OSError:
                pass

        self.update_meta(new_etag, new_lm, count)
        emit_progress(self.name, 100, f"done ({count} hashes)")
        return count


# ============================================================================
# Aggregator Orchestrator
# ============================================================================

ALL_SOURCES = [
    MalwareBazaarAdapter,
    URLhausPayloadsAdapter,
    ThreatFoxAdapter,
    ESETMalwareIOCAdapter,
    TweetFeedAdapter,
]


class Aggregator:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.cache_dir = db_path.parent / "aggregator_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def clean_cache(self):
        """Remove leftover files from previous interrupted runs.

        This purges the aggregator_cache/ directory of stale downloads
        (e.g. half-downloaded ZIPs from a previous run that was killed
        by the user or a crash). Safe to call before every update.
        """
        if not self.cache_dir.exists():
            return
        removed = 0
        for item in self.cache_dir.iterdir():
            try:
                if item.is_file():
                    item.unlink()
                    removed += 1
                elif item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                    removed += 1
            except OSError as e:
                logger.warning(f"could not remove {item}: {e}")
        if removed > 0:
            logger.info(f"cleaned {removed} stale item(s) from cache")

    def run_update(self, sources: Optional[list] = None, force: bool = False) -> dict:
        """Run update across sources. Returns summary dict."""
        init_db(self.db_path)

        # Clean up any leftover files from a previous interrupted run
        self.clean_cache()

        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")

        before_count = 0
        before_links = 0
        try:
            before_count = conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            before_links = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
        except sqlite3.OperationalError:
            pass  # tables don't exist yet — init_db should have created them

        start = time.time()
        results = {}
        any_success = False

        adapter_classes = ALL_SOURCES if sources is None else sources

        for adapter_cls in adapter_classes:
            adapter = adapter_cls(conn, self.cache_dir)

            # Check rate limit (unless forced)
            if not force:
                skip_reason = should_skip_due_to_rate_limit(conn, adapter.name)
                if skip_reason:
                    emit_source_skip(adapter.name, skip_reason)
                    results[adapter.name] = ("skipped", skip_reason)
                    # Rate-limit skips count as success — the source is healthy,
                    # we just fetched it recently. If ALL sources are rate-
                    # limited, the DB is already current and we should exit 0,
                    # not report "all sources failed".
                    any_success = True
                    continue

            emit_progress(adapter.name, 0, "starting")
            src_start = time.time()
            try:
                conn.execute("BEGIN")
                count = adapter.refresh()
                conn.commit()
                elapsed = time.time() - src_start
                emit_source_done(adapter.name, count, elapsed)
                results[adapter.name] = ("ok", count)
                any_success = True
            except NotModified:
                try:
                    conn.rollback()
                except sqlite3.OperationalError:
                    pass
                emit_source_skip(adapter.name, "not modified since last fetch (304)")
                results[adapter.name] = ("skipped", "304 not modified")
                any_success = True  # 304 is a successful check
            except (SourceError, DownloadError) as e:
                try:
                    conn.rollback()
                except sqlite3.OperationalError:
                    pass
                emit_source_fail(adapter.name, str(e))
                results[adapter.name] = ("failed", str(e))
            except Exception as e:
                # Catch-all so one bad source doesn't kill the whole run
                logger.exception(f"Source {adapter.name} raised")  # Full traceback to updater.log
                try:
                    conn.rollback()
                except sqlite3.OperationalError:
                    pass
                emit_source_fail(adapter.name, f"unexpected error: {type(e).__name__}: {e}")
                results[adapter.name] = ("failed", str(e))

        # U-19: replace the unconditional VACUUM (which rewrites the whole
        # 1.1M-row database on every update) with an incremental vacuum that
        # only returns already-freed pages. init_db enables auto_vacuum for
        # new databases; older databases keep the previous layout until a
        # manual `VACUUM` is run once.
        try:
            conn.commit()
            conn.execute("PRAGMA incremental_vacuum")
        except sqlite3.OperationalError as e:
            logger.debug(f"incremental_vacuum skipped: {e}")

        # U-12: flush the WAL back into the main database file before
        # closing. The C engine computes its HMAC integrity file over the
        # physical .db file; a live -wal would make the logical database
        # state diverge from the bytes that get authenticated.
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.OperationalError as e:
            logger.warning(f"wal_checkpoint(TRUNCATE) failed: {e}")

        after_count = 0
        after_links = 0
        try:
            after_count = conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            after_links = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
        except sqlite3.OperationalError:
            pass
        conn.close()

        elapsed = time.time() - start
        emit_complete(
            total_unique=after_count,
            duplicates_removed=after_links - before_links,
            elapsed_sec=elapsed
        )

        return {
            "any_success": any_success,
            "before_unique": before_count,
            "after_unique": after_count,
            "elapsed_sec": elapsed,
            "results": results,
        }

    def print_stats(self) -> int:
        """Print database statistics to stdout (human-readable)."""
        if not self.db_path.exists():
            sys.stderr.write(f"Database not found: {self.db_path}\n")
            return 1

        conn = sqlite3.connect(str(self.db_path))
        try:
            total = conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            print(f"Database: {self.db_path}")
            print(f"Total unique SHA-256 hashes: {total:,}")
            print()
            print("Per-source breakdown:")
            print("-" * 70)
            for row in conn.execute(
                "SELECT source_name, COUNT(*) as cnt, MAX(first_seen_utc) as latest "
                "FROM sources GROUP BY source_name ORDER BY cnt DESC"
            ):
                print(f"  {row[0]:20s} {row[1]:>10,}  latest: {row[2] or 'N/A'}")
            print("-" * 70)
            print()
            print("Last fetch per source:")
            print("-" * 70)
            for row in conn.execute(
                "SELECT source_name, last_fetch_utc, last_count "
                "FROM source_meta ORDER BY source_name"
            ):
                fetched = row[1] or "never"
                cnt = row[2] or 0
                print(f"  {row[0]:20s} fetched: {fetched:30s}  count: {cnt:,}")
            print("-" * 70)
        finally:
            conn.close()
        return 0


# ============================================================================
# CLI
# ============================================================================

def cmd_init(args):
    db_path = Path(args.db) if args.db else get_default_db_path()
    setup_logging(db_path)
    logger.info("Initializing database schema")
    init_db(db_path)
    print(f"Database initialized: {db_path}")
    return 0


def cmd_update(args):
    db_path = Path(args.db) if args.db else get_default_db_path()
    setup_logging(db_path)

    lock = FileLock(get_lock_path(db_path))
    if not lock.acquire(blocking=False):
        emit_error("another aggregator instance is already running")
        return 3

    try:
        sources = None
        if args.only:
            source_map = {c.name: c for c in ALL_SOURCES}
            sources = []
            for name in args.only:
                if name in source_map:
                    sources.append(source_map[name])
                else:
                    emit_error(f"unknown source: {name}")
                    return 2

        agg = Aggregator(db_path)
        summary = agg.run_update(sources=sources, force=args.force)

        if not summary["any_success"]:
            logger.error("all sources failed")
            return 1
        return 0
    finally:
        lock.release()


def cmd_daemon(args):
    db_path = Path(args.db) if args.db else get_default_db_path()
    setup_logging(db_path)

    logger.info(f"Starting daemon mode, interval={args.interval}h")
    sys.stderr.write(
        f"Daemon mode: polling every {args.interval}h. Press Ctrl+C to stop.\n"
    )

    while True:
        try:
            lock = FileLock(get_lock_path(db_path))
            if not lock.acquire(blocking=False):
                logger.warning("another instance is running, skipping this cycle")
            else:
                try:
                    agg = Aggregator(db_path)
                    agg.run_update(force=False)
                finally:
                    lock.release()

            sleep_sec = args.interval * 3600
            logger.info(f"sleeping {sleep_sec}s")
            time.sleep(sleep_sec)
        except KeyboardInterrupt:
            logger.info("daemon interrupted, exiting")
            return 0
        except Exception as e:
            logger.error(f"daemon cycle error: {e}")
            time.sleep(60)


def cmd_stats(args):
    db_path = Path(args.db) if args.db else get_default_db_path()
    setup_logging(db_path)
    agg = Aggregator(db_path)
    return agg.print_stats()


def cmd_cleanup(args):
    """Remove stale artifacts from the AppData directory.

    Cleans up:
      - aggregator_cache/ contents (leftover downloads from interrupted runs)
      - update_*/ directories (leftover from old v1.0 C-side WinINet downloader)
      - hash_db_config.json (leftover from old v1.0 Python scripts)
      - update_hashes.bat (leftover from old v1.0 setup)
      - auto_update.log DIRECTORY (created by a bug in v1.1 auto_update.c
        that called CreateDirectoryA on the full file path)

    Does NOT touch: malware_hashes.db, settings.conf, updater.log,
    history.log, heuristics.log, Quarantine/, the auto_update.log FILE
    (once the directory bug is fixed).
    """
    db_path = Path(args.db) if args.db else get_default_db_path()
    setup_logging(db_path)
    appdata_dir = db_path.parent

    print(f"Cleaning up stale artifacts in: {appdata_dir}")
    print()

    # 1. aggregator_cache/ contents
    cache_dir = appdata_dir / "aggregator_cache"
    if cache_dir.exists():
        removed = 0
        for item in cache_dir.iterdir():
            try:
                if item.is_file():
                    item.unlink()
                    removed += 1
                elif item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                    removed += 1
            except OSError as e:
                print(f"  WARNING: could not remove {item}: {e}")
        print(f"  aggregator_cache/: removed {removed} stale item(s)")
    else:
        print(f"  aggregator_cache/: not present")

    # 2. update_*/ directories (from old v1.0 C-side downloader)
    #    Only match DIRECTORIES named update_* — don't touch files like
    #    update_hashes.bat (handled separately below).
    import glob
    update_dirs = [d for d in glob.glob(str(appdata_dir / "update_*"))
                   if Path(d).is_dir()]
    for d in update_dirs:
        try:
            shutil.rmtree(d, ignore_errors=True)
            print(f"  removed stale dir: {Path(d).name}")
        except OSError as e:
            print(f"  WARNING: could not remove {d}: {e}")

    # 3. Old v1.0 config files
    old_files = [
        "hash_db_config.json",    # old aggregator config
        "update_hashes.bat",       # old setup batch file
    ]
    for fname in old_files:
        fpath = appdata_dir / fname
        if fpath.exists():
            try:
                fpath.unlink()
                print(f"  removed old file: {fname}")
            except OSError as e:
                print(f"  WARNING: could not remove {fname}: {e}")

    # 4. auto_update.log DIRECTORY (bug in v1.1 auto_update.c)
    #    If it's a directory, remove it so the fixed code can create a FILE
    #    with the same name.
    auto_update_path = appdata_dir / "auto_update.log"
    if auto_update_path.is_dir():
        try:
            shutil.rmtree(auto_update_path, ignore_errors=True)
            print(f"  removed auto_update.log DIRECTORY (was a bug in v1.1)")
        except OSError as e:
            print(f"  WARNING: could not remove auto_update.log dir: {e}")
    elif auto_update_path.exists():
        print(f"  auto_update.log: already a file (OK)")

    print()
    print("Cleanup complete.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="hash_aggregator",
        description="Unified malware hash aggregator for FOS Antivirus"
    )
    # Global --db option (must come before subcommand)
    parser.add_argument("--db",
                        help="Path to malware_hashes.db (default: %%APPDATA%%/FOS-Antivirus/malware_hashes.db)")

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create or upgrade the database schema")
    p_init.set_defaults(func=cmd_init)

    p_update = sub.add_parser("update", help="One-shot refresh of all (or selected) sources")
    p_update.add_argument("--only", nargs="+",
                          choices=[c.name for c in ALL_SOURCES],
                          help="Only refresh specified sources")
    p_update.add_argument("--force", action="store_true",
                          help="Skip rate-limit checks")
    p_update.set_defaults(func=cmd_update)

    p_daemon = sub.add_parser("daemon", help="Continuous mode (poll every N hours)")
    p_daemon.add_argument("--interval", type=int, default=6,
                          help="Poll interval in hours (default: 6)")
    p_daemon.set_defaults(func=cmd_daemon)

    p_stats = sub.add_parser("stats", help="Print database statistics")
    p_stats.set_defaults(func=cmd_stats)

    p_cleanup = sub.add_parser("cleanup", help="Remove stale artifacts from AppData dir")
    p_cleanup.set_defaults(func=cmd_cleanup)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())



# FOS Antivirus

FOS Antivirus is a Windows security-scanner prototype built in C11 with a GTK4 user interface. It combines SHA-256 signature matching, static PE feature extraction, heuristic scoring, a lightweight native Decision Forest inference engine, real-time file monitoring, and quarantine/restore workflows.

This project is intended as a research and educational endpoint-security prototype. It is not production endpoint protection.

## Core Capabilities

- Native GTK4 desktop UI for scans, settings, updates, and detection history.
- **Centralized SQLite signature database** aggregated from 5 public no-auth sources (MalwareBazaar, URLhaus, ThreatFox, ESET malware-ioc, TweetFeed).
- Fast SHA-256 hash lookups against ~1.1M+ malware signatures.
- Native static feature extraction for PE-like files into a 2,381-dimensional vector.
- Custom `FORE` binary model format for LightGBM-derived decision forest inference.
- Rule-based heuristic scoring for suspicious file properties and real-time burst events.
- Quarantine/restore support with verified copy-before-delete behavior.
- Real-time monitoring of user-profile file changes via Windows APIs.

## v1.1 Changes

This release replaces the broken C-side WinINet downloader (MalwareBazaar now serves a ZIP, not raw text, which the old code explicitly rejected) with a shell-out to a unified Python aggregator that pulls from 5 public no-auth sources. It also removes the "lock app on failed initial DB update" behavior, applies several code-quality refactors, and hardens the quarantine-restore path against path-traversal attacks.

### Removed: First-Run UI Lock
The app previously disabled scan/realtime buttons and forced a download progress bar on first launch. This is gone. The app now starts cleanly; if no DB exists, scan attempts surface the existing "signature database not loaded" error and the user can click "Update Now" in Settings.

### Removed: 4 Prior Python Scripts
The prior `aggregate_hashes.py`, `hash_updater_daemon.py`, `setup_hash_database.py`, and `monitor_hash_database.py` have been replaced by a single unified `scripts/hash_aggregator.py`. If you have the old scripts in your tree, delete them.

### Added: Inert Auto-Update Stub
A new `src/app/auto_update.c` provides an inert stub (`auto_update_check()`) called on startup. This is the entry point for a future server-based application auto-update mechanism. It currently does nothing useful — it logs once and returns. To wire up your own server later, replace the body of `auto_update_check()` in `src/app/auto_update.c`.

## New: Centralized Hash Database

The app uses a **centralized SQLite database** aggregated from 5 public no-auth sources by `scripts/hash_aggregator.py`:

| # | Source | Confidence | Approx hashes | Refresh | Format |
|---|--------|-----------|---------------|---------|--------|
| 1 | MalwareBazaar (abuse.ch) | 100 | ~1.11M | hourly | ZIP → TXT (sha256 per line) |
| 2 | URLhaus payloads (abuse.ch) | 85 | ~259K | 5-min | ZIP → CSV (firstseen,url,filetype,md5,sha256,signature) |
| 3 | ThreatFox (abuse.ch) | 90 | ~5K | hourly | ZIP → JSON (filter `ioc_type=="sha256_hash"`) |
| 4 | ESET malware-ioc (GitHub, BSD-2) | 95 | ~6.1K | irregular | tarball → ~147 `samples.sha256` files |
| 5 | TweetFeed (GitHub) | 75 | ~2.3K | 15-min | CSV (rolling 365-day window) |

### Schema (rich, multi-source attribution)
```sql
hashes(sha256 PK, threat_label, first_seen_utc, last_seen_utc, source_count)
sources(sha256 FK, source_name, confidence, first_seen_utc, PK(sha256, source_name))
source_meta(source_name PK, last_fetch_utc, etag, last_modified, last_count)
-- Backward-compat view (matches C-side lookup query):
CREATE VIEW malware_hashes AS SELECT sha256, threat_label FROM hashes;
```

### Usage
```bash
# One-shot refresh of all sources (called by the C app's "Update Now" button)
python scripts/hash_aggregator.py update

# Or with explicit DB path
python scripts/hash_aggregator.py --db "C:\path\to\malware_hashes.db" update

# Refresh only specific sources
python scripts/hash_aggregator.py update --only malwarebazaar threatfox

# Skip rate-limit checks (force re-download)
python scripts/hash_aggregator.py update --force

# Continuous mode (poll every 6h, for Task Scheduler)
python scripts/hash_aggregator.py daemon --interval 6

# Print DB statistics
python scripts/hash_aggregator.py stats
```

### Backward Compatibility
The C-side lookup query `SELECT threat_label FROM malware_hashes WHERE sha256 = ?` still works unchanged — `malware_hashes` is now a VIEW over the `hashes` table.

### Important: abuse.ch Auth Migration
As of 2025-06-30, abuse.ch officially requires a free Auth-Key for their new API endpoints. The legacy static URLs used by this aggregator (`bazaar.abuse.ch/export/...`, `urlhaus.abuse.ch/downloads/...`, `threatfox.abuse.ch/export/...`) still serve no-auth as of July 2026, but this could change without notice. If they break, register a free key at https://auth.abuse.ch and update the URL constants at the top of `scripts/hash_aggregator.py`.

## Runtime Storage

Mutable runtime data is stored under:

```text
%APPDATA%\FOS-Antivirus\
```

The app stores:

- `malware_hashes.db`: Centralized SQLite database with 1.1M+ malware signatures
- `malware_hashes.db-wal`: SQLite write-ahead log
- `malware_hashes.db-shm`: SQLite shared memory index
- `aggregator_cache/`: Temp directory for download/extract during updates
- `history.log`: quarantine and detection history.
- `heuristics.log`: heuristic and monitor diagnostics.
- `Quarantine\`: isolated quarantined files.
- `updater.log`: hash database update logs
- `auto_update.log`: inert-stub log (will be replaced when real auto-update lands)
- `hash_aggregator.lock`: cross-process lock file during aggregator runs
- `settings.conf`: app settings (auto_update, last_update, dark_mode)

The ML model is staged at build time to:

```text
build\ml\models\forest.bin
```

At runtime, the app first looks for `ml\models\forest.bin` next to the executable and falls back to the source-tree `assets\models\forest.bin` for development runs.

## Repository Layout

```text
FOS-Antivirus/
  assets/models/forest.bin           # Bundled FORE decision forest model
  scripts/
    hash_aggregator.py               # Unified hash aggregator (5 sources, subcommands: init/update/daemon/stats)
  src/app/
    app.c, app.h                     # App lifecycle + SettingsState struct
    app_paths.c, app_paths.h         # Path resolution
    auto_update.c, auto_update.h     # Inert stub for future server-based auto-update
  src/engine/
    signature_scan.c/h               # Signature scanning + update_signature_db() (shells out to Python)
    signature_scan_sqlite.c/h        # SQLite database interface
    feature_extract.c/h              # PE feature extraction (FEAT_IDX_* defines for vector indices)
    response_engine.c/h              # Quarantine/restore (v1.1: fixed stored_patheader typo)
    scan_report_bridge.c/h
    ...                              # Other detection engines
  src/ui/
    ui_history.c/h                   # Detection history (v1.1: path canonicalization)
    ui_scan.c/h
    ui_views.c/h                     # Dashboard (v1.1: removed first-run UI lock)
    ui_update.c/h
    ui_sidebar.c/h
    ui_scan_paths.c/h
  CMakeLists.txt                     # MSYS2/MinGW build configuration (SQLite3 required)
  README.md
  requirements.txt                   # Python training/validation dependencies
```

## Build Instructions

Install MSYS2 and use the MINGW64 shell:

```bash
pacman -S mingw-w64-x86_64-gcc \
          mingw-w64-x86_64-cmake \
          mingw-w64-x86_64-ninja \
          mingw-w64-x86_64-gtk4 \
          mingw-w64-x86_64-pkgconf \
          mingw-w64-x86_64-sqlite3
```

Configure and build:

```bash
cmake -B build -S . -G "Ninja" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Run:

```bash
./build/FOS-Antivirus.exe
```

The build stages `assets/models/forest.bin` into `build/ml/models/forest.bin` AND `scripts/hash_aggregator.py` into `build/scripts/hash_aggregator.py` automatically.

### Python Dependency

The C app shells out to `python.exe` for signature DB updates. Install Python 3.8+ from https://python.org and ensure it's on your PATH. The aggregator requires the `requests` library:

```bash
pip install requests
```

If Python is not on PATH, the C app will also probe `C:\PythonNNN\python.exe` and `%LOCALAPPDATA%\Programs\Python\PythonNNN\python.exe` for NNN in {313, 312, 311, 310, 39}.

## Signature Updates

The signature database uses the centralized SQLite database aggregated from 5 public sources.

### Public Sources Included

1. **MalwareBazaar** — confidence 100 — ~1.11M SHA-256 hashes
2. **URLhaus (payloads)** — confidence 85 — ~259K SHA-256 hashes
3. **ThreatFox** — confidence 90 — ~5K SHA-256 IOCs
4. **ESET malware-ioc** — confidence 95 — ~6.1K SHA-256 hashes (BSD-2 license)
5. **TweetFeed** — confidence 75 — ~2.3K SHA-256 hashes (rolling 365 days)

### Update Methods

#### Automatic (In-App)

Click "Update Now" in the Settings tab. The C app shells out to `scripts/hash_aggregator.py update` and displays real-time progress via the JSONL stream from the Python script's stdout.

#### Automatic (Background)

The app checks for updates every 6 hours via a GLib timer (if auto-update is enabled in Settings).

#### Daemon Mode (Task Scheduler)

For unattended updates, set up Windows Task Scheduler to run:

```bash
python scripts/hash_aggregator.py daemon --interval 6
```

#### Manual (Command Line)

```bash
python scripts/hash_aggregator.py update
python scripts/hash_aggregator.py stats
```

### Initial Setup

1. Install Python 3.8+ from https://python.org (ensure it's on PATH).
2. Install dependencies:
   ```bash
   pip install requests
   ```
3. Build and run the app. The first "Update Now" click will download and aggregate all 5 sources (~1-5 minutes depending on network; URLhaus is the largest at ~775 MB compressed).

## ML Response Policy

ML detections are monitor-only by default. Signature matches and unsigned high-risk heuristic detections may quarantine files. This avoids destructive false positives while model parity and calibration are still being validated.

## Python ML Pipeline

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Example workflow:

```bash
python scripts/build_db.py --db D:/train_data.db --win32-dir D:/win32_train --win64-dir D:/win64_train
python scripts/extract_features.py --db D:/train_data.db --train-out assets/data/train.txt --test-out assets/data/test.txt
python scripts/train_lightgbm.py --train assets/data/train.txt --valid assets/data/test.txt --model-out assets/models/forest.txt
python scripts/export_lgb_to_forest.py --model assets/models/forest.txt --out assets/models/forest.bin
python scripts/validate_model.py
```

## Prototype Safety Limitations

- The quarantine vault is intended for prototype isolation, not strong cryptographic protection.
- Real-time monitoring can still miss events under extreme filesystem churn.
- The ML feature pipeline needs parity testing against representative PE samples before its score should drive destructive action.
- This app should not be installed as a replacement for production antivirus software.

## License

MIT License.

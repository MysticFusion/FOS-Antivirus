# FOS-Antivirus

`C11` `GTK4` `SQLite3` `CMake` `Ninja` `MSYS2` `Python`

---

## Description

FOS-Antivirus is a free, open-source, **educational** endpoint-security prototype for Windows. It was built to demonstrate — in a single, readable codebase — how modern antivirus products actually work: signature matching against a large malware-hash database, static file analysis, heuristic scoring, machine-learning classification, real-time file monitoring, trust verification, and a quarantine/restore workflow — all wrapped in a native desktop application.

It is a learning tool and a research prototype. It is **not** a production antivirus product, and it should never be treated as a substitute for one.

---

## Functionalities

- **Full Scan** — recursive scan of any directory with an extension whitelist tuned for executable content.
- **Quick Scan** — focused scan of running processes, persistence points (Run keys, startup folders), and high-risk user directories with age-based filtering.
- **Real-Time Monitoring** — watches user-profile file changes for the creation or modification of suspicious files.
- **Tiered Detection Pipeline** —
  1. SHA-256 signature lookup against a SQLite database of **1.1M+ known malware hashes**;
  2. Rule-based **heuristic scoring** of file characteristics and behaviors;
  3. **Machine-learning classification** using a bundled decision-forest model built based on Ember 2024 PE Dataset;
  4. **AMSI script scanning** — script files (.ps1/.js/.vbs/.hta/...) are submitted to the OS's registered AMSI providers, so obfuscated script content is evaluated by the platform's script engines.
- **Digital Signature Trust** — evaluates file signatures (e.g., Microsoft-signed binaries) to reduce false positives.
- **Automatic Remediation** — quarantines detected threats into an isolated folder and keeps a full detection/quarantine history with restore support.
- **Signature Database Updates** — one-click in-app update that aggregates malware hashes from five public, no-authentication threat-intelligence sources (MalwareBazaar, URLhaus, ThreatFox, ESET malware-ioc, TweetFeed). The update pipeline is defense-in-depth: the aggregator script is SHA-256-pinned at build time, the Python interpreter must be Authenticode-signed by the Python Software Foundation, it runs with `-E` (environment isolation), and the resulting database is HMAC-SHA256-integrity-checked at load.
- **Native GTK4 Desktop UI** — dashboard, scan controls, settings, update management, and detection history.
- **Unit Test** — automated decision-policy test built alongside the main application.

## Non-Functionalities

FOS-Antivirus intentionally does **not** provide:

- Web, email, or network-traffic protection.
- Scheduled or background automatic scanning.
- Deep archive inspection (no unpacking of ZIP/RAR/ISO contents).
- Cloud-based or third-party threat-intelligence lookups at scan time.
- A cryptographically hardened quarantine vault (prototype isolation only).
- Protection against zero-day threats, advanced persistent threats, or targeted attacks.
- Support for any OS other than Windows (64-bit).
- Guaranteed event capture under extreme filesystem churn (real-time monitoring can miss events).
- Destructive auto-removal — ML-only detections are monitor-only by design, and no file is ever deleted silently.

---

## Tools & Technologies Utilized — and How

| Technology | Where / How It Is Used |
|---|---|
| **C11** | Entire application (engine, UI logic, Windows integration) is written in modern C. |
| **MSYS2 + MinGW-w64 (GCC)** | The official toolchain. Provides the Windows SDK headers/libs the project links against. |
| **CMake + Ninja** | Cross-platform build system and fast parallel build driver; `CMakeLists.txt` wires the whole project. |
| **GTK4 + GLib** | Desktop UI (sidebar, scan views, history, settings) and threading primitives (mutexes, thread pool, timers). |
| **SQLite3** | Signature database (`malware_hashes.db`) — fast SHA-256 lookups over 1.1M+ hashes; also uses WAL mode for safe concurrent access. |
| **Windows API** | File-system enumeration (`FindFirstFileEx`), real-time monitoring (`ReadDirectoryChangesW`), process image enumeration (`EnumProcesses`/`QueryFullProcessImageName`), known-folder resolution, threading and events. |
| **WinVerifyTrust / WinTrust** | Digital signature verification used to mark files signed by trusted vendors. |
| **SHA-256** | File hashing for signature lookups (bundled, dependency-free implementation). |
| **Decision Forest (ML)** | Lightweight native inference engine that scores files using a bundled gradient-boosted forest model (`forest.bin`) trained on PE-file features. |
| **Python 3** | The hash aggregator (`scripts/hash_aggregator.py`) — downloads, parses, and merges public malware-hash feeds into the SQLite database. |
| **Git / GitHub** | Version control and distribution of this open-source project. |

---

## How to Run This Project

> There is **no pre-built release yet** — the application must be built from source. This section covers prerequisites and the build/run flow for Windows 10/11 (64-bit).

### Prerequisites

| Requirement | Why | Install if missing |
|---|---|---|
| Windows 10/11 (64-bit) | Target platform | — |
| Git | Cloning the repository | https://git-scm.com/install/windows |
| MSYS2 | Toolchain + package manager | https://www.msys2.org/ |
| Python 3.8+ | Signature-database updates | https://www.python.org/downloads/ |

### 1. Install the build dependencies

Inside the **MSYS2 MINGW64** shell, install the required packages:

```bash
pacman -S --needed \
  mingw-w64-x86_64-gcc \
  mingw-w64-x86_64-cmake \
  mingw-w64-x86_64-ninja \
  mingw-w64-x86_64-gtk4 \
  mingw-w64-x86_64-pkgconf \
  mingw-w64-x86_64-sqlite3 \
  git
```

### 2. Install the Python dependency

```bash
python -m pip install requests
```

Make sure `python` is on your `PATH` (or let the app auto-detect a standard Python install location).

### 3. Clone the repository

```bash
git clone https://github.com/MysticFusion/FOS-Antivirus.git
cd FOS-Antivirus
```

### 4. Configure and build

```bash
cmake -B build -S . -G "Ninja" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The build automatically stages the ML model (`forest.bin`) and the Python aggregator script next to the executable.

### 5. Run

```bash
./build/FOS-Antivirus.exe
```

**First run:** go to **Settings** and click **Update Now** to download and aggregate the signature database (~1 GB). Scans work immediately for the bundled heuristics/ML model; signature hits require the database.

### Optional: run the tests

```bash
ctest --test-dir build --output-on-failure
```

or run the built binary directly: `./build/decision_policy_test.exe`

---

## ML Model: Training & Validation

The bundled decision forest (`assets/models/forest.bin`, custom binary `FORE`
format, 100 trees, 2381 EMBER-2024 features) is validated end-to-end before
shipping. The feature extractor in `src/engine/feature_extract.c` is pinned to
EMBER's exact algorithms (byte histogram, byte-entropy, import hashes, string
stats) by `tests/python/test_feature_parity.py`, so any model trained with the
pipeline below is guaranteed to score identically in C and Python.

### Re-training (requires the EMBER-style training corpus)

```bash
# 1. Build the training SQLite DB (per-row: label + hist256 + ent256 + imports
#    + scalars, mirroring EMBER-2024 fields). build_db.py is the reference.
python scripts/build_db.py

# 2. Extract the 2381-dim LIBSVM files (train.txt / test.txt)
python scripts/extract_features.py --db training.sqlite

# 3. Train the LightGBM model (text dump: forest.txt)
python scripts/train_lightgbm.py --train assets/data/train.txt --valid assets/data/test.txt

# 4. Convert to the C-inference FORE binary
python scripts/export_lgb_to_forest.py --model assets/models/forest.txt --out assets/models/forest.bin

# 5. Re-sign the model (Ed25519; the engine refuses unsigned models)
python scripts/sign_model.py

# 6. Validate: structure + C/Python parity on real binaries
python scripts/validate_model.py --scores-file build/ml_scores.json
ctest --test-dir build --output-on-failure   # includes security_test_ml_scores
```

Step 6's scores file comes from the C pipeline itself:

```bash
gcc -O1 -o ml_inference_harness.exe tests/security/ml_inference_harness.c \
  src/engine/ml_engine.c src/engine/feature_extract.c src/engine/ed25519_verify.c \
  src/utils/path_utils.c -Isrc/engine -Isrc/utils
./ml_inference_harness.exe assets/models/forest.bin \
  C:/Windows/System32/kernel32.dll C:/Windows/System32/cmd.exe --dump build/ml_scores.json
python scripts/validate_model.py --scores-file build/ml_scores.json
```

### Known calibration caveats

- ML scores are **not** calibrated to a 0.50 boundary; the production gate is
  `ML_SCORE_THRESHOLD = 0.8` (`src/engine/scan_executor.c`), and ML is only
  evaluated for `TRUST_NONE` files (`src/engine/scan_core.c`) — signed system
  binaries never reach the ML gate.
- The current shipped model scores benign DLLs low (0.1-0.3), system EXEs in
  the 0.3-0.7 zone, and has a positive prior on unknown inputs (random-vector
  mean ≈ 0.64). ML-only detections are monitor-only by design.

---

## Educational Disclaimer

**IMPORTANT — READ BEFORE USE**

FOS-Antivirus is a **research and educational project**. It is provided free of charge, as open-source software, **strictly for learning purposes** — to demonstrate how antivirus engines, file scanning, heuristics, machine-learning classification, real-time monitoring, and quarantine workflows function under the hood.

- This software is **not a production antivirus**, is **not certified** by any security organization, and provides **no guarantee of protection** against any threat.
- It may produce **false positives**, **false negatives**, and **unexpected behavior** — especially the heuristic and machine-learning components, which are experimental.
- The author(s) and contributors assume **no liability, in any shape or form**, for any loss, damage, system malfunction, data loss, or any other consequence arising from the use, modification, distribution, or misappropriation of this software.
- Use it **at your own risk**, ideally inside a virtual machine or a disposable test environment. Do not deploy it on systems that hold critical data.
- The malware-hash database aggregates indicators from third-party public sources; those sources may be incomplete, delayed, or inaccurate.

By cloning, building, or using FOS-Antivirus, you acknowledge that you have read and understood this disclaimer and that you accept full responsibility for your own use of the software.

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for the full text. Free to use, modify, and distribute, with the author holding no liability.

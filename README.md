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
  3. **Machine-learning classification** using a bundled decision-forest model.
- **Digital Signature Trust** — evaluates file signatures (e.g., Microsoft-signed binaries) to reduce false positives.
- **Automatic Remediation** — quarantines detected threats into an isolated folder and keeps a full detection/quarantine history with restore support.
- **Signature Database Updates** — one-click in-app update that aggregates malware hashes from five public, no-authentication threat-intelligence sources (MalwareBazaar, URLhaus, ThreatFox, ESET malware-ioc, TweetFeed).
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
| Git | Cloning the repository | https://git-scm.com/download/win |
| MSYS2 | Toolchain + package manager | https://www.msys2.org/ (install, then open the **MSYS2 MINGW64** shell) |
| Python 3.8+ | Signature-database updates (optional but recommended) | https://www.python.org/downloads/ |

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

### 2. Install the Python dependency (optional)

Only needed if you want the app's "Update Now" feature to work:

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

**First run:** go to **Settings** and click **Update Now** to download and aggregate the signature database (1–5 minutes, depending on your connection — the largest feed is ~775 MB compressed). Scans work immediately for the bundled heuristics/ML model; signature hits require the database.

### Optional: run the tests

```bash
ctest --test-dir build --output-on-failure
```

or run the built binary directly: `./build/decision_policy_test.exe`

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

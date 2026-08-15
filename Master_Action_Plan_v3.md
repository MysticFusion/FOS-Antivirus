# Master Action Plan (MAP) v3

**Project:** FOS-Antivirus  
**Date:** 2026-08-04  
**Authors:** Unified Security & Architecture Review (Merged from independent code-only analyses)  
**Objective:** Dissect all identified vulnerabilities, operability gaps, and architectural deficiencies discovered during the read-only code review, and prescribe industry-standard resolutions. 

---

## Table of Contents

1. [Legend](#1-legend)
2. [Issue Tracking Matrix](#2-issue-tracking-matrix)
3. [Detailed Issue Dissections & Resolutions](#3-detailed-issue-dissections--resolutions)
   - [Phase 0: Active Operability Bugs (P0)](#phase-0-active-operability-bugs-p0)
     - [U-01: Aggregator Error Handler Discards Python Tracebacks](#u-01-aggregator-error-handler-discards-python-tracebacks)
     - [U-02: Broken Stdout Pipe Causes OSError [Errno 22]](#u-02-broken-stdout-pipe-causes-oserror-errno-22)
   - [Phase 1: Critical Security & Memory Safety (P0/P1)](#phase-1-critical-security--memory-safety-p0p1)
     - [U-03: TOCTOU Race in Process & Persistence Scanning](#u-03-toctou-race-in-process--persistence-scanning)
     - [U-04: TOCTOU Race in Filesystem Enumeration](#u-04-toctou-race-in-filesystem-enumeration)
     - [U-05: Buffer Overflow Risk in Process Module Enumeration](#u-05-buffer-overflow-risk-in-process-module-enumeration)
     - [U-06: Python Interpreter Hijacking in Update Pipeline](#u-06-python-interpreter-hijacking-in-update-pipeline)
   - [Phase 2: High Severity Evasion & DoS (P1)](#phase-2-high-severity-evasion--dos-p1)
     - [U-07: Ransomware Tracker Array Exhaustion (DoS)](#u-07-ransomware-tracker-array-exhaustion-dos)
     - [U-08: Real-Time Monitor Extension Blindness](#u-08-real-time-monitor-extension-blindness)
     - [U-09: Custom HKDF-GCM Streaming Complexity](#u-09-custom-hkdf-gcm-streaming-complexity)
     - [U-10: Missing AMSI / Script Coverage](#u-10-missing-amsi--script-coverage)
   - [Phase 3: Cryptographic & Pipeline Integrity (P1/P2)](#phase-3-cryptographic--pipeline-integrity-p1p2)
     - [U-11: Unverified Download Integrity (Short Reads)](#u-11-unverified-download-integrity-short-reads)
     - [U-12: HMAC Computed Over WAL Database (State Divergence)](#u-12-hmac-computed-over-wal-database-state-divergence)
     - [U-13: Machine-Bound DB HMAC Key (Local Forgery Risk)](#u-13-machine-bound-db-hmac-key-local-forgery-risk)
     - [U-14: History Log Path Traversal (Partially Mitigated)](#u-14-history-log-path-traversal-partially-mitigated)
   - [Phase 4: Medium Hardening & Code Quality (P2)](#phase-4-medium-hardening--code-quality-p2)
     - [U-15: FNV-1a Hash Collision in Signature Table](#u-15-fnv-1a-hash-collision-in-signature-table)
     - [U-16: Unpinned Python Dependencies (Supply Chain Risk)](#u-16-unpinned-python-dependencies-supply-chain-risk)
     - [U-17: Unsanitized SQL Identifiers in build_db.py](#u-17-unsanitized-sql-identifiers-in-build_dbpy)
     - [U-18: Path-Based Trust Heuristic Instead of Cert Publisher Check](#u-18-path-based-trust-heuristic-instead-of-cert-publisher-check)
   - [Phase 5: Low Priority / Backlog (P3)](#phase-5-low-priority--backlog-p3)
4. [Implementation Priority & Sequencing](#4-implementation-priority--sequencing)
5. [Implementation Record & Residual Scope (2026-08-15)](#5-implementation-record--residual-scope-2026-08-15)

---

## 1. Legend

- **ID:** Unique identifier for the action item (U-XX).
- **Severity:** 
  - `Critical`: Actively breaks functionality or introduces severe security risk.
  - `High`: Major operability degradation, evasion path, or significant security gap.
  - `Medium`: Logic flaw, performance issue, or moderate security risk.
  - `Low`: Code quality, maintainability, or minor portability issue.
- **Priority:** 
  - `P0`: Immediate (Fix in next build).
  - `P1`: High (Fix in current sprint).
  - `P2`: Medium (Schedule for next milestone).
  - `P3`: Low (Backlog).
- **Status:** `Open`, `In Progress`, `Resolved`, `Won't Fix`
- **CWE:** Common Weakness Enumeration reference.

---

## 2. Issue Tracking Matrix

> **Status update — 2026-08-15.** All actionable MAPv3 items are implemented
> and verified by the extended CTest suite (15 targets: 13 C + 2 Python-
> related where available). Residual scope notes are recorded per item and
> consolidated in §5 below.

| ID | Title | Severity | Priority | CWE | Status |
|:---|:------|:---------|:---------|:----|:-------|
| U-01 | Aggregator error handler discards Python tracebacks | High | P0 | N/A | **Resolved** (`emit_source_fail(exc_info=)` + `logger.exception`; regression test `test_hash_aggregator_pipe.py`, now in CTest) |
| U-02 | Broken stdout pipe causes `OSError [Errno 22]` | High | P0 | N/A | **Resolved** (`_emit` catches `BrokenPipeError/OSError`; same regression test) |
| U-03 | TOCTOU race in process & persistence scanning | Critical | P0 | CWE-367 | **Resolved** (`fos_open_canonical` handle-derived paths in both scanners; `unit_test_toctou`) |
| U-04 | TOCTOU race in filesystem enumeration | Critical | P0 | CWE-367 | **Resolved** (immediate open + reparse decision from the handle in `fs_enumerator.c`) |
| U-05 | Buffer overflow risk in process module enumeration | Critical | P1 | CWE-120 | **Resolved** (`GetModuleFileNameExW` + geometric buffer growth to `FOS_MAX_PATH`) |
| U-06 | Python interpreter hijacking in update pipeline | Critical | P1 | CWE-426 | **Resolved** (Authenticode + PSF signer-subject gate; hardened further: `-E` env isolation, scripts-dir module-shadowing check, timeout kill — see §5 PR-1..PR-4) |
| U-07 | Ransomware tracker array exhaustion (DoS) | High | P1 | CWE-770 | **Resolved*** (growable slot tables, 64 → 65536 with oldest-eviction; per-PID quota deferred — see §5) |
| U-08 | Real-time monitor extension blindness | High | P1 | CWE-693 | **Resolved** (RT allowlist mirrors `scan_core`'s 25-extension list) |
| U-09 | Custom HKDF-GCM streaming complexity | High | P1 | CWE-327 | **Resolved** (single-shot CNG GCM; explicit 500 MB body cap on quarantine + restore) |
| U-10 | Missing AMSI / script coverage | High | P1 | CWE-693 | **Resolved*** (AMSI *client* integration: script files submitted to registered providers via `AmsiScanBuffer`; provider registration out of scope — see §5) |
| U-11 | Unverified download integrity (short reads) | Medium | P1 | N/A | **Resolved** (`downloaded == Content-Length` check before `tmp.replace`) |
| U-12 | HMAC computed over WAL database (state divergence) | Medium | P1 | N/A | **Resolved** (`PRAGMA wal_checkpoint(TRUNCATE)` before close; deterministic even if close-time checkpointing changes) |
| U-13 | Machine-bound DB HMAC key (local forgery risk) | Medium | P2 | N/A | **Resolved** (user-bound primary key; legacy machine-bound key accepted for verify only, migrating on next update) |
| U-14 | History log path traversal (partially mitigated) | High | P2 | CWE-22 | **Resolved*** (handle-based canonicalization: `.vir` opened no-follow, restore-dest parent resolved via `GetFinalPathNameByHandleW`; `FOS_MAX_PATH` buffers; residual window documented in code) |
| U-15 | FNV-1a hash collision in signature table | Medium | P2 | CWE-328 | **Resolved** (keyed SipHash-2-4, per-process CSPRNG key, fail-closed) |
| U-16 | Unpinned Python dependencies (supply chain risk) | Medium | P2 | N/A | **Resolved** (exact `==` pins incl. previously-missing `requests`/`cryptography`; `--generate-hashes` deferred — see §5) |
| U-17 | Unsanitized SQL identifiers in `build_db.py` | Low-Med | P2 | CWE-89 | **Resolved** (identifier regex validation on table + all column names) |
| U-18 | Path-based trust heuristic instead of cert publisher check | Low-Med | P2 | N/A | **Resolved** (signer-subject extraction; `TRUST_HIGH` = "Microsoft Windows"/"Microsoft Corporation" publishers, path no longer grants HIGH) |
| U-19 | Performance bottleneck from VACUUM in update pipeline | Low | P3 | N/A | **Resolved** (`auto_vacuum=INCREMENTAL` + `PRAGMA incremental_vacuum`) |
| U-20 | Vendored cryptography (maintenance & audit burden) | Low | P3 | N/A | **Won't Fix** (see §5) |
| U-21 | Inert application self-updater | Low | P3 | N/A | **Won't Fix** (see §5) |

---

## 3. Detailed Issue Dissections & Resolutions

### Phase 0: Active Operability Bugs (P0)

#### U-01: Aggregator Error Handler Discards Python Tracebacks
- **Evidence:** In `scripts/hash_aggregator.py` (lines 362, 1088), the catch-all exception handler formats the error into a one-liner and calls `logger.error(...)` without passing `exc_info=True`. This is why the user's log showed `OSError: [Errno 22]` but no stack trace to identify the exact syscall.
- **Industry Standard Approach:** Security and operability tooling must log full stack traces for unexpected exceptions to enable rapid root-cause analysis. Python's native `logging` module supports this natively.
- **Resolution:** 
  1. Modify `emit_source_fail` to accept an optional `exc_info` parameter.
  2. In the `run_update` orchestrator catch-all, use `logger.exception()` before formatting the one-liner for the UI JSONL pipe.
  ```python
  # hash_aggregator.py
  except Exception as e:
      logger.exception(f"Source {adapter.name} raised") # Logs full traceback to updater.log
      try: conn.rollback()
      except sqlite3.OperationalError: pass
      emit_source_fail(adapter.name, f"unexpected error: {type(e).__name__}: {e}")
  ```

#### U-02: Broken Stdout Pipe Causes `OSError [Errno 22]`
- **Evidence:** In `scripts/hash_aggregator.py` (line 325), `_emit()` calls `print(json.dumps(event), flush=True)`. The C application merges stderr and stdout into one pipe. If the C app's reading thread stalls or the pipe breaks during the 42MB MalwareBazaar download, Windows `WriteFile` surfaces in CPython as `OSError: [Errno 22] Invalid argument`, killing the source.
- **Industry Standard Approach:** Child processes communicating via stdout/stderr pipes must be resilient to `BrokenPipeError` and Windows-specific pipe `OSError` variants. The child should silently drop progress events if the parent goes away, rather than crashing the data pipeline.
- **Resolution:** Wrap the `print` call in `_emit()` with a specific exception handler.
  ```python
  # hash_aggregator.py
  def _emit(event: dict):
      event["ts"] = datetime.now(timezone.utc).isoformat()
      try:
          print(json.dumps(event), flush=True)
      except (BrokenPipeError, OSError):
          # Parent process pipe is gone/broken; continue aggregation silently
          pass
  ```

### Phase 1: Critical Security & Memory Safety (P0/P1)

#### U-03: TOCTOU Race in Process & Persistence Scanning
- **Evidence:** In `src/engine/scan_processes.c` and `src/engine/scan_persistence.c` (`add_path_if_unique()`), the code checks `GetFileAttributesA(path)` and later the scanner opens the file. A malicious process can swap the file (e.g., to a junction) in that microsecond window, causing the scanner to hash the wrong file.
- **Industry Standard Approach:** Atomic Open + Handle-Based Operations (Microsoft SDL). Do not defer file operations. 
- **Resolution:** Open the file **immediately** upon extracting the path using `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT`. Pass the `HANDLE` (or a duplicated handle) to the scanning engine. If the engine requires a path string, use `GetFinalPathNameByHandleW` to obtain a stable path after opening.

#### U-04: TOCTOU Race in Filesystem Enumeration
- **Evidence:** In `src/engine/fs_enumerator.c` (`walk_recursive_wide`), the enumerator skips reparse points **at discovery time**, but the callback opens the file **much later**. Between `FindFirstFileExW` and `CreateFileW`, an attacker can convert a normal directory to a junction pointing to `C:\Windows\System32`.
- **Industry Standard Approach:** O_PATH-style Handle Passing + Re-open Validation.
- **Resolution:** Instead of skipping reparse points entirely, open every file/directory immediately with `CreateFileW` + `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`. Pass the `HANDLE` through the callback chain. Before hashing, call `GetFinalPathNameByHandleW` to verify the path has not changed.

#### U-05: Buffer Overflow Risk in Process Module Enumeration
- **Evidence:** In `src/engine/scan_processes.c` (`enumerate_process_modules()`), `GetModuleFileNameExA` is used with a `char module_path[MAX_PATH]` buffer. On modern Windows with long-path support, a module path can exceed 260 characters. The ANSI function will silently truncate, and may fail to null-terminate, causing out-of-bounds reads in subsequent `_strlwr_s` and `g_hash_table` operations.
- **Industry Standard Approach:** Always Use Wide APIs + Dynamic Allocation.
- **Resolution:** Replace `GetModuleFileNameExA` with `GetModuleFileNameExW`. Use a dynamically allocated buffer (or `wchar_t *buf = malloc(FOS_MAX_PATH * sizeof(wchar_t))`). Pass the wide path directly to the scanner using `compute_file_sha256_wide`.

#### U-06: Python Interpreter Hijacking in Update Pipeline
- **Evidence:** In `src/engine/signature_scan.c` (lines 302-335), the updater searches `PATH` and known directories for `python.exe`. While the `hash_aggregator.py` script is SHA-256 pinned, the interpreter executing it is not verified. An attacker who modifies `PATH` can force the AV to execute a malicious `python.exe` with the AV's privileges.
- **Industry Standard Approach:** Subprocess Isolation + Binary Verification.
- **Resolution:** As an immediate mitigation, use `WinVerifyTrust` on the resolved `python.exe` path to ensure it is digitally signed by the Python Software Foundation before executing it. Long-term, bundle a pinned, standalone Python runtime within the application directory.

### Phase 2: High Severity Evasion & DoS (P1)

#### U-07: Ransomware Tracker Array Exhaustion (DoS)
- **Evidence:** In `src/engine/ransomware_signals.c`, the `rw_tracker_t` struct uses fixed arrays (`rename_slot_t rename_old[RW_RENAME_SLOTS]` where `RW_RENAME_SLOTS` is 64). A benign process (like `git checkout` or a compiler) or an attacker can easily generate >64 unmatched rename-old events within the 10-second window, filling the array. The tracker then misses the actual ransomware extension rewrite.
- **Industry Standard Approach:** Dynamic Allocation + Per-Process Quotas.
- **Resolution:** Replace fixed arrays with hash maps (e.g., `GHashTable`) keyed by `FileId`. Implement per-process rate limiting by obtaining the `PID` responsible for the file event (via `NtQueryInformationFile` or ETW) and capping each process to N rename events per second.

#### U-08: Real-Time Monitor Extension Blindness
- **Evidence:** In `src/engine/rt_monitor.c` (`is_interesting_file()`), the extension allowlist is heavily restricted: `.exe`, `.dll`, `.sys`, `.scr`, `.js`, `.vbs`. It is missing primary malware delivery vectors like `.ps1`, `.bat`, `.cmd`, `.hta`, `.jar`, `.py`, `.docm`, `.xlsm`.
- **Industry Standard Approach:** Behavioral-First Filtering + Extension Allowlist.
- **Resolution:** Add the missing extensions. Furthermore, for script extensions, read the first 8 KB and scan for suspicious patterns (e.g., `-enc`, `FromBase64String`, `Invoke-Expression`).

#### U-09: Custom HKDF-GCM Streaming Complexity
- **Evidence:** In `src/engine/response_engine.c` (`gcm_encrypt_stream()`), the code implements manual chunked GCM using `BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG`. This is correct but extremely fragile. CNG's chained GCM is poorly documented, and off-by-one errors in alignment or flag handling can silently corrupt authentication.
- **Industry Standard Approach:** Use Established High-Level Crypto Libraries.
- **Resolution:** Replace custom streaming with libsodium's `crypto_secretstream_xchacha20poly1305`, which handles chunking and tagging automatically. Alternatively, since quarantined files are typically small, load the entire file into memory and encrypt in a single `BCryptEncrypt` call to eliminate streaming complexity.

#### U-10: Missing AMSI / Script Coverage
- **Evidence:** No AMSI (Antimalware Scan Interface) integration is present. Without it, the AV is blind to fileless PowerShell, encoded commands, and in-memory .NET assemblies.
- **Industry Standard Approach:** Native AMSI Integration.
- **Resolution:** Implement `AmsiInitialize`, `AmsiOpenSession`, and `AmsiScanBuffer`. Register the AV as an AMSI provider to scan all PowerShell, VBScript, JScript, and Office macro execution via AMSI callbacks.

### Phase 3: Cryptographic & Pipeline Integrity (P1/P2)

#### U-11: Unverified Download Integrity (Short Reads)
- **Evidence:** In `scripts/hash_aggregator.py` (`download_to_file`, lines 461-484), the function streams chunks to a file but never checks if `downloaded == total` (from `Content-Length`) before moving the temp file.
- **Industry Standard Approach:** Network downloads must validate payload completeness before processing.
- **Resolution:** Add a post-loop validation check before `tmp.replace(dest)`.
  ```python
  # hash_aggregator.py
  if total > 0 and downloaded != total:
      raise DownloadError(f"short read: {downloaded}/{total} bytes")
  tmp.replace(dest)
  ```

#### U-12: HMAC Computed Over WAL Database (State Divergence)
- **Evidence:** The DB is opened in WAL mode (`hash_aggregator.py` line 502), but the C-side HMAC (`db_hmac.c` line 76) computes the hash over `malware_hashes.db` only. If the Python script hasn't checkpointed the WAL file, the logical DB state diverges from the physical `.db` file, causing HMAC verification to fail or miss recent insertions.
- **Industry Standard Approach:** Before computing an HMAC over a SQLite database, ensure all WAL frames are flushed.
- **Resolution:** Execute a truncating checkpoint in Python before closing the connection after an update.
  ```python
  # hash_aggregator.py, inside Aggregator.run_update() before conn.close()
  conn.commit()
  conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
  conn.close()
  ```

#### U-13: Machine-Bound DB HMAC Key (Local Forgery Risk)
- **Evidence:** In `src/engine/db_hmac.c` (lines 55-58), the DPAPI call uses `CRYPTPROTECT_LOCAL_MACHINE`. This binds the key to the machine SID, meaning any process running on that machine can derive the same key and forge a valid HMAC after tampering with the DB.
- **Industry Standard Approach:** Integrity keys for user-space security applications should be bound to the user profile to elevate the barrier for local tampering.
- **Resolution:** Remove `CRYPTPROTECT_LOCAL_MACHINE` from the `CryptProtectData` call. 

#### U-14: History Log Path Traversal (Partially Mitigated)
- **Evidence:** In `src/ui/ui_history.c` (`canonicalize_path()`), `GetFullPathNameA` resolves `..` but does **not** resolve symbolic links or junctions. An attacker can place a junction at `C:\Users\Victim\Quarantine\..\..\Windows` that resolves to a benign-looking path, but `restore_file_from_quarantine` later follows the junction. Also, `MAX_PATH` (260) is used instead of `FOS_MAX_PATH`.
- **Industry Standard Approach:** Canonicalization via Handle + Strict Prefix Validation.
- **Resolution:** Open the file with `CreateFileA` + `FILE_FLAG_OPEN_REPARSE_POINT`, then call `GetFinalPathNameByHandleA` to obtain the true, symlink-resolved path. Verify the path starts with the known quarantine directory prefix. Replace `MAX_PATH` buffers with `FOS_MAX_PATH`.

### Phase 4: Medium Hardening & Code Quality (P2)

#### U-15: FNV-1a Hash Collision in Signature Table
- **Evidence:** In `src/engine/hash_util.c` (`fnv1a_hash()`), FNV-1a is used for hash table bucket indexing. While a `memcmp` saves it from false positives, an attacker can craft a database that floods a single bucket, degrading O(1) lookup to O(n) (Hash Flooding DoS).
- **Industry Standard Approach:** Cryptographic Hash for Table Indexing.
- **Resolution:** Replace FNV-1a with SipHash-2-4 (resistant to hash flooding) using a random 128-bit key generated at process start.

#### U-16: Unpinned Python Dependencies (Supply Chain Risk)
- **Evidence:** `requirements.txt` contains unpinned package names (`lightgbm`, `mmh3`, `numpy`, `tqdm`, `orjson`).
- **Industry Standard Approach:** Dependencies must be pinned to exact versions and hashed to prevent dependency confusion attacks.
- **Resolution:** Generate a locked `requirements.txt` with exact versions and hashes (`pip-compile --generate-hashes`).

#### U-17: Unsanitized SQL Identifiers in `build_db.py`
- **Evidence:** In `scripts/build_db.py` (lines 32-65), JSONL key names are directly interpolated into SQL `CREATE TABLE` and `ALTER TABLE` statements via f-strings. A malformed JSONL key containing `"` could break out of the identifier context.
- **Industry Standard Approach:** Never trust external data for SQL identifiers.
- **Resolution:** Implement an identifier sanitizer: `if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name): raise ValueError(...)`.

#### U-18: Path-Based Trust Heuristic Instead of Cert Publisher Check
- **Evidence:** In `src/engine/trust.c` (lines 67-77), a file is granted `TRUST_HIGH` if it has a valid Authenticode signature *and* its path is under `FOLDERID_Windows`. Path location does not dictate the signer.
- **Industry Standard Approach:** Trust must be derived strictly from the certificate chain.
- **Resolution:** Use `WinVerifyTrust` to extract the signer certificate, then validate the publisher name against trusted publishers (e.g., "Microsoft Windows").

### Phase 5: Low Priority / Backlog (P3)

#### U-19: Performance Bottleneck from VACUUM in Update Pipeline
- **Evidence:** In `hash_aggregator.py` (line 1093), `conn.execute("VACUUM")` is called after every update on a 1.1M-row database inside the same connection, causing I/O blocking.
- **Resolution:** Remove the unconditional `VACUUM`. Set `PRAGMA auto_vacuum = INCREMENTAL` during `init_db`, and run `PRAGMA incremental_vacuum` conditionally.

#### U-20: Vendored Cryptography (Maintenance & Audit Burden)
- **Evidence:** `src/engine/ed25519_verify.c` and `sha2.c` are vendored implementations. While well-vetted, rolling custom crypto increases maintenance burden.
- **Resolution:** Migrate `sha2.c` to `BCryptHash` (CNG) and `ed25519_verify.c` to `NCrypt` or a statically linked, audited library like libsodium.

#### U-21: Inert Application Self-Updater
- **Evidence:** `src/app/auto_update.c` is explicitly an inert stub. Only the signature DB updates; the C application itself cannot be updated.
- **Resolution:** Implement the server-side manifest generation and the client-side fetch/verify/swap pipeline using Ed25519 signatures.

---

## 4. Implementation Priority & Sequencing

1. **Immediate Operability Fix (P0):** Address U-01 and U-02 immediately. These are actively preventing the user from updating the signature database and diagnosing the error. 
2. **Critical Security Remediation (P0/P1):** Address U-03, U-04, U-05, and U-06. These TOCTOU races and buffer overflows are exploitable and represent the highest security risk.
3. **Evasion & DoS Hardening (P1):** Address U-07, U-08, U-09, and U-10. These close ransomware evasion paths and script-blindness gaps.
4. **Pipeline & Crypto Integrity (P1/P2):** Address U-11, U-12, U-13, and U-14. These ensure the update pipeline is robust and the database integrity model holds up under WAL.
5. **Code Quality & Maintenance (P2/P3):** Address U-15 through U-21 as part of long-term project health.

---

## 5. Implementation Record & Residual Scope (2026-08-15)

### 5.1 Post-review findings (discovered during implementation, all fixed)

| ID | Finding | Resolution |
|:---|:--------|:-----------|
| PR-1 | **Update pipeline fully broken:** the MAP-12 refactor of `update_signature_db` dropped `python_w` from the `_snwprintf_s` command-line format (3 `%s`, 2 args). Argv shifted → the aggregator's argparse rejected the invocation → every "Update Now" failed with `UPDATE_ERR_PYTHON_FAILED`, plus undefined behavior reading the third vararg. | Argument restored; command line now `"<python>" -E "<script>" --db "<db>" update`. |
| PR-2 | **Update timeout leaked the child:** on `WAIT_TIMEOUT` the handles were closed but the orphaned `python.exe` kept running while holding the aggregator's cross-process `FileLock`, wedging all later updates. | `TerminateProcess` + wait before closing handles. |
| PR-3 | **`PYTHONPATH` hijack of the signed interpreter:** `CreateProcessW(..., lpEnvironment=NULL)` inherited the AV's user-influenceable environment; a fake `requests` package would execute inside a perfectly valid PSF-signed python.exe. | `-E` flag (ignores all `PYTHON*` variables; available on every Python 3, unlike `-I`/`-P` which are 3.11+). |
| PR-4 | **Script-dir module shadowing:** Python prepends the script's directory to `sys.path`; a planted `scripts\json.py` is imported *instead of* the stdlib module and is not covered by the I-19 script pin. | New `verify_scripts_dir_clean()` gate: the staged `scripts\` directory must contain no `.py` module other than `hash_aggregator.py` (`UPDATE_ERR_SCRIPT_DIR_DIRTY`). |
| PR-5 | **`unit_test_toctou` junction fixture rejected by current Windows 11:** `FSCTL_SET_REPARSE_POINT` returns `ERROR_INVALID_REPARSE_DATA` (4392) unless each name in the mount-point buffer is followed by a NUL wchar *outside* its declared length (`ReparseDataLength = 8 + subst + 2 + print + 2`). Verified byte-for-byte against what `mklink /J` writes. | Buffer layout fixed (junction creation verified working); test 3 also made self-contained (it previously depended on the junction surviving test 2's `tearDown`). |
| PR-6 | **Threshold drift:** heuristic engine classified ≥45 as SUSPICIOUS while the decision engine required ≥50 to MONITOR; the double-extension re-derivation used a third copy of the numbers. | Single source of truth: `HEURISTIC_SCORE_MALICIOUS`/`HEURISTIC_SCORE_SUSPICIOUS` in `heuristic_engine.h`. |
| PR-7 | **`test_model_signature.c` hard-coded `D:\Experiment\FOS-Antivirus\...`** — failed on every other checkout of this public repository. | Assets dir passed via CTest argument / argv fallback. |
| PR-8 | Misc: SQLite URI built from raw paths (`?`/`#`/`%` could alter `mode=ro`); manual-update dialog singleton could be clobbered by a second click (and never released on the error path); signature-matched files skipped the `files_scanned` counter; aggregator `FileLock.release()` unlinked the lock file after unlocking (re-acquire/unlink race). | All fixed alongside the related MAP items. |

### 5.2 Residual scope (documented, accepted)

- **U-07 (partial):** slots now grow to 65,536 entries with oldest-eviction, which is far beyond any observed benign bulk-rename storm and keeps memory bounded (~3.7 MB/table). The MAP's *per-process* quota requires attributing file events to PIDs (ETW or a minifilter — kernel components outside this prototype's scope). Revisit if real-time telemetry is added.
- **U-10 (client-side):** script content is submitted to the OS's registered AMSI providers via `AmsiScanBuffer` (`src/engine/amsi_scan.c`), with provider detections scored as malicious (trust-dampened, so signed detections monitor rather than quarantine). Registering FOS itself as an AMSI *provider* requires a COM `DllRegisterServer` + `HKLM\SOFTWARE\Microsoft\AMSI\Providers` registration and an elevation-aware installer — deferred until the project ships an installer.
- **U-14 (residual window):** both history paths are canonicalized from handles at validation time, but restore later re-opens by path, so a junction swapped into the chain *between validation and write* could still redirect the restore. Fully closing it requires handle-passing through `response_restore_file`; the window and rationale are documented at the validation site.
- **U-16 (pins without hashes):** versions are exactly pinned (including the previously-missing `requests` and `cryptography`). Full `pip-compile --generate-hashes` locking is deferred until the training environment is containerized/CI-reproducible.
- **U-18:** trust extraction now uses the signer certificate, but the publisher allow-list is the two Microsoft production subjects. Extending it to a configurable trusted-publisher list is a product decision, not a code fix.

### 5.3 Won't Fix (with rationale)

- **U-20 — vendored `sha2.c` / `ed25519_verify.c`:** both are reference implementations pinned by known-answer tests (`unit_test_hash`, `test_model_signature`), and `db_hmac`/`script_verify`/`hash_util` are built around their incremental API. Migrating to CNG/NCrypt would re-plumb three modules and their KAT harnesses for no attacker-facing gain in this prototype's threat model (the vendored code verifies *local* artifacts, it does not need to resist a hostile cryptanalytic environment). Revisit if the project adopts libsodium for other reasons.
- **U-21 — application self-updater:** there is no update server, manifest distribution channel, or release pipeline; an updater with nothing to update is pure attack surface. The signature-DB update path (pinned script + PSF-signed interpreter + HMAC'd database) covers the threat-intel lifecycle. Revisit when a release channel exists.
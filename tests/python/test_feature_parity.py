#!/usr/bin/env python3
"""
test_feature_parity.py -- C vs Python feature-extraction parity tests.

Builds the real C extractor (src/engine/feature_extract.c) into a tiny
helper, then compares its output against an independent numpy/mmh3
reference implementation of the same, format-agnostic features:

  1. Byte histogram (vec[0:256], L1-normalized counts)
  2. EMBER 2D byte-entropy histogram (vec[256:512], 16x16 -> 256 dims)
  3. File-scope scalars (file size, entropy, string statistics)
  4. MurmurHash3 x86_32 with seed 0 (exact signed int32 match to mmh3)

The byte-entropy reference below is a direct port of EMBER's
ByteEntropyHistogram (https://github.com/elastic/ember), the same source
that produced the training-side EMBER JSONL features.

Requirements: gcc (MinGW), numpy, mmh3.
Run:          python tests/python/test_feature_parity.py
"""

import math
import os
import random
import subprocess
import sys
import tempfile

import mmh3
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HELPER_SRC = os.path.join(ROOT, "tests", "python", "feature_parity_helper.c")
EXTRACT_SRC = os.path.join(ROOT, "src", "engine", "feature_extract.c")
ENGINE_INC = os.path.join(ROOT, "src", "engine")

WINDOW = 2048
STEP = 1024

failures = 0


def check(name, cond, detail=""):
    global failures
    safe = lambda s: s.encode("ascii", "backslashreplace").decode("ascii")
    print(f"[{'PASS' if cond else 'FAIL'}] {safe(name)}" + (f" -- {safe(detail)}" if detail else ""))
    if not cond:
        failures += 1


# ---------------------------------------------------------------------------
# Reference implementations (independent of the C code)
# ---------------------------------------------------------------------------

def ref_byte_histogram(raw):
    counts = np.bincount(np.frombuffer(raw, dtype=np.uint8), minlength=256)
    return counts.astype(np.float64) / float(len(raw))


def ref_entropy_bin_counts(block):
    """EMBER _entropy_bin_counts: coarse 16-bin nibble histogram; note the
    probability denominator is always the window size, even for files
    smaller than the window (reference-implementation quirk)."""
    c = np.bincount(block >> 4, minlength=16)
    p = c.astype(np.float32) / WINDOW
    wh = np.where(c)[0]
    H = float(np.sum(-p[wh] * np.log2(p[wh]))) * 2.0
    Hbin = int(H * 2.0)
    if Hbin == 16:
        Hbin = 15
    return Hbin, c


def ref_byte_entropy(raw):
    """EMBER ByteEntropyHistogram.raw_features + L1 normalization."""
    output = np.zeros((16, 16), dtype=np.int64)
    a = np.frombuffer(raw, dtype=np.uint8)
    if a.shape[0] < WINDOW:
        Hbin, c = ref_entropy_bin_counts(a)
        output[Hbin, :] += c
    else:
        for i in range(0, a.shape[0] - WINDOW + 1, STEP):
            Hbin, c = ref_entropy_bin_counts(a[i : i + WINDOW])
            output[Hbin, :] += c
    counts = output.flatten().astype(np.float64)
    s = counts.sum()
    return counts / s if s > 0 else counts


def ref_strings(raw):
    """Port of analyze_strings() from feature_extract.c (runs of 32..126)."""
    MIN_LEN = 4
    current_len = 0
    total_len_all = 0
    num_strings = 0.0
    printables = 0.0
    paths = 0.0
    urls = 0.0
    reg = 0.0

    def end_run(start, length):
        nonlocal num_strings, total_len_all, paths, urls, reg
        if length >= MIN_LEN:
            num_strings += 1.0
            total_len_all += length
            s = raw[start : start + length]
            if length > 7 and (
                s.startswith(b"http://") or s.startswith(b"https://")
            ):
                urls += 1.0
            if length > 3 and (
                (s[0:1].isalpha() and s[1:2] == b":" and s[2:3] == b"\\")
                or s[0:1] == b"/"
            ):
                paths += 1.0
            if length > 5 and s.startswith(b"HKEY_"):
                reg += 1.0

    run_start = 0
    for i, c in enumerate(raw):
        if 32 <= c <= 126:
            if current_len == 0:
                run_start = i
            current_len += 1
            printables += 1.0
        else:
            if current_len >= MIN_LEN:
                end_run(run_start, current_len)
            current_len = 0
    if current_len >= MIN_LEN:
        end_run(run_start, current_len)

    avg = total_len_all / num_strings if num_strings > 0 else 0.0
    return {
        2311: num_strings,
        2312: avg,
        2313: printables,
        2315: paths,
        2316: urls,
        2317: reg,
    }


def ref_file_entropy(raw):
    counts = np.bincount(np.frombuffer(raw, dtype=np.uint8), minlength=256)
    ent = 0.0
    n = float(len(raw))
    for c in counts:
        if c > 0:
            p = c / n
            ent -= p * math.log2(p)
    return ent


# ---------------------------------------------------------------------------
# C helper
# ---------------------------------------------------------------------------

def build_helper(tmpdir):
    exe = os.path.join(tmpdir, "feature_parity_helper.exe")
    cmd = [
        "gcc",
        "-O2",
        "-Wall",
        "-Wextra",
        "-DFOS_FEATURE_TEST_EXPORTS",
        f"-I{ENGINE_INC}",
        "-o",
        exe,
        HELPER_SRC,
        EXTRACT_SRC,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        sys.exit(f"failed to build feature_parity_helper: {proc.stderr}")
    return exe


def c_hist(helper, path):
    proc = subprocess.run(
        [helper, "--hist", path], capture_output=True, text=True
    )
    if proc.returncode != 0:
        return None
    vec = {}
    for line in proc.stdout.splitlines():
        idx, val = line.split()
        vec[int(idx)] = float(val)
    return vec


def c_hashes(helper, strings):
    proc = subprocess.run(
        [helper, "--hash"] + list(strings), capture_output=True, text=True
    )
    out = {}
    for line in proc.stdout.splitlines():
        i, h = line.split()
        out[int(i)] = int(h)
    return out


# ---------------------------------------------------------------------------
# Test corpus
# ---------------------------------------------------------------------------

def make_corpus(tmpdir):
    rng = random.Random(0xC0FFEE)
    files = []
    sizes = [1, 100, 2047, 2048, 2049, 4095, 4096, 4097, 10000, 131072]
    for i, n in enumerate(sizes):
        p = os.path.join(tmpdir, f"rand_{n}.bin")
        with open(p, "wb") as f:
            f.write(bytes(rng.randrange(256) for _ in range(n)))
        files.append(p)
    # uniform 256-cycle: every nibble equally likely -> H = 8 -> Hbin clamp to 15
    p = os.path.join(tmpdir, "uniform256.bin")
    with open(p, "wb") as f:
        f.write(bytes(i % 256 for i in range(8192)))
    files.append(p)
    # all zeros (single byte value, zero entropy)
    p = os.path.join(tmpdir, "zeros.bin")
    with open(p, "wb") as f:
        f.write(b"\x00" * 3000)
    files.append(p)
    # text-heavy blob (string statistics)
    p = os.path.join(tmpdir, "text.bin")
    words = [
        b"http://example.com/path",
        b"HKEY_LOCAL_MACHINE\\Software\\x",
        b"c:\\windows\\system32\\kernel32.dll",
        b"LoadLibraryA",
        b"abcdefghij",
        b"\x01",
    ]
    with open(p, "wb") as f:
        for _ in range(500):
            f.write(rng.choice(words))
            f.write(b"\x00")
    files.append(p)
    # MZ-prefixed PE-like blob
    p = os.path.join(tmpdir, "pe_like.bin")
    blob = bytearray(b"MZ" + bytes(1024))
    for i in range(4096):
        blob.append((i * 7) % 256)
    blob += b"\x00" * 2048
    with open(p, "wb") as f:
        f.write(bytes(blob))
    files.append(p)
    return files


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    tmpdir = tempfile.mkdtemp(prefix="fos_parity_")
    helper = build_helper(tmpdir)
    files = make_corpus(tmpdir)

    # 1. MurmurHash3 parity (exact signed int32).
    # Note: test strings are ASCII-only because Windows argv reaches the C
    # helper through the ANSI codepage; non-ASCII would be mangled on the
    # way in and not test anything about the hash itself.
    strings = [
        "",
        "a",
        "abc",
        "kernel32.dll",
        "LoadLibraryA",
        "kernel32.dll:LoadLibraryA",
        "CreateProcessInternalW",
        "VirtualAlloc",
        "SetWindowsHookExW",
        "Microsoft.Windows.Common-Controls",
        "tls",
        "load_config",
        "wincrypt.h",
    ]
    c_h = c_hashes(helper, strings)
    ok = True
    for i, s in enumerate(strings):
        py = mmh3.hash(s.encode("utf-8"), seed=0)
        if c_h.get(i) != py:
            ok = False
            check(f"murmur3 {s!r}", False, f"C={c_h.get(i)} python={py}")
    check("murmur3 matches mmh3.hash(seed=0) for all strings", ok)

    # 2. Feature vectors
    for path in files:
        name = os.path.basename(path)
        with open(path, "rb") as f:
            raw = f.read()
        cv = c_hist(helper, path)
        check(f"{name}: C extractor ran", cv is not None)
        if cv is None:
            continue

        ref_hist = ref_byte_histogram(raw)
        ok = all(
            abs(cv[i] - ref_hist[i]) <= 1e-6
            for i in range(256)
        )
        check(f"{name}: byte histogram [0:256] matches", ok,
              f"max_diff={max(abs(cv[i]-ref_hist[i]) for i in range(256)):.2e}")

        ref_ent = ref_byte_entropy(raw)
        max_diff = max(abs(cv[256 + i] - ref_ent[i]) for i in range(256))
        ok = max_diff <= 1e-4
        check(f"{name}: byte-entropy [256:512] matches EMBER ref", ok,
              f"max_diff={max_diff:.2e}")

        ok = cv[2304] == float(len(raw))
        check(f"{name}: file size scalar matches", ok)

        ref_ent_scalar = ref_file_entropy(raw)
        ok = abs(cv[2314] - ref_ent_scalar) <= 1e-6
        check(f"{name}: file entropy scalar matches", ok)

        ref_str = ref_strings(raw)
        ok = all(abs(cv[k] - v) <= 1e-6 for k, v in ref_str.items())
        check(f"{name}: string statistics match", ok)

    print("\n%d FAILURE(S)" % failures if failures else "\nALL PARITY CHECKS PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

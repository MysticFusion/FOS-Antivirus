#!/usr/bin/env python3
"""
validate_model.py — Validates that forest.bin is well-formed and produces
correct inference results, mirroring the exact C logic in ml_engine.c.
"""

import struct
import sys
import os
import numpy as np

# ── Config ────────────────────────────────────────────────────────────────────

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "assets", "models", "forest.bin")
BUILD_PATH  = os.path.join(os.path.dirname(__file__), "..", "build",  "ml", "models", "forest.bin")

FOREST_MAGIC  = 0x45524F46   # 'FORE' little-endian
NUM_FEATURES  = 2381
# Node layout: matches export_lgb_to_forest.py struct.pack('<hfii f', ...)
# '<hfii f' pads the trailing float to align → 18 bytes on all platforms
NODE_FMT  = '<hfii f'
NODE_SIZE = struct.calcsize(NODE_FMT)  # 18 bytes

# ── Binary loader (mirrors ml_engine.c) ───────────────────────────────────────

def load_forest(path):
    with open(path, "rb") as f:
        magic, = struct.unpack("I", f.read(4))
        if magic != FOREST_MAGIC:
            raise ValueError(f"BAD MAGIC: 0x{magic:08X} (expected 0x{FOREST_MAGIC:08X})")

        num_trees, num_features = struct.unpack("II", f.read(8))

        trees = []
        for _ in range(num_trees):
            n_nodes, = struct.unpack("I", f.read(4))
            nodes = []
            for _ in range(n_nodes):
                raw = f.read(NODE_SIZE)
                if len(raw) < NODE_SIZE:
                    raise IOError("Unexpected EOF while reading node")
                feat_idx, threshold, left, right, value = struct.unpack(NODE_FMT, raw)
                nodes.append((feat_idx, threshold, left, right, value))
            trees.append(nodes)

    return num_trees, num_features, trees

# ── Tree evaluator (mirrors evaluate_tree() in ml_engine.c) ──────────────────

def evaluate_tree(nodes, features):
    curr = 0
    visited = set()
    while nodes[curr][0] != -1:  # feature_index == -1 → leaf
        if curr in visited:
            raise RuntimeError(f"Cycle detected at node {curr}")
        visited.add(curr)
        feat_idx, threshold, left, right, _ = nodes[curr]
        curr = left if features[feat_idx] <= threshold else right
    return nodes[curr][4]  # raw log-odds leaf value

def run_inference(trees, features):
    import math
    total = sum(evaluate_tree(t, features) for t in trees)
    log_odds = total
    # Apply sigmoid to match ml_engine.c: 1 / (1 + exp(-log_odds))
    return 1.0 / (1.0 + math.exp(-log_odds))

# ── Test samples ──────────────────────────────────────────────────────────────

# ── 2381-dim test vectors ────────────────────────────────────────────────────
# Index layout:
#  [0:256]   byte histogram (L1 normalized)
#  [256:512] byteentropy
#  [512:1536] import hashes
#  [2304]    file_size  [2309] num_sections  [2314] entropy  [2319] is_64bit

def make_benign_vector():
    """Approximates a small, legitimate PE: bimodal low-byte histogram, low entropy."""
    v = [0.0] * NUM_FEATURES
    # Byte histogram: typical PE has lots of 0x00 padding, some 0xFF, medium range
    # Low bytes dominate (code section alignment zeros)
    for i in range(0, 32):   v[i] = 0.025          # lots of low bytes / zeros
    for i in range(32, 128): v[i] = 0.005          # printable ASCII region
    for i in range(128, 256): v[i] = 0.001         # high bytes minimal
    total = sum(v[0:256]); norm = 1.0/total if total else 1.0
    for i in range(256): v[i] *= norm              # L1 normalize
    # Scalar features at known indices
    v[2304] = 51200.0          # file_size ~50 KB
    v[2305] = 65536.0          # vsize
    v[2306] = 1.0              # has_debug
    v[2309] = 4.0              # num_sections
    v[2310] = 3.5              # avg section entropy
    v[2311] = 120.0            # num_strings
    v[2312] = 12.0             # avg string length
    v[2314] = 5.2              # entropy
    v[2318] = 23117.0          # MZ magic
    # Small import footprint (kernel32, advapi32 only) — ~20 functions
    for i in range(512, 532): v[i] = 1.0
    return v

def make_malware_vector():
    """Approximates a packed/encrypted PE: near-uniform byte histogram, very high entropy."""
    v = [0.0] * NUM_FEATURES
    # Packed malware: near-uniform byte distribution across all 256 values
    for i in range(256): v[i] = 1.0 / 256.0       # flat = max entropy
    # Entropy histogram similarly flat
    for i in range(256, 512): v[i] = 1.0 / 256.0
    # Scalar features
    v[2304] = 2_621_440.0      # file_size ~2.5 MB
    v[2305] = 4_194_304.0      # vsize ~4 MB
    v[2309] = 12.0             # many sections
    v[2310] = 7.8              # near-max section entropy (packed)
    v[2311] = 800.0            # lots of strings
    v[2314] = 7.92             # near-max file entropy
    v[2316] = 35.0             # many URL strings
    v[2317] = 28.0             # many registry strings
    v[2318] = 23117.0          # MZ magic
    # Dense imports (150 functions across many DLLs)
    for i in range(512, 512+154): v[i] = 1.0
    return v

BENIGN_FEATURES  = make_benign_vector()
MALWARE_FEATURES = make_malware_vector()



def main():
    print("=" * 60)
    print("  FOS-Antivirus - forest.bin Validator")
    print("=" * 60)

    # ── 1. Locate model ───────────────────────────────────────────────────────
    path = None
    for candidate in [MODEL_PATH, BUILD_PATH]:
        p = os.path.normpath(candidate)
        if os.path.exists(p):
            path = p
            break

    if not path:
        print(f"[FAIL] forest.bin not found at either:\n  {MODEL_PATH}\n  {BUILD_PATH}")
        sys.exit(1)

    print(f"[OK]   Model found : {path}")
    print(f"[OK]   File size   : {os.path.getsize(path):,} bytes")

    # ── 2. Load & validate structure ──────────────────────────────────────────
    try:
        num_trees, num_features, trees = load_forest(path)
    except Exception as e:
        print(f"[FAIL] Load error: {e}")
        sys.exit(1)

    print(f"[OK]   Magic       : 0x{FOREST_MAGIC:08X} ('FORE')")
    print(f"[OK]   Trees       : {num_trees}")
    print(f"[OK]   Features    : {num_features}")

    if num_features != NUM_FEATURES:
        print(f"[WARN] Expected {NUM_FEATURES} features, got {num_features}")

    total_nodes = sum(len(t) for t in trees)
    avg_nodes   = total_nodes / num_trees if num_trees else 0
    print(f"[OK]   Total nodes : {total_nodes:,}  (avg {avg_nodes:.1f} / tree)")

    # ── 3. Tree integrity ─────────────────────────────────────────────────────
    print("\n-- Tree Integrity Check -------------------------------------")
    errors = 0
    for i, nodes in enumerate(trees):
        leaf_count = sum(1 for n in nodes if n[0] == -1)
        internal   = len(nodes) - leaf_count
        if leaf_count == 0:
            print(f"[FAIL] Tree {i}: no leaves!")
            errors += 1
        invalid_feat = [n for n in nodes if n[0] != -1 and not (0 <= n[0] < num_features)]
        if invalid_feat:
            print(f"[FAIL] Tree {i}: {len(invalid_feat)} node(s) with out-of-range feature index")
            errors += 1

    if errors == 0:
        print(f"[OK]   All {num_trees} trees are structurally valid")
    else:
        print(f"[FAIL] {errors} tree(s) have structural problems")

    # ── 4. Inference test ─────────────────────────────────────────────────────
    print("\n-- Inference Test -------------------------------------------")
    try:
        benign_score  = run_inference(trees, BENIGN_FEATURES)
        malware_score = run_inference(trees, MALWARE_FEATURES)
    except Exception as e:
        print(f"[FAIL] Inference error: {e}")
        sys.exit(1)

    benign_label  = "BENIGN"  if benign_score  < 0.5 else "MALWARE"
    malware_label = "MALWARE" if malware_score >= 0.5 else "BENIGN"

    print(f"  Benign  sample score : {benign_score:.4f}  -> {benign_label}")
    print(f"  Malware sample score : {malware_score:.4f}  -> {malware_label}")

    ok_benign  = benign_score  < 0.5
    ok_malware = malware_score >= 0.5

    if ok_benign and ok_malware:
        print("[OK]   Inference results are correct")
    else:
        if not ok_benign:
            print(f"[WARN] Benign sample scored too HIGH ({benign_score:.4f}) - model may be miscalibrated")
        if not ok_malware:
            print(f"[WARN] Malware sample scored too LOW ({malware_score:.4f}) - model may be miscalibrated")

    # ── 5. Score distribution (random probe) ──────────────────────────────────
    print("\n-- Score Distribution (1000 random samples) -----------------")
    rng = np.random.default_rng(42)
    # Random 2381-dim vectors in [0,1]
    rand_samples = rng.random((1000, NUM_FEATURES)).tolist()
    scores = [run_inference(trees, s) for s in rand_samples]
    scores_arr = np.array(scores)
    print(f"  Min   : {scores_arr.min():.4f}")
    print(f"  Max   : {scores_arr.max():.4f}")
    print(f"  Mean  : {scores_arr.mean():.4f}")
    print(f"  Std   : {scores_arr.std():.4f}")
    histogram_bins = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    counts, _ = np.histogram(scores_arr, bins=histogram_bins)
    print("  Histogram (score -> count):")
    for lo, hi, c in zip(histogram_bins, histogram_bins[1:], counts):
        bar = "#" * (c // 10)
        print(f"    [{lo:.1f}-{hi:.1f}): {c:4d}  {bar}")

    # ── 6. Summary ────────────────────────────────────────────────────────────
    print("\n-- Summary ---------------------------------------------------")
    if errors == 0 and ok_benign and ok_malware:
        print("[PASS] forest.bin is valid and inference works correctly")
    else:
        print("[WARN] Some checks did not pass - review output above.")

if __name__ == "__main__":
    main()

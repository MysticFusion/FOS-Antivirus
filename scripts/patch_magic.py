"""
patch_magic.py
Prepends the 4-byte FORE magic to the existing forest.bin (which was
exported without it), so it matches what ml_engine.c expects.
"""
import struct
import shutil
import os

# Derive paths relative to this script's location — works in any project directory
_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_ASSETS_DIR  = os.path.join(_SCRIPTS_DIR, "..", "assets", "models")
_BUILD_DIR   = os.path.join(os.path.dirname(_SCRIPTS_DIR), "build", "ml", "models")

SRC       = os.path.join(_ASSETS_DIR, "forest.bin")
BAK       = os.path.join(_ASSETS_DIR, "forest.bin.bak")
BUILD_DST = os.path.join(_BUILD_DIR, "forest.bin")
MAGIC     = b"FORE"  # 0x45524F46
EXPECTED  = 0x45524F46

# ── Check if already patched ──────────────────────────────────────────────────
with open(SRC, "rb") as f:
    first4 = f.read(4)
    existing_magic = struct.unpack("I", first4)[0]

if existing_magic == EXPECTED:
    print("[SKIP] forest.bin already has correct FORE magic — no patch needed.")
else:
    # ── Back up original ──────────────────────────────────────────────────────
    shutil.copy(SRC, BAK)
    print(f"[OK]   Backed up original to {BAK}")

    # ── Read and prepend magic ────────────────────────────────────────────────
    with open(SRC, "rb") as f:
        original = f.read()

    patched = MAGIC + original

    with open(SRC, "wb") as f:
        f.write(patched)
    print(f"[OK]   Patched assets/models/forest.bin  ({len(patched):,} bytes)")

    # ── Update build copy ─────────────────────────────────────────────────────
    with open(BUILD_DST, "wb") as f:
        f.write(patched)
    print(f"[OK]   Updated build/ml/models/forest.bin  ({len(patched):,} bytes)")

# ── Verify ────────────────────────────────────────────────────────────────────
with open(SRC, "rb") as f:
    check = struct.unpack("I", f.read(4))[0]
    num_trees, num_features = struct.unpack("II", f.read(8))

status = "OK" if check == EXPECTED else "FAIL"
print(f"[{status}]   Magic verify : 0x{check:08X}")
print(f"[OK]   Trees      : {num_trees}")
print(f"[OK]   Features   : {num_features}")
print("Done.")

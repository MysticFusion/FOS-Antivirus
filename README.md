# FOS Antivirus 🛡️

FOS Antivirus is a modern, high-performance security scanner for Windows, built natively in **C11** with a GTK4 user interface. It combines traditional signature-based detection with a custom-engineered Decision Forest machine learning engine capable of extracting and analyzing 2,381 static PE features entirely in C.

## Core Capabilities

- **Native ML Inference Engine**: Evaluates a 100-tree LightGBM model directly in C without heavyweight dependencies (no ONNX/TensorFlow required).
- **EMBER-2024 Feature Extraction**: Natively parses PE files to extract 2,381 dimensions, including L1-normalized byte histograms, sliding-window entropy, and MurmurHash3 string hashing for imports, exports, and sections.
- **High-Speed Signature Scanning**: Matches file hashes against a high-performance local SQLite signature database.
- **GTK4 User Interface**: Clean, responsive frontend with native Dark Mode support, providing Custom Scans, Quarantine management, and Real-Time monitoring overview.
- **Out-of-Core Training Pipeline**: Includes a complete Python ETL and training pipeline capable of processing 70GB+ SQLite datasets into sparse LIBSVM arrays and training LightGBM models within strict memory limits.

## Repository Architecture

```text
FOS-Antivirus/
├── src/
│   ├── app/            # Application lifecycle & GTK initialization
│   ├── engine/         # C11 backend: signature checks, PE parsing, feature extraction, ML inference
│   └── ui/             # GTK4 graphical interface controllers
├── scripts/
│   ├── build_db.py             # JSONL -> SQLite database ingestion
│   ├── extract_features.py     # SQLite -> 2381-dim sparse LIBSVM (multiprocessing)
│   ├── train_lightgbm.py       # Out-of-core LightGBM model training
│   ├── export_lgb_to_forest.py # Exports LightGBM trees to the custom .bin format
│   └── validate_model.py       # Structural and inference parity validation
├── assets/
│   └── models/
│       └── forest.bin  # The compiled 100-tree binary model ('FORE' magic)
└── CMakeLists.txt      # MinGW/Ninja build configuration
```

## Build Instructions (Windows)

The project requires **MSYS2** to provide the GCC compiler and GTK4 libraries.

### 1. Install Dependencies (MSYS2 UCRT64/MINGW64)
Run the following in your MSYS2 terminal:
```bash
pacman -S mingw-w64-x86_64-gcc \
          mingw-w64-x86_64-cmake \
          mingw-w64-x86_64-ninja \
          mingw-w64-x86_64-gtk4 \
          mingw-w64-x86_64-pkgconf
```

### 2. Compile from Source
```bash
git clone https://github.com/MysticFusion/FOS-Antivirus.git
cd FOS-Antivirus

# Configure the build system
cmake -B build -S . -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release

# Compile the executable (uses all cores)
cmake --build build -j
```

### 3. Run
The compiled executable and the required ML models are automatically staged in the `build/` directory.
```bash
./build/Antivirus.exe
```

## ML Pipeline Workflow

If you wish to retrain the ML model on new data:

1. **Ingest data**: `python scripts/build_db.py` pulls massive JSONL datasets into a SQLite DB.
2. **Extract features**: `python scripts/extract_features.py` hashes and normalizes PE characteristics into sparse LIBSVM format.
3. **Train model**: `python scripts/train_lightgbm.py` trains the trees iteratively using two-round streaming to prevent out-of-memory (OOM) crashes on huge datasets.
4. **Export to C format**: `python scripts/export_lgb_to_forest.py` flattens the LightGBM booster into a highly compact `forest.bin` file optimized for C `struct` memory alignment.

## License
Open Source under the MIT License.
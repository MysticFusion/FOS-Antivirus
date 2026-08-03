import sqlite3
import os
import mmh3
import random
import multiprocessing as mp
from tqdm import tqdm

try:
    import orjson as json
except ImportError:
    import json
    print("Warning: orjson not found. Using standard json (slower).")

DB_PATH = "D:/train_data.db"
TRAIN_TXT = "assets/data/train.txt"
TEST_TXT = "assets/data/test.txt"
FEATURE_COUNT = 2381

def hash_feature(vec_dict, string_val, start_idx, num_dims):
    if isinstance(string_val, str):
        b = string_val.encode('utf-8')
    else:
        b = str(string_val).encode('utf-8')
        
    h = mmh3.hash(b, seed=0)
    idx = abs(h) % num_dims
    val = 1.0 if h > 0 else -1.0
    
    dict_idx = start_idx + idx
    vec_dict[dict_idx] = vec_dict.get(dict_idx, 0.0) + val

def extract_features_sparse(row, is_64bit):
    vec_dict = {}
    
    try:
        hist = json.loads(row[0]) if row[0] else []
        ent = json.loads(row[1]) if row[1] else []
        imp = json.loads(row[2]) if row[2] else {}
        exp = json.loads(row[3]) if row[3] else []
        dd = json.loads(row[4]) if row[4] else []
        sec = json.loads(row[5]) if row[5] else {}
        gen = json.loads(row[6]) if row[6] else {}
        strs = json.loads(row[7]) if row[7] else {}
    except Exception:
        return vec_dict

    if hist and len(hist) == 256:
        h_sum = sum(hist)
        if h_sum > 0:
            for i, v in enumerate(hist):
                if v > 0: vec_dict[i] = v / h_sum
            
    if ent and len(ent) == 256:
        e_sum = sum(ent)
        if e_sum > 0:
            for i, v in enumerate(ent):
                if v > 0: vec_dict[256 + i] = v / e_sum

    if isinstance(imp, dict):
        for lib, funcs in imp.items():
            lib_lower = lib.lower()
            hash_feature(vec_dict, lib_lower, 512, 1024)
            for func in funcs:
                hash_feature(vec_dict, f"{lib_lower}:{func}", 512, 1024)

    if isinstance(exp, list):
        for func in exp:
            hash_feature(vec_dict, func, 1536, 256)

    sections = sec.get('sections', [])
    for s in sections:
        name = s.get('name', '')
        if name:
            hash_feature(vec_dict, name, 1792, 256)
        props = s.get('props', [])
        for p in props:
            hash_feature(vec_dict, str(p), 1792, 256)

    if isinstance(dd, list):
        for d in dd:
            name = d.get('name', '')
            if name:
                hash_feature(vec_dict, name, 2048, 256)

    v = gen.get('size', 0.0)
    if v: vec_dict[2304] = v
    v = gen.get('vsize', 0.0)
    if v: vec_dict[2305] = v
    if gen.get('has_debug', 0) > 0: vec_dict[2306] = 1.0
    
    v = len(exp) if isinstance(exp, list) else 0.0
    if v: vec_dict[2307] = float(v)
    
    if isinstance(imp, dict):
        v = sum(len(x) for x in imp.values())
        if v: vec_dict[2308] = float(v)
    elif isinstance(imp, list):
        v = len(imp)
        if v: vec_dict[2308] = float(v)
        
    v = len(sections)
    if v: vec_dict[2309] = float(v)
    
    if len(sections) > 0:
        entropies = [s.get('entropy', 0.0) for s in sections if 'entropy' in s]
        if entropies: vec_dict[2310] = sum(entropies) / len(sections)
        
    v = strs.get('numstrings', 0.0)
    if v: vec_dict[2311] = v
    v = strs.get('avlength', 0.0)
    if v: vec_dict[2312] = v
    v = strs.get('printables', 0.0)
    if v: vec_dict[2313] = v
    v = strs.get('entropy', 0.0)
    if v: vec_dict[2314] = v
    v = strs.get('paths', 0.0)
    if v: vec_dict[2315] = v
    v = strs.get('urls', 0.0)
    if v: vec_dict[2316] = v
    v = strs.get('registry', 0.0)
    if v: vec_dict[2317] = v
    v = strs.get('MZ', 0.0)
    if v: vec_dict[2318] = v
    
    if is_64bit: vec_dict[2319] = 1.0

    return vec_dict

def dict_to_libsvm(label, vec_dict):
    parts = [str(label)]
    for idx in sorted(vec_dict.keys()):
        val = vec_dict[idx]
        if val != 0.0:
            parts.append(f"{idx}:{val}")
    return " ".join(parts) + "\n"

def process_chunk(args):
    table_name, is_64bit, start_id, end_id, seed_offset = args
    
    # Independent sqlite connection per worker
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.isolation_level = None
    cur = conn.cursor()
    cur.execute("PRAGMA read_uncommitted = True")
    
    query = f"SELECT histogram, byteentropy, imports, exports, datadirectories, section, general, strings, label FROM {table_name} WHERE rowid > ? AND rowid <= ?"
    cur.execute(query, (start_id, end_id))
    rows = cur.fetchall()
    
    train_lines = []
    test_lines = []
    
    # Local deterministic random based on chunk offset to ensure consistent 80/20 splitting
    rng = random.Random(42 + seed_offset)
    
    for row in rows:
        label = int(row[8])
        vec_dict = extract_features_sparse(row, is_64bit)
        line = dict_to_libsvm(label, vec_dict)
        
        if rng.random() < 0.8:
            train_lines.append(line)
        else:
            test_lines.append(line)
            
    conn.close()
    return len(rows), train_lines, test_lines

def main():
    if not os.path.exists(DB_PATH):
        print(f"Error: Database not found at {DB_PATH}")
        return

    os.makedirs(os.path.dirname(TRAIN_TXT), exist_ok=True)
    
    print("=" * 60)
    print("  EMBER-2024 Fast Multiprocess ETL Pipeline")
    print("=" * 60)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Get max rowids natively
    cur.execute("SELECT MAX(rowid) FROM win64")
    max_win64 = cur.fetchone()[0] or 1040000
    
    cur.execute("SELECT MAX(rowid) FROM win32")
    max_win32 = cur.fetchone()[0] or 3120000
    conn.close()
    
    chunk_size = 10000
    tasks = []
    seed_ctr = 0
    
    for start_id in range(0, max_win64, chunk_size):
        tasks.append(("win64", True, start_id, start_id + chunk_size, seed_ctr))
        seed_ctr += 1
        
    for start_id in range(0, max_win32, chunk_size):
        tasks.append(("win32", False, start_id, start_id + chunk_size, seed_ctr))
        seed_ctr += 1
        
    total_rows = max_win32 + max_win64
    
    # Clear out files first
    open(TRAIN_TXT, 'w').close()
    open(TEST_TXT, 'w').close()
    
    cpu_count = max(1, mp.cpu_count() - 2)
    print(f"[1] Launching {cpu_count} worker processes for {total_rows:,} rows...")
    
    # We open files in append mode. The main process writes chunks as they complete natively.
    f_train = open(TRAIN_TXT, 'a')
    f_test = open(TEST_TXT, 'a')
    
    with mp.Pool(processes=cpu_count) as pool:
        # imap_unordered is incredibly fast as it doesn't wait to sort the output array
        with tqdm(total=total_rows, desc="Extracting features") as pbar:
            for row_count, tr_lines, te_lines in pool.imap_unordered(process_chunk, tasks):
                if tr_lines: f_train.writelines(tr_lines)
                if te_lines: f_test.writelines(te_lines)
                pbar.update(row_count)
                
    f_train.close()
    f_test.close()

    print("\n[2] ETL Complete.")
    
if __name__ == '__main__':
    mp.freeze_support()
    main()

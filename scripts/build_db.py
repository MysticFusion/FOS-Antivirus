import sqlite3
import time
from pathlib import Path

# Try to use orjson for blazing fast parsing. Fallback to standard json if missing.
try:
    import orjson as json
    USING_ORJSON = True
except ImportError:
    import json
    USING_ORJSON = False

def ingest_directory_to_sqlite(directory_path, db_path, table_name, batch_size=100000):
    start_time = time.time()
    dir_path = Path(directory_path)
    
    # Grab all .jsonl files in the directory
    jsonl_files = list(dir_path.glob('*.jsonl'))
    if not jsonl_files:
        print(f"⚠️ No .jsonl files found in {directory_path}!")
        return

    print(f"🚀 Found {len(jsonl_files)} files in '{directory_path}'. Starting import to table '{table_name}'...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Aggressive Performance Tweaks
    cursor.execute('PRAGMA synchronous = OFF')
    cursor.execute('PRAGMA journal_mode = OFF') 
    cursor.execute('PRAGMA cache_size = 100000') 
    cursor.execute('PRAGMA temp_store = MEMORY')
    
    # Track known columns across all files
    columns = []
    
    # Helper function to rebuild the SQL insert command dynamically
    def build_query(cols):
        cols_escaped = ", ".join([f'"{c}"' for c in cols])
        placeholders = ", ".join(["?"] * len(cols))
        return f'INSERT INTO "{table_name}" ({cols_escaped}) VALUES ({placeholders})'

    total_rows_inserted = 0
    total_errors = 0
    
    for file_idx, filepath in enumerate(jsonl_files):
        print(f"📄 Processing File {file_idx + 1}/{len(jsonl_files)}: {filepath.name}...")
        
        with open(filepath, 'rb') as f:
            # If this is the very first file and table doesn't exist, build initial schema
            if not columns:
                first_line = f.readline()
                if not first_line: continue
                
                record = json.loads(first_line)
                columns = list(record.keys())
                cols_def = ", ".join([f'"{col}" TEXT' for col in columns])
                cursor.execute(f'CREATE TABLE IF NOT EXISTS "{table_name}" ({cols_def})')
                f.seek(0)
            
            insert_query = build_query(columns)
            batch = []
            
            cursor.execute('BEGIN TRANSACTION')
            
            for line_idx, line in enumerate(f):
                try:
                    record = json.loads(line)
                    
                    # ✨ Dynamic Schema Evolution: Check for new keys
                    new_keys = [k for k in record.keys() if k not in columns]
                    if new_keys:
                        # Flush current batch before altering table structure
                        if batch:
                            cursor.executemany(insert_query, batch)
                            conn.commit()
                            batch = []
                        
                        # Add new columns to SQLite dynamically
                        for new_key in new_keys:
                            cursor.execute(f'ALTER TABLE "{table_name}" ADD COLUMN "{new_key}" TEXT')
                            columns.append(new_key)
                        
                        # Rebuild query with new schema and restart transaction
                        insert_query = build_query(columns)
                        cursor.execute('BEGIN TRANSACTION')
                    
                    # Append row to batch
                    batch.append(tuple(record.get(col, None) for col in columns))
                    
                    if len(batch) >= batch_size:
                        cursor.executemany(insert_query, batch)
                        conn.commit()
                        cursor.execute('BEGIN TRANSACTION')
                        total_rows_inserted += len(batch)
                        batch = []
                        
                except Exception as e:
                    total_errors += 1
                    if total_errors <= 5:
                        print(f"⚠️ Corrupted data in {filepath.name} (Line {line_idx+1}): {e}")
                    elif total_errors == 6:
                        print(f"⚠️ Muting further error prints to preserve performance...")
            
            # Insert remaining records for the current file
            if batch:
                cursor.executemany(insert_query, batch)
                conn.commit()
                total_rows_inserted += len(batch)

    conn.close()
    elapsed = time.time() - start_time
    print(f"✅ Finished '{table_name}'. Inserted {total_rows_inserted:,} rows from {len(jsonl_files)} files. Time: {elapsed:.2f}s!")

if __name__ == "__main__":
    # Point these to your directories
    ingest_directory_to_sqlite('D:/win32_train', 'D:/train_data.db', 'win32')
    ingest_directory_to_sqlite('D:/win64_train', 'D:/train_data.db', 'win64')
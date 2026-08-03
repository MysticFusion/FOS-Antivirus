import lightgbm as lgb
import time
import os

TRAIN_TXT = "assets/data/train.txt"
TEST_TXT = "assets/data/test.txt"
MODEL_LGB_TXT = "assets/models/forest.txt"

def main():
    if not os.path.exists(TRAIN_TXT):
        print(f"Error: {TRAIN_TXT} not found. Run extract_features.py first.")
        return

    print("=" * 60)
    print("  EMBER-2024 LightGBM Training (Full 2381-Feature Route)")
    print("=" * 60)

    print(f"[1] Configuring Out-of-Core LightGBM Datasets (two_round streaming mode)")
    t0 = time.time()

    # two_round=True: LightGBM reads the file twice sequentially instead of
    # loading it all at once. Cuts peak RAM by ~60% at the cost of 2-3x slower
    # bin-mapping. max_bin=63 halves the bin table size further.
    low_ram_params = {'two_round': True, 'max_bin': 63}
    train_data = lgb.Dataset(TRAIN_TXT, params=low_ram_params)
    test_data  = lgb.Dataset(TEST_TXT,  params=low_ram_params, reference=train_data)

    print(f"    Datasets configured in {time.time() - t0:.2f}s")
    
    print(f"\n[2] Training LightGBM Model (Out-of-Core Stream)...")
    t0 = time.time()
    
    params = {
        'objective':        'binary',
        'metric':           'auc',
        'learning_rate':    0.05,      # slower but stabler convergence
        'num_leaves':       512,       # reduced from 1024 to save RAM during tree build
        'max_depth':        12,
        'max_bin':          63,        # match dataset bin count
        'min_data_in_leaf': 100,       # prevents over-fitting on sparse hashed features
        'is_unbalance':     True,
        'random_state':     42,
        'num_threads':      4,         # leave cores free for OS; avoids thrashing
        'verbose':          1,
    }
    
    # Early stopping via callbacks
    callbacks = [lgb.early_stopping(stopping_rounds=10), lgb.log_evaluation(period=1)]
    
    # Note: LightGBM will stream chunks from the text file during bin mapping
    gbm = lgb.train(
        params,
        train_data,
        num_boost_round=100,
        valid_sets=[test_data],
        valid_names=['valid'],
        callbacks=callbacks
    )
    
    print(f"    Training finished in {time.time() - t0:.2f}s")
    
    # [3] Export
    os.makedirs(os.path.dirname(MODEL_LGB_TXT), exist_ok=True)
    gbm.save_model(MODEL_LGB_TXT)
    print(f"\n[3] Saved LightGBM tree dump to {MODEL_LGB_TXT}")
    print("    Ready for export_lgb_to_forest.py conversion.")

if __name__ == '__main__':
    main()

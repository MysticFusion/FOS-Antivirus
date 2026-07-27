import lightgbm as lgb
import time
import os
import argparse

def main():
    parser = argparse.ArgumentParser(description="Train the FOS LightGBM malware model.")
    parser.add_argument("--train", default="assets/data/train.txt", help="Input train LIBSVM file.")
    parser.add_argument("--valid", default="assets/data/test.txt", help="Input validation LIBSVM file.")
    parser.add_argument("--model-out", default="assets/models/forest.txt", help="Output LightGBM text model.")
    args = parser.parse_args()

    if not os.path.exists(args.train):
        print(f"Error: {args.train} not found. Run extract_features.py first.")
        return
    if not os.path.exists(args.valid):
        print(f"Error: {args.valid} not found. Run extract_features.py first.")
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
    train_data = lgb.Dataset(args.train, params=low_ram_params)
    test_data  = lgb.Dataset(args.valid,  params=low_ram_params, reference=train_data)

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
    out_dir = os.path.dirname(args.model_out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    gbm.save_model(args.model_out)
    print(f"\n[3] Saved LightGBM tree dump to {args.model_out}")
    print("    Ready for export_lgb_to_forest.py conversion.")

if __name__ == '__main__':
    main()

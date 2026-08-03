import lightgbm as lgb
import struct
import json
import os

LGB_MODEL_PATH = "assets/models/forest.txt"
OUTPUT_BIN_PATH = "assets/models/forest.bin"
MAGIC = b'FORE'
NUM_FEATURES = 2381

def flatten_lgb_tree(tree_structure):
    nodes = []
    
    def traverse(node):
        node_id = len(nodes)
        nodes.append(None) # placeholder
        
        if 'leaf_value' in node:
            # It's a leaf
            nodes[node_id] = {
                'feature': -1,
                'threshold': 0.0,
                'left': -1,
                'right': -1,
                'value': float(node['leaf_value'])
            }
        else:
            # It's an internal node
            left_idx = traverse(node['left_child'])
            right_idx = traverse(node['right_child'])
            nodes[node_id] = {
                'feature': int(node['split_feature']),
                'threshold': float(node['threshold']),
                'left': left_idx,
                'right': right_idx,
                'value': 0.0
            }
        return node_id
        
    traverse(tree_structure)
    return nodes

def main():
    if not os.path.exists(LGB_MODEL_PATH):
        print(f"Error: {LGB_MODEL_PATH} not found.")
        return
        
    print(f"Loading LightGBM model from {LGB_MODEL_PATH}...")
    booster = lgb.Booster(model_file=LGB_MODEL_PATH)
    
    dump = booster.dump_model()
    trees = dump['tree_info']
    n_trees = len(trees)
    
    print(f"Parsed {n_trees} trees. Converting to binary format...")
    
    out_dir = os.path.dirname(OUTPUT_BIN_PATH)
    if out_dir: os.makedirs(out_dir, exist_ok=True)
    
    with open(OUTPUT_BIN_PATH, 'wb') as f:
        # Header
        f.write(MAGIC)
        f.write(struct.pack('<II', n_trees, NUM_FEATURES))
        
        total_nodes = 0
        for i, tree in enumerate(trees):
            flat_nodes = flatten_lgb_tree(tree['tree_structure'])
            n_nodes = len(flat_nodes)
            total_nodes += n_nodes
            
            f.write(struct.pack('<I', n_nodes))
            
            for node in flat_nodes:
                f.write(struct.pack('<hfii f',
                                    node['feature'],
                                    node['threshold'],
                                    node['left'],
                                    node['right'],
                                    node['value']))
                                    
    print(f"Export successful!")
    print(f"Wrote {n_trees} trees and {total_nodes} total nodes to {OUTPUT_BIN_PATH}.")

if __name__ == '__main__':
    main()

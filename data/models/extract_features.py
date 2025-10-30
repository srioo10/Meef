#!/usr/bin/env python3
"""
Extract ML features from IR JSON files and catalog
Converts compiler IR to numerical feature vectors for ML training
"""

import pandas as pd
import json
import numpy as np
from pathlib import Path
import sys

class FeatureExtractor:
    def __init__(self, catalog_path="data/catalog.csv", output_path="data/features_ml.csv"):
        self.catalog_path = catalog_path
        self.output_path = output_path
        
    def load_catalog(self):
        """Load the catalog CSV"""
        try:
            catalog = pd.read_csv(self.catalog_path)
            print(f"[✓] Loaded catalog: {len(catalog)} entries")
            return catalog
        except Exception as e:
            print(f"[✗] Error loading catalog: {e}")
            return None
    
    def extract_features_from_ir(self, ir_path):
        """Extract features from a single IR JSON file"""
        try:
            with open(ir_path, 'r') as f:
                ir = json.load(f)
            
            features = {}
            
            # Behavioral features (7 features)
            behavior = ir.get('behavior', {})
            features['uses_network'] = behavior.get('uses_network', 0)
            features['uses_fileops'] = behavior.get('uses_fileops', 0)
            features['uses_registry'] = behavior.get('uses_registry', 0)
            features['uses_memory'] = behavior.get('uses_memory', 0)
            features['uses_injection'] = behavior.get('uses_injection', 0)
            features['uses_crypto'] = behavior.get('uses_crypto', 0)
            features['uses_persist'] = behavior.get('uses_persist', 0)
            
            # CFG features (4 features)
            cfg = ir.get('cfg', {})
            features['cfg_num_blocks'] = cfg.get('num_blocks', 0)
            features['cfg_num_edges'] = cfg.get('num_edges', 0)
            features['cfg_branch_density'] = cfg.get('branch_density', 0.0)
            features['cfg_cyclomatic_complexity'] = cfg.get('cyclomatic_complexity', 1.0)
            
            # API call features
            apis = ir.get('apis', [])
            features['num_unique_apis'] = len(apis)
            features['total_api_calls'] = sum(api.get('count', 0) for api in apis)
            
            # Top API frequencies (top 10)
            api_counts = {api['name']: api['count'] for api in apis}
            sorted_apis = sorted(api_counts.items(), key=lambda x: x[1], reverse=True)
            for i in range(10):
                if i < len(sorted_apis):
                    features[f'top_api_{i+1}_count'] = sorted_apis[i][1]
                else:
                    features[f'top_api_{i+1}_count'] = 0
            
            # Opcode features
            opcodes = ir.get('opcodes', [])
            features['num_unique_opcodes'] = len(opcodes)
            features['total_opcodes'] = sum(op.get('count', 0) for op in opcodes)
            
            # Specific opcode frequencies
            opcode_dict = {op['name']: op['count'] for op in opcodes}
            important_opcodes = ['CALL', 'MOV', 'PUSH', 'POP', 'JMP', 'RET', 'ADD', 'SUB', 'XOR', 'TEST']
            for opcode in important_opcodes:
                features[f'opcode_{opcode.lower()}_count'] = opcode_dict.get(opcode, 0)
            
            # Derived features
            if features['total_opcodes'] > 0:
                features['call_ratio'] = features.get('opcode_call_count', 0) / features['total_opcodes']
                features['jmp_ratio'] = features.get('opcode_jmp_count', 0) / features['total_opcodes']
            else:
                features['call_ratio'] = 0.0
                features['jmp_ratio'] = 0.0
            
            # Code complexity indicators
            features['api_to_opcode_ratio'] = (features['total_api_calls'] / features['total_opcodes'] 
                                               if features['total_opcodes'] > 0 else 0.0)
            
            return features
            
        except Exception as e:
            print(f"[✗] Error extracting features from {ir_path}: {e}")
            return None
    
    def extract_all_features(self, catalog):
        """Extract features from all IR files in catalog"""
        features_list = []
        
        print(f"\n[*] Extracting features from {len(catalog)} samples...")
        
        for idx, row in catalog.iterrows():
            ir_path = row.get('ir_path')
            sha256 = row.get('sha256')
            label = row.get('label', 'unknown')
            
            if not ir_path or not Path(ir_path).exists():
                print(f"[⚠] IR file not found: {ir_path}")
                continue
            
            features = self.extract_features_from_ir(ir_path)
            
            if features:
                # Add metadata
                features['sha256'] = sha256
                features['label'] = label
                features['label_binary'] = 1 if label == 'malicious' else 0
                features_list.append(features)
                
                if (idx + 1) % 10 == 0:
                    print(f"  Processed {idx + 1}/{len(catalog)} samples...")
        
        print(f"[✓] Successfully extracted features from {len(features_list)} samples")
        
        return pd.DataFrame(features_list)
    
    def save_features(self, features_df):
        """Save features to CSV"""
        try:
            # Ensure output directory exists
            Path(self.output_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Save
            features_df.to_csv(self.output_path, index=False)
            print(f"[✓] Features saved to: {self.output_path}")
            
            # Show summary
            print(f"\n📊 Feature Summary:")
            print(f"   Total samples: {len(features_df)}")
            print(f"   Total features: {len(features_df.columns) - 3}")  # Exclude sha256, label, label_binary
            print(f"   Malicious: {(features_df['label'] == 'malicious').sum()}")
            print(f"   Benign: {(features_df['label'] == 'benign').sum()}")
            
            # Show feature columns
            print(f"\n📋 Feature columns ({len(features_df.columns)}):")
            feature_cols = [col for col in features_df.columns if col not in ['sha256', 'label', 'label_binary']]
            for i, col in enumerate(feature_cols[:10], 1):
                print(f"   {i}. {col}")
            if len(feature_cols) > 10:
                print(f"   ... and {len(feature_cols) - 10} more")
            
            return True
            
        except Exception as e:
            print(f"[✗] Error saving features: {e}")
            return False
    
    def run(self):
        """Run complete feature extraction pipeline"""
        print("╔══════════════════════════════════════════════════════════╗")
        print("║          MEEF Feature Extraction for ML                 ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print()
        
        # Load catalog
        catalog = self.load_catalog()
        if catalog is None or len(catalog) == 0:
            print("[✗] No samples in catalog")
            return False
        
        # Extract features
        features_df = self.extract_all_features(catalog)
        
        if len(features_df) == 0:
            print("[✗] No features extracted")
            return False
        
        # Save features
        success = self.save_features(features_df)
        
        if success:
            print(f"\n[✓] Feature extraction complete!")
            print(f"    Next step: python3 train_model.py")
        
        return success


if __name__ == "__main__":
    extractor = FeatureExtractor()
    success = extractor.run()
    sys.exit(0 if success else 1)

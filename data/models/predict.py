#!/usr/bin/env python3
"""
Predict if a sample is malware using trained ML model
"""

import sys
import json
import numpy as np
import joblib
from pathlib import Path
import subprocess

class MalwarePredictor:
    def __init__(self, model_dir="data/models"):
        self.model_dir = Path(model_dir)
        self.model = None
        self.scaler = None
        self.metadata = None
        
    def load_model(self):
        """Load trained model"""
        try:
            model_path = self.model_dir / "malware_classifier.pkl"
            scaler_path = self.model_dir / "feature_scaler.pkl"
            metadata_path = self.model_dir / "model_metadata.json"
            
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            
            with open(metadata_path, 'r') as f:
                self.metadata = json.load(f)
            
            print(f"[✓] Model loaded successfully")
            print(f"    Test accuracy: {self.metadata['test_metrics']['accuracy']*100:.2f}%")
            return True
            
        except Exception as e:
            print(f"[✗] Error loading model: {e}")
            print(f"    Train a model first: python3 train_model.py")
            return False
    
    def process_sample(self, input_path):
        """Process a sample through the pipeline"""
        input_path = Path(input_path)
        
        # Check if it's already an ASM file
        if input_path.suffix == '.asm':
            asm_file = input_path
        elif input_path.suffix in ['.exe', '.dll']:
            # Need to disassemble first
            print(f"[*] Disassembling {input_path.name}...")
            asm_file = input_path.with_suffix('.asm')
            
            result = subprocess.run(
                ['./disassemble_clean.sh', str(input_path), str(asm_file)],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"[✗] Disassembly failed")
                return None
        else:
            print(f"[✗] Unsupported file type: {input_path.suffix}")
            return None
        
        # Parse with MEEF
        print(f"[*] Parsing with MEEF compiler...")
        ir_file = Path('output/temp_predict_ir.json')
        ir_file.parent.mkdir(parents=True, exist_ok=True)
        
        result = subprocess.run(
            ['./src/cd_frontend/meef_parser', str(asm_file), str(ir_file)],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0 or not ir_file.exists():
            print(f"[✗] Parsing failed")
            return None
        
        print(f"[✓] IR generated successfully")
        return ir_file
    
    def extract_features(self, ir_path):
        """Extract features from IR file"""
        try:
            with open(ir_path, 'r') as f:
                ir = json.load(f)
            
            features = []
            feature_names = self.metadata['feature_names']
            
            # Build feature vector in same order as training
            for feat_name in feature_names:
                if feat_name.startswith('uses_'):
                    # Behavioral features
                    behavior_key = feat_name.replace('uses_', '')
                    features.append(ir['behavior'].get(f'uses_{behavior_key}', 0))
                    
                elif feat_name.startswith('cfg_'):
                    # CFG features
                    cfg_key = feat_name.replace('cfg_', '')
                    features.append(ir['cfg'].get(cfg_key, 0))
                    
                elif feat_name == 'num_unique_apis':
                    features.append(len(ir.get('apis', [])))
                    
                elif feat_name == 'total_api_calls':
                    features.append(sum(api.get('count', 0) for api in ir.get('apis', [])))
                    
                elif feat_name.startswith('top_api_'):
                    # Top API counts
                    idx = int(feat_name.split('_')[-2]) - 1
                    apis = ir.get('apis', [])
                    sorted_apis = sorted(apis, key=lambda x: x.get('count', 0), reverse=True)
                    features.append(sorted_apis[idx]['count'] if idx < len(sorted_apis) else 0)
                    
                elif feat_name == 'num_unique_opcodes':
                    features.append(len(ir.get('opcodes', [])))
                    
                elif feat_name == 'total_opcodes':
                    features.append(sum(op.get('count', 0) for op in ir.get('opcodes', [])))
                    
                elif feat_name.startswith('opcode_'):
                    # Specific opcode counts
                    opcode_name = feat_name.replace('opcode_', '').replace('_count', '').upper()
                    opcodes = {op['name']: op['count'] for op in ir.get('opcodes', [])}
                    features.append(opcodes.get(opcode_name, 0))
                    
                elif feat_name in ['call_ratio', 'jmp_ratio', 'api_to_opcode_ratio']:
                    # Derived ratios
                    total_opcodes = sum(op.get('count', 0) for op in ir.get('opcodes', []))
                    if total_opcodes > 0:
                        if feat_name == 'call_ratio':
                            opcodes = {op['name']: op['count'] for op in ir.get('opcodes', [])}
                            features.append(opcodes.get('CALL', 0) / total_opcodes)
                        elif feat_name == 'jmp_ratio':
                            opcodes = {op['name']: op['count'] for op in ir.get('opcodes', [])}
                            features.append(opcodes.get('JMP', 0) / total_opcodes)
                        elif feat_name == 'api_to_opcode_ratio':
                            total_apis = sum(api.get('count', 0) for api in ir.get('apis', []))
                            features.append(total_apis / total_opcodes)
                    else:
                        features.append(0.0)
                else:
                    features.append(0)
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            print(f"[✗] Error extracting features: {e}")
            return None
    
    def predict(self, features):
        """Make prediction"""
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Predict
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        
        return prediction, probability
    
    def display_results(self, prediction, probability, input_path):
        """Display prediction results"""
        print("\n╔══════════════════════════════════════════════════════════╗")
        print("║                   Prediction Results                     ║")
        print("╠══════════════════════════════════════════════════════════╣")
        print(f"║ File: {Path(input_path).name[:50]:<50} ║")
        print("╠══════════════════════════════════════════════════════════╣")
        
        if prediction == 1:
            print(f"║ Classification: 🚨 MALICIOUS                             ║")
            print(f"║ Confidence:     {probability[1]*100:5.2f}%                                  ║")
        else:
            print(f"║ Classification: ✅ BENIGN                                ║")
            print(f"║ Confidence:     {probability[0]*100:5.2f}%                                  ║")
        
        print("╠══════════════════════════════════════════════════════════╣")
        print(f"║ Malicious probability: {probability[1]*100:5.2f}%                          ║")
        print(f"║ Benign probability:    {probability[0]*100:5.2f}%                          ║")
        print("╚══════════════════════════════════════════════════════════╝")
        
        # Risk assessment
        if probability[1] >= 0.9:
            risk = "🔴 CRITICAL"
        elif probability[1] >= 0.7:
            risk = "🟠 HIGH"
        elif probability[1] >= 0.5:
            risk = "🟡 MEDIUM"
        else:
            risk = "🟢 LOW"
        
        print(f"\nRisk Level: {risk}")
    
    def run(self, input_path):
        """Run prediction pipeline"""
        print("╔══════════════════════════════════════════════════════════╗")
        print("║              MEEF Malware Prediction                     ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print()
        
        # Load model
        if not self.load_model():
            return False
        
        # Process sample
        print(f"\n[*] Processing: {input_path}")
        ir_file = self.process_sample(input_path)
        
        if ir_file is None:
            return False
        
        # Extract features
        print(f"[*] Extracting features...")
        features = self.extract_features(ir_file)
        
        if features is None:
            return False
        
        # Predict
        print(f"[*] Running prediction...")
        prediction, probability = self.predict(features)
        
        # Display results
        self.display_results(prediction, probability, input_path)
        
        return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 predict.py <file.exe|file.asm>")
        print("\nExamples:")
        print("  python3 predict.py samples/malicious/trojan.exe")
        print("  python3 predict.py samples/benign/calc.asm")
        sys.exit(1)
    
    input_path = sys.argv[1]
    
    if not Path(input_path).exists():
        print(f"[✗] File not found: {input_path}")
        sys.exit(1)
    
    predictor = MalwarePredictor()
    success = predictor.run(input_path)
    sys.exit(0 if success else 1)

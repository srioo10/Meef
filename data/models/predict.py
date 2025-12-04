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
import os
import shlex
from sklearn.pipeline import Pipeline

class MalwarePredictor:
    def __init__(self, model_dir=None):
        # Default to the models directory next to this file
        if model_dir is None:
            model_dir = Path(__file__).parent
        self.model_dir = Path(model_dir)
        self.model = None
        self.scaler = None
        self.metadata = None
        
    def _windows_to_wsl(self, p):
        """Convert a Windows path (C:\\...) to a WSL path (/mnt/c/...)"""
        p = str(Path(p).resolve())
        # If already looks like WSL path, return with forward slashes
        if p.startswith('/'):
            return p.replace('\\', '/')
        if ':' in p:
            drive, rest = p.split(':', 1)
            drive = drive.lower()
            rest = rest.replace('\\', '/')
            # ensure leading slash on rest
            if not rest.startswith('/'):
                rest = '/' + rest
            return f"/mnt/{drive}{rest}"
        return p.replace('\\', '/')


        
    def load_model(self):
        """Load trained model"""
        try:
            model_path = self.model_dir / "malware_classifier.pkl"
            scaler_path = self.model_dir / "feature_scaler.pkl"
            metadata_path = self.model_dir / "model_metadata.json"
            
            self.model = joblib.load(model_path)
            # If the saved model is a Pipeline that already includes a scaler step,
            # do not load/apply an external scaler (to avoid double-scaling).
            try:
                # model may be a Pipeline (contains scaler step) or a calibrated wrapper
                base_est = None
                if isinstance(self.model, Pipeline):
                    base_est = self.model
                else:
                    # CalibratedClassifierCV may have attribute base_estimator or estimator
                    base_est = getattr(self.model, 'base_estimator', None) or getattr(self.model, 'estimator', None)

                if isinstance(base_est, Pipeline) and 'scaler' in getattr(base_est, 'named_steps', {}):
                    self.scaler = None
                else:
                    # load external scaler if present
                    if (self.model_dir / 'feature_scaler.pkl').exists():
                        self.scaler = joblib.load(scaler_path)
                    else:
                        self.scaler = None
            except Exception:
                # fallback: try to load external scaler if available
                if (self.model_dir / 'feature_scaler.pkl').exists():
                    self.scaler = joblib.load(scaler_path)
                else:
                    self.scaler = None
            
            with open(metadata_path, 'r') as f:
                self.metadata = json.load(f)
            
            # Determine a representative accuracy for logging – prefer test accuracy if present
            metrics = self.metadata.get('metrics', {})
            accuracy = None
            if isinstance(metrics, dict):
                if 'test' in metrics and isinstance(metrics['test'], dict) and 'accuracy' in metrics['test']:
                    accuracy = metrics['test']['accuracy']
                elif 'validation' in metrics and isinstance(metrics['validation'], dict) and 'accuracy' in metrics['validation']:
                    accuracy = metrics['validation']['accuracy']
                elif 'accuracy' in metrics:
                    accuracy = metrics['accuracy']
            if accuracy is None:
                accuracy = 0.0
            print(f"[✓] Model loaded successfully")
<<<<<<< Updated upstream
            print(f"    Test accuracy: {self.metadata['test_metrics']['accuracy']*100:.2f}%")
=======
            print(f"    Accuracy: {accuracy*100:.2f}%")
>>>>>>> Stashed changes
            return True
            
        except Exception as e:
            print(f"[✗] Error loading model: {e}")
            print(f"    Train a model first: python3 train_model.py")
            return False
    
    def _run_cmd(self, args, cwd=None, timeout=None):
        if os.name == 'nt':
            cmd_str = ' '.join(shlex.quote(a) for a in args)
            wsl_cmd = ['wsl', 'bash', '-lc', cmd_str]
            return subprocess.run(
                wsl_cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout
            )
        else:
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout
            )

    
    
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

            # Try to find a disassembly script
            possible_scripts = [
                Path.cwd() / 'disassemble_clean.sh',
                Path.cwd() / 'disassemble.sh',
                Path(__file__).parent.parent.parent / 'disassemble.sh',
                Path(__file__).parent.parent.parent / 'disassemble_clean.sh',
            ]
            disasm_script = next((p for p in possible_scripts if p.exists()), None)
            if disasm_script is None:
                print("[✗] Disassembly script not found (disassemble.sh / disassemble_clean.sh)")
                return None

            try:
                if os.name == 'nt':
                    w_input = self._windows_to_wsl(input_path)
                    w_output = self._windows_to_wsl(asm_file)
                    w_script = self._windows_to_wsl(disasm_script)
                    result = self._run_cmd([w_script, w_input, w_output], timeout=120)
                else:
                    result = self._run_cmd([str(disasm_script), str(input_path), str(asm_file)], timeout=120)
            except Exception as e:
                print(f"[✗] Disassembly failed: {e}")
                return None

            if result.returncode != 0:
                msg = (result.stderr or result.stdout or '').strip()
                print(f"[✗] Disassembly failed: {msg}")
                return None
        else:
            print(f"[✗] Unsupported file type: {input_path.suffix}")
            return None
        
        # Parse with MEEF
        # Parse with MEEF
        print(f"[*] Parsing with MEEF compiler...")
        import uuid
        ir_file = Path(f'output/temp_ir_{uuid.uuid4().hex}.json')
        ir_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Ensure clean state
        if ir_file.exists():
            ir_file.unlink()
        
        # Locate the meef parser binary
        parser_bin = Path.cwd() / 'src' / 'cd_frontend' / 'meef_parser'
        if not parser_bin.exists():
            # try relative to this file
            parser_bin = Path(__file__).parent.parent.parent / 'src' / 'cd_frontend' / 'meef_parser'

        try:
            if os.name == 'nt':
                w_parser = self._windows_to_wsl(parser_bin)
                w_asm = self._windows_to_wsl(asm_file)
                w_ir = self._windows_to_wsl(ir_file)
                result = self._run_cmd([w_parser, w_asm, w_ir], timeout=60)
            else:
                result = self._run_cmd([str(parser_bin), str(asm_file), str(ir_file)], timeout=60)
        except Exception as e:
            print(f"[✗] Parsing failed: {e}")
            return None

        if result.returncode != 0 or not ir_file.exists():
            msg = (result.stderr or result.stdout or '').strip()
            print(f"[✗] Parsing failed: {msg}")
            return None
        
        
        # Verify IR file was created and has content
        if not ir_file.exists():
            print(f"[✗] IR file was not created: {ir_file}")
            return None
        
        if ir_file.stat().st_size == 0:
            print(f"[✗] IR file is empty: {ir_file}")
            return None
            
        print(f"[✓] IR generated successfully: {ir_file.name}")
        return ir_file
    
    def extract_features(self, ir_path):
        """Extract features from IR file"""
        try:
            with open(ir_path, 'r') as f:
                ir = json.load(f)
            
            features = []
            # Handle both 'feature_names' and legacy 'features' key for backward compatibility
            feature_names = self.metadata.get('feature_names') or self.metadata.get('features')
            if not feature_names:
                raise KeyError('Neither feature_names nor features found in metadata')
            
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
            
            feature_array = np.array(features).reshape(1, -1)
            
            # Diagnostic output - show feature diversity
            print(f"[*] Extracted {len(features)} features")
            print(f"    Feature range: [{feature_array.min():.2f}, {feature_array.max():.2f}]")
            print(f"    Non-zero features: {np.count_nonzero(feature_array)}")
            print(f"    First 5 features: {feature_array[0][:5]}")
            
            return feature_array
            
        except Exception as e:
            print(f"[✗] Error extracting features: {e}")
            return None
    
    def predict(self, features):
        """Make prediction"""
        # If an external scaler is present (and the model doesn't already include scaling), apply it.
        if self.scaler is not None:
            features_input = self.scaler.transform(features)
        else:
            # model may include its own scaler inside a Pipeline
            features_input = features

        # Predict
        prediction = self.model.predict(features_input)[0]
        probability = self.model.predict_proba(features_input)[0]
        
        return prediction, probability
    
    def explain_prediction(self, features, top_n=5):
        """
        Explain why a sample was classified as it was.
        Returns a list of (feature_name, importance_score, value) tuples.
        """
        try:
            # Get feature names
            feature_names = self.metadata.get('feature_names') or self.metadata.get('features')
            if not feature_names:
                return []

            # Get feature importances from the model
            importances = None
            if hasattr(self.model, 'feature_importances_'):
                importances = self.model.feature_importances_
            elif hasattr(self.model, 'best_estimator_'): # If it's a grid search result
                if hasattr(self.model.best_estimator_, 'feature_importances_'):
                    importances = self.model.best_estimator_.feature_importances_
            
            if importances is None:
                return []

            # Normalize features for explanation (if scaler exists)
            # We want to know if a feature is "high" relative to normal
            if self.scaler:
                # Use the scaled values to see deviation from mean
                features_scaled = self.scaler.transform(features)[0]
            else:
                features_scaled = features[0]

            # Calculate contribution: Importance * Value (magnitude)
            # We focus on features that are both IMPORTANT and HAVE A HIGH VALUE in this sample
            contributions = []
            for i, (name, importance) in enumerate(zip(feature_names, importances)):
                val = features[0][i] # Original value
                scaled_val = features_scaled[i] # Deviation from mean
                
                # Heuristic: Contribution = Importance * Scaled_Value
                # Only consider positive deviations (features that are higher than average)
                # or binary features that are present (1.0)
                score = importance * max(0, scaled_val)
                
                contributions.append({
                    'name': name,
                    'importance': importance,
                    'value': val,
                    'score': score,
                    'description': self._get_feature_description(name, val)
                })

            # Sort by score descending
            contributions.sort(key=lambda x: x['score'], reverse=True)
            
            return contributions[:top_n]

        except Exception as e:
            print(f"[!] Explanation failed: {e}")
            return []

    def _get_feature_description(self, feature_name, value):
        """Generate a human-readable description for a feature"""
        descriptions = {
            'uses_network': "Network activity detected",
            'uses_fileops': "File system operations detected",
            'uses_registry': "Registry manipulation detected",
            'uses_memory': "Direct memory manipulation",
            'uses_injection': "Code injection capabilities",
            'uses_crypto': "Cryptographic operations detected",
            'uses_persist': "Persistence mechanisms detected",
            'cfg_num_blocks': "Complex control flow (Blocks)",
            'cfg_num_edges': "Complex control flow (Edges)",
            'cfg_cyclomatic_complexity': "High code complexity",
            'num_unique_apis': "High number of unique APIs",
            'total_api_calls': "High volume of API calls",
            'num_unique_opcodes': "Diverse instruction set",
            'call_ratio': "High function call frequency",
            'jmp_ratio': "High jump/branch frequency",
            'api_to_opcode_ratio': "High API usage density"
        }
        
        base_desc = descriptions.get(feature_name, feature_name.replace('_', ' ').title())
        
        # Add context based on value
        if feature_name.startswith('uses_'):
            return base_desc if value > 0 else f"No {base_desc.lower()}"
        elif 'count' in feature_name or 'num' in feature_name:
            return f"{base_desc} ({int(value)})"
        else:
            return f"{base_desc} ({value:.2f})"
    
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

        # Debug: show raw feature vector with names to verify alignment
        try:
            feature_names = self.metadata.get('feature_names') or self.metadata.get('features', [])
            print("[*] Raw feature vector:")
            for name, val in zip(feature_names, features.flatten()):
                print(f"  {name}: {val}")
        except Exception:
            print("[*] (Could not print feature names)")

        # Scale features and show a short preview of scaled values
        try:
            features_scaled = self.scaler.transform(features)
            flat = features_scaled.flatten()
            preview = ', '.join(f"{x:.4f}" for x in flat[:8])
            print(f"[*] Scaled features (first 8): {preview} ...")
        except Exception as e:
            print(f"[✗] Error scaling features: {e}")
            return False

        # Predict using scaled features
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        
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

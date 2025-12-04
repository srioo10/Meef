#!/usr/bin/env python3
"""
Diagnostic script to check model probability outputs
"""

import joblib
import json
import numpy as np
from pathlib import Path

print("=" * 60)
print("Model Probability Diagnostic Tool")
print("=" * 60)
print()

# Load the model
model_path = Path("data/models/malware_classifier.pkl")
metadata_path = Path("data/models/model_metadata.json")

if not model_path.exists():
    print(f"❌ Model not found at {model_path}")
    print("Please train the model first: python data/models/train_model.py")
    exit(1)

print(f"[1] Loading model from {model_path}...")
model = joblib.load(model_path)

with open(metadata_path, 'r') as f:
    metadata = json.load(f)

print(f"✅ Model loaded: {metadata['model_type']}")
print(f"   Features: {metadata['num_features']}")
print(f"   Accuracy: {metadata['metrics']['accuracy']*100:.2f}%")
print()

# Check model type
print("[2] Checking model structure...")
print(f"   Model type: {type(model).__name__}")

# Check if it's a pipeline or calibrated
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV

if isinstance(model, CalibratedClassifierCV):
    print("   ✅ Model is calibrated (CalibratedClassifierCV)")
    base = model.base_estimator if hasattr(model, 'base_estimator') else model.estimator
    print(f"   Base estimator: {type(base).__name__}")
    
    if isinstance(base, Pipeline):
        print("   Pipeline steps:")
        for name, step in base.named_steps.items():
            print(f"     - {name}: {type(step).__name__}")
elif isinstance(model, Pipeline):
    print("   ✅ Model is a Pipeline")
    print("   Pipeline steps:")
    for name, step in model.named_steps.items():
        print(f"     - {name}: {type(step).__name__}")
else:
    print(f"   ⚠️  Model is just: {type(model).__name__}")

print()

# Create a test sample (random features)
print("[3] Testing prediction with random sample...")
num_features = metadata['num_features']
test_sample = np.random.randn(1, num_features)

print(f"   Test sample shape: {test_sample.shape}")

# Make prediction
try:
    prediction = model.predict(test_sample)[0]
    print(f"   ✅ Prediction: {prediction} ({'Malware' if prediction == 1 else 'Benign'})")
except Exception as e:
    print(f"   ❌ Prediction failed: {e}")
    exit(1)

# Get probabilities
try:
    probabilities = model.predict_proba(test_sample)[0]
    print(f"   ✅ Probabilities: {probabilities}")
    print(f"      - Benign:  {probabilities[0]:.6f} ({probabilities[0]*100:.2f}%)")
    print(f"      - Malware: {probabilities[1]:.6f} ({probabilities[1]*100:.2f}%)")
    
    # Check if probabilities are reasonable
    if np.allclose(probabilities[0], 1.0) or np.allclose(probabilities[1], 1.0):
        print("   ⚠️  WARNING: Probabilities are at extreme (0 or 1)!")
        print("       This suggests the model is overconfident.")
    elif np.abs(probabilities[0] - probabilities[1]) < 0.1:
        print("   ✅ Probabilities are balanced (uncertainty present)")
    else:
        print("   ✅ Probabilities look reasonable")
        
except Exception as e:
    print(f"   ❌ predict_proba failed: {e}")
    exit(1)

print()

# Test with multiple random samples
print("[4] Testing with 10 random samples...")
test_samples = np.random.randn(10, num_features)

predictions = model.predict(test_samples)
probabilities = model.predict_proba(test_samples)

print("   Results:")
for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
    max_prob = max(prob)
    print(f"   Sample {i+1}: Class={pred}, Confidence={max_prob*100:.2f}% | Probs=[{prob[0]:.4f}, {prob[1]:.4f}]")

# Statistics
max_probs = np.max(probabilities, axis=1)
print()
print("   Statistics:")
print(f"   - Mean confidence: {np.mean(max_probs)*100:.2f}%")
print(f"   - Min confidence:  {np.min(max_probs)*100:.2f}%")
print(f"   - Max confidence:  {np.max(max_probs)*100:.2f}%")

if np.all(max_probs > 0.95):
    print("   ⚠️  WARNING: All predictions have >95% confidence!")
    print("       This suggests:")
    print("       1. Model may be overfitted")
    print("       2. Random features are too different from training data")
    print("       3. Calibration may not be working")
elif np.all(max_probs == 1.0):
    print("   ❌ CRITICAL: All predictions are 100% confident!")
    print("       The model is NOT returning proper probabilities.")
    print("       Possible issues:")
    print("       - SVM trained without probability=True")
    print("       - Calibration failed")
    print("       - Model was not saved correctly")
else:
    print("   ✅ Confidence distribution looks normal")

print()
print("=" * 60)
print("Diagnostic complete!")
print("=" * 60)

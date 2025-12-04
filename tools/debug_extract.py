from importlib import util
from pathlib import Path

predict_path = Path('data/models/predict.py').resolve()
spec = util.spec_from_file_location('predict', str(predict_path))
mod = util.module_from_spec(spec)
spec.loader.exec_module(mod)

MalwarePredictor = mod.MalwarePredictor
p = MalwarePredictor()
if not p.load_model():
    print('Failed to load model')
else:
    ir = 'output/ir_results/calc_ir.json'
    features = p.extract_features(ir)
    print('\nExtracted feature vector shape:', None if features is None else features.shape)
    print('Feature vector (raw):')
    if features is not None:
        print(features)
    
    # Also show scaled preview
    if p.scaler is not None and features is not None:
        scaled = p.scaler.transform(features)
        print('\nScaled (first 8):', scaled.flatten()[:8])

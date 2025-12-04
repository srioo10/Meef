import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.metrics import brier_score_loss
from sklearn.calibration import CalibratedClassifierCV
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

MODEL_DIR = Path(__file__).parent
FEATURES_CSV = MODEL_DIR.parent / 'features_ml.csv'

def load_artifacts():
    model = joblib.load(MODEL_DIR / 'malware_classifier.pkl')
    scaler = joblib.load(MODEL_DIR / 'feature_scaler.pkl')
    with open(MODEL_DIR / 'model_metadata.json','r') as f:
        meta = json.load(f)
    return model, scaler, meta


def load_data():
    df = pd.read_csv(str(FEATURES_CSV))
    exclude = ['sha256','label','label_binary']
    feature_cols = [c for c in df.columns if c not in exclude]
    X = df[feature_cols].values
    y = df['label_binary'].values
    return df, feature_cols, X, y


def main():
    print('[*] Loading artifacts and data...')
    model, scaler, meta = load_artifacts()
    df, feature_cols, X, y = load_data()
    print(f'[*] Dataset shape: {X.shape}, Labels distribution:', np.bincount(y))
    print(f"[*] Metadata keys: {list(meta.keys())}")
    # Check feature order agreement
    meta_feat = meta.get('feature_names') or meta.get('features')
    same = (list(feature_cols) == list(meta_feat))
    print(f'[*] feature_cols == metadata.feature_names ? {same}')
    if not same:
        print('\nDifferences (first 12):')
        for i, (a, b) in enumerate(zip(feature_cols, meta_feat)):
            if a != b:
                print(f' idx {i}: csv={a} meta={b}')
                if i>12:
                    break
    if 'metrics' in meta:
        print('[*] Metadata.metrics:', meta.get('metrics'))
    if 'num_features' in meta:
        print('[*] num_features:', meta.get('num_features'))

    # Decide whether to apply external scaler or let model pipeline handle scaling
    model_has_internal_scaler = False
    try:
        from sklearn.pipeline import Pipeline
        if isinstance(model, Pipeline) and 'scaler' in getattr(model, 'named_steps', {}):
            model_has_internal_scaler = True
        else:
            # If the model is a calibrated wrapper, inspect the base_estimator
            if isinstance(model, CalibratedClassifierCV):
                base = getattr(model, 'base_estimator', None) or getattr(model, 'estimator', None)
                if isinstance(base, Pipeline) and 'scaler' in getattr(base, 'named_steps', {}):
                    model_has_internal_scaler = True
    except Exception:
        model_has_internal_scaler = False

    use_external_scaler = (scaler is not None) and (not model_has_internal_scaler)

    if use_external_scaler:
        Xs = scaler.transform(X)
    else:
        # model will perform scaling internally (or no scaling is applied)
        Xs = X

    # Predictions
    if hasattr(model, 'predict_proba'):
        probs = model.predict_proba(Xs)
        preds = model.predict(Xs)
    else:
        # some models don't have predict_proba (e.g., some SVC without prob)
        preds = model.predict(Xs)
        probs = None

    print('[*] Prediction distribution:', np.bincount(preds))

    # Confusion on whole dataset
    print('\nConfusion matrix on whole dataset:')
    print(confusion_matrix(y, preds))
    print('\nClassification report (whole dataset):')
    print(classification_report(y, preds, zero_division=0))

    # Probability stats if available
    if probs is not None:
        mal_probs = probs[:,1]
        print('\nProbability stats for malicious class:')
        print(' min, 25%, median, 75%, max =', np.min(mal_probs), np.percentile(mal_probs, [25,50,75]), np.max(mal_probs))
        # show fraction with extreme probabilities
        print('Fraction with prob>0.99 =', np.mean(mal_probs>0.99))
        print('Fraction with prob<0.01 =', np.mean(mal_probs<0.01))

        # Save histogram of malicious probabilities
        outdir = Path(__file__).parent.parent.parent / 'output' / 'diagnostics'
        outdir.mkdir(parents=True, exist_ok=True)
        plt.figure(figsize=(6,4))
        plt.hist(mal_probs, bins=50, range=(0,1), color='C0', alpha=0.8)
        plt.title('Histogram of malicious class probabilities (proba of class=1)')
        plt.xlabel('Probability (class=1)')
        plt.ylabel('Count')
        plt.grid(False)
        hist_path = outdir / 'proba_hist.png'
        plt.savefig(hist_path, bbox_inches='tight')
        plt.close()
        print(f'[*] Saved probability histogram → {hist_path}')

        # Brier score
        brier = brier_score_loss(y, mal_probs)
        print('[*] Brier score:', brier)

        # Decision function stats (if available)
        try:
            if hasattr(model, 'decision_function'):
                dec = model.decision_function(Xs)
                print('[*] Decision function percentiles:', np.percentile(dec, [0,1,5,25,50,75,95,99,100]))
        except Exception as e:
            print('[✗] Could not compute decision function stats:', e)

        # Calibration curve values (fraction of positives vs mean predicted in bins)
        try:
            from sklearn.calibration import calibration_curve
            prob_true, prob_pred = calibration_curve(y, mal_probs, n_bins=10)
            print('[*] Calibration bins (fraction true vs mean predicted):')
            for pt, pp in zip(prob_true, prob_pred):
                print(f'    {pp:.3f} -> {pt:.3f}')
            # Save calibration plot
            plt.figure(figsize=(5,5))
            plt.plot(prob_pred, prob_true, marker='o')
            plt.plot([0,1],[0,1],'k--', linewidth=0.5)
            plt.xlabel('Mean predicted probability')
            plt.ylabel('Fraction of positives')
            plt.title('Calibration curve')
            calib_path = outdir / 'calibration_curve.png'
            plt.savefig(calib_path, bbox_inches='tight')
            plt.close()
            print(f'[*] Saved calibration plot → {calib_path}')
        except Exception as e:
            print('[✗] Could not compute calibration curve:', e)

    # Sample a few rows and show features + scaled + probs
    print('\nSample predictions (first 10 rows):')
    for i in range(10):
        row = X[i:i+1]
        row_s = Xs[i:i+1]
        p = preds[i]
        prob = probs[i,1] if probs is not None else None
        print(f'idx={i} label={y[i]} pred={p} prob={prob}')
        print('  raw first 8:', row.flatten()[:8])
        print('  scaled first 8:', row_s.flatten()[:8])

    # Per-feature separation stats
    print('\nPer-feature separation (top 12 by abs mean difference):')
    X0 = X[y==0]
    X1 = X[y==1]
    mean0 = X0.mean(axis=0)
    mean1 = X1.mean(axis=0)
    std_all = X.std(axis=0, ddof=0)
    # avoid divide by zero
    std_all[std_all==0] = 1.0
    # standardized mean difference
    smd = (mean1 - mean0) / std_all
    feats = feature_cols
    pairs = list(zip(feats, mean0, mean1, smd))
    pairs_sorted = sorted(pairs, key=lambda x: abs(x[3]), reverse=True)
    for name, m0, m1, d in pairs_sorted[:12]:
        print(f'{name}: mean0={m0:.3f} mean1={m1:.3f} smd={d:.3f}')
if __name__=='__main__':
    main()

#!/usr/bin/env python3
"""
Train ML model for malware detection
Uses features extracted from compiler IR
70% train, 15% validation, 15% test split
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (classification_report, confusion_matrix,
                             accuracy_score, precision_score, recall_score, f1_score, roc_auc_score)
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path
import json
import sys


class MalwareClassifier:
    def __init__(self, features_path=None, model_dir=None):
        repo_data_dir = Path(__file__).parent.parent  # data/
        if features_path is None:
            features_path = repo_data_dir / 'features_ml.csv'
        if model_dir is None:
            model_dir = Path(__file__).parent

        self.features_path = Path(features_path)
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        self.model = None
        self.scaler = None
        self.feature_names = None

    def load_features(self):
        try:
            if not self.features_path.exists():
                raise FileNotFoundError(f"Features file not found: {self.features_path}")

            df = pd.read_csv(str(self.features_path))
            print(f"[✓] Loaded features: {len(df)} samples, {len(df.columns)} columns")
            return df
        except Exception as e:
            print(f"[✗] Error loading features: {e}")
            return None

    def prepare_data(self, df):
        exclude_cols = ['sha256', 'label', 'label_binary']
        feature_cols = [col for col in df.columns if col not in exclude_cols]

        X = df[feature_cols].values
        y = df['label_binary'].values

        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        self.feature_names = feature_cols

        print(f"[✓] Prepared {len(feature_cols)} features")
        print(f"    Class distribution: Benign={np.sum(y == 0)}, Malicious={np.sum(y == 1)}")

        return X, y

    def train_model(self, X_train, y_train):
        print("\n[*] Training Random Forest classifier...")

        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)

        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )

        self.model.fit(X_train_scaled, y_train)
        print(f"[✓] Model trained with {self.model.n_estimators} trees")
        return X_train_scaled
<<<<<<< Updated upstream
    
    def evaluate_model(self, X_set, y_set, set_name="Test"):
        """Evaluate model performance on a dataset"""
        print(f"\n[*] Evaluating on {set_name} set...")
        
        X_set_scaled = self.scaler.transform(X_set)
        
        # Predictions
        y_pred = self.model.predict(X_set_scaled)
        y_pred_proba = self.model.predict_proba(X_set_scaled)[:, 1]
        
        # Metrics
        accuracy = accuracy_score(y_set, y_pred)
        precision = precision_score(y_set, y_pred, zero_division=0)
        recall = recall_score(y_set, y_pred, zero_division=0)
        f1 = f1_score(y_set, y_pred, zero_division=0)
        
        try:
            auc = roc_auc_score(y_set, y_pred_proba)
=======

    def evaluate_model(self, X, y, title="Test Set"):
        print(f"\n[*] Evaluating model on {title}...")

        X_scaled = self.scaler.transform(X)

        y_pred = self.model.predict(X_scaled)
        y_proba = self.model.predict_proba(X_scaled)[:, 1]

        accuracy = accuracy_score(y, y_pred)
        precision = precision_score(y, y_pred, zero_division=0)
        recall = recall_score(y, y_pred, zero_division=0)
        f1 = f1_score(y, y_pred, zero_division=0)

        try:
            auc = roc_auc_score(y, y_proba)
>>>>>>> Stashed changes
        except:
            auc = 0.0

        print(f"\n╔══════════════════════════════════════════════════════════╗")
<<<<<<< Updated upstream
        print(f"║            {set_name} Set Performance                         ║")
=======
        print(f"║        Performance on {title:<20}              ║")
>>>>>>> Stashed changes
        print(f"╠══════════════════════════════════════════════════════════╣")
        print(f"║ Accuracy:  {accuracy*100:6.2f}%                                        ║")
        print(f"║ Precision: {precision*100:6.2f}%                                        ║")
        print(f"║ Recall:    {recall*100:6.2f}%                                        ║")
        print(f"║ F1-Score:  {f1*100:6.2f}%                                        ║")
        print(f"║ AUC-ROC:   {auc*100:6.2f}%                                        ║")
        print(f"╚══════════════════════════════════════════════════════════╝")
<<<<<<< Updated upstream
        
        # Confusion Matrix
        cm = confusion_matrix(y_set, y_pred)
        print(f"\nConfusion Matrix ({set_name}):")
        print(f"                Predicted")
        print(f"              Benign  Malicious")
        print(f"Actual Benign    {cm[0][0]:4d}     {cm[0][1]:4d}")
        print(f"     Malicious   {cm[1][0]:4d}     {cm[1][1]:4d}")
        
=======

        print("\nConfusion Matrix:")
        cm = confusion_matrix(y, y_pred)
        print(cm)

        print("\nClassification Report:")
        print(classification_report(y, y_pred,
                                   target_names=['Benign', 'Malicious'],
                                   zero_division=0))

>>>>>>> Stashed changes
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'auc': auc,
            'confusion_matrix': cm.tolist()
        }
<<<<<<< Updated upstream
    
    def show_feature_importance(self, top_n=15):
        """Show most important features"""
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print(f"\n📊 Top {top_n} Most Important Features:")
        print(f"{'Rank':<6} {'Feature':<35} {'Importance':<12}")
        print("=" * 55)
        
        for i in range(min(top_n, len(indices))):
            idx = indices[i]
            print(f"{i+1:<6} {self.feature_names[idx]:<35} {importances[idx]:.4f}")
    
    def save_model(self, train_metrics, val_metrics, test_metrics):
        """Save trained model and metadata"""
=======

    def save_model(self, metrics_all):
>>>>>>> Stashed changes
        try:
            model_path = self.model_dir / "malware_classifier.pkl"
            joblib.dump(self.model, model_path)
            print(f"[✓] Model saved to: {model_path}")

            scaler_path = self.model_dir / "feature_scaler.pkl"
            joblib.dump(self.scaler, scaler_path)
            print(f"[✓] Scaler saved to: {scaler_path}")

            metadata = {
                'feature_names': self.feature_names,
                'num_features': len(self.feature_names),
<<<<<<< Updated upstream
                'train_metrics': train_metrics,
                'validation_metrics': val_metrics,
                'test_metrics': test_metrics,
=======
                'metrics': metrics_all,
>>>>>>> Stashed changes
                'model_type': 'RandomForestClassifier',
                'n_estimators': self.model.n_estimators,
                'split_ratio': {
                    'train': 0.70,
                    'validation': 0.15,
                    'test': 0.15
                }
            }

            metadata_path = self.model_dir / "model_metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)

            print(f"[✓] Metadata saved to: {metadata_path}")
            return True

        except Exception as e:
            print(f"[✗] Error saving model: {e}")
            return False

    def run(self):
<<<<<<< Updated upstream
        """Run complete training pipeline with 70/15/15 split"""
        print("╔══════════════════════════════════════════════════════════╗")
        print("║              MEEF ML Model Training                      ║")
        print("║         70% Train | 15% Validation | 15% Test            ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print()
        
        # Load features
=======
        print("╔══════════════════════════════════════════════════════════╗")
        print("║              MEEF ML Model Training                      ║")
        print("╚══════════════════════════════════════════════════════════╝\n")

>>>>>>> Stashed changes
        df = self.load_features()
        if df is None or len(df) == 0:
            return False

        if len(df['label'].unique()) < 2:
            print("[✗] Need both benign and malicious samples")
            return False

        X, y = self.prepare_data(df)
<<<<<<< Updated upstream
        
        # Split data: 70% train, 30% temp (which becomes 15% val + 15% test)
        print(f"\n[*] Splitting data (70% train, 15% validation, 15% test)...")
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=0.30, random_state=42, stratify=y
        )
        
        # Split temp into validation and test (50/50 of temp = 15%/15% of total)
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
        )
        
        total_samples = len(X)
        print(f"[✓] Train set:      {len(X_train)} samples ({len(X_train)/total_samples*100:.1f}%)")
        print(f"[✓] Validation set: {len(X_val)} samples ({len(X_val)/total_samples*100:.1f}%)")
        print(f"[✓] Test set:       {len(X_test)} samples ({len(X_test)/total_samples*100:.1f}%)")
        
        print(f"\n[*] Class distribution:")
        print(f"    Train:      Benign={np.sum(y_train==0)}, Malicious={np.sum(y_train==1)}")
        print(f"    Validation: Benign={np.sum(y_val==0)}, Malicious={np.sum(y_val==1)}")
        print(f"    Test:       Benign={np.sum(y_test==0)}, Malicious={np.sum(y_test==1)}")
        
        # Train model
        X_train_scaled = self.train_model(X_train, y_train)
        
        # Cross-validation on training set
        print(f"\n[*] Running 5-fold cross-validation on training set...")
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5, scoring='accuracy')
        print(f"[✓] CV Accuracy: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")
        
        # Evaluate on all three sets
        train_metrics = self.evaluate_model(X_train, y_train, "Training")
        val_metrics = self.evaluate_model(X_val, y_val, "Validation")
        test_metrics = self.evaluate_model(X_test, y_test, "Test")
        
        # Show feature importance
        self.show_feature_importance()
        
        # Print detailed classification report for test set
        print(f"\n[*] Detailed Classification Report (Test Set):")
        X_test_scaled = self.scaler.transform(X_test)
        y_pred = self.model.predict(X_test_scaled)
        print(classification_report(y_test, y_pred, 
                                   target_names=['Benign', 'Malicious'],
                                   zero_division=0))
        
        # Summary comparison
        print(f"\n╔══════════════════════════════════════════════════════════╗")
        print(f"║                Performance Comparison                    ║")
        print(f"╠══════════════════════════════════════════════════════════╣")
        print(f"║ Dataset     │ Accuracy │ Precision │ Recall │ F1-Score  ║")
        print(f"╠═════════════╪══════════╪═══════════╪════════╪═══════════╣")
        print(f"║ Training    │  {train_metrics['accuracy']*100:5.2f}%  │   {train_metrics['precision']*100:5.2f}%  │ {train_metrics['recall']*100:5.2f}% │  {train_metrics['f1']*100:5.2f}%   ║")
        print(f"║ Validation  │  {val_metrics['accuracy']*100:5.2f}%  │   {val_metrics['precision']*100:5.2f}%  │ {val_metrics['recall']*100:5.2f}% │  {val_metrics['f1']*100:5.2f}%   ║")
        print(f"║ Test        │  {test_metrics['accuracy']*100:5.2f}%  │   {test_metrics['precision']*100:5.2f}%  │ {test_metrics['recall']*100:5.2f}% │  {test_metrics['f1']*100:5.2f}%   ║")
        print(f"╚══════════════════════════════════════════════════════════╝")
        
        # Check for overfitting
        train_acc = train_metrics['accuracy']
        val_acc = val_metrics['accuracy']
        test_acc = test_metrics['accuracy']
        
        print(f"\n[*] Overfitting Analysis:")
        if train_acc - val_acc > 0.05:
            print(f"    ⚠️  Train-Val gap: {(train_acc-val_acc)*100:.2f}% (Possible overfitting)")
        else:
            print(f"    ✅ Train-Val gap: {(train_acc-val_acc)*100:.2f}% (Good generalization)")
        
        if val_acc - test_acc > 0.05:
            print(f"    ⚠️  Val-Test gap: {(val_acc-test_acc)*100:.2f}% (Possible variance)")
        else:
            print(f"    ✅ Val-Test gap: {(val_acc-test_acc)*100:.2f}% (Consistent performance)")
        
        # Save model
        success = self.save_model(train_metrics, val_metrics, test_metrics)
        
        if success:
            print(f"\n[✓] Training complete!")
            print(f"    Model ready for predictions")
            print(f"    Final Test Accuracy: {test_acc*100:.2f}%")
            print(f"    Next step: python3 predict.py <sample.asm>")
        
=======

        print("\n[*] Splitting data into 70/15/15 (train/val/test)...")
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=0.30, random_state=42, stratify=y
        )

        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
        )

        print(f"[✓] Train:      {len(X_train)} samples")
        print(f"[✓] Validation: {len(X_val)} samples")
        print(f"[✓] Test:       {len(X_test)} samples")

        X_train_scaled = self.train_model(X_train, y_train)

        print("\n[*] Running 5-fold cross-validation...")
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5, scoring='accuracy')
        print(f"[✓] CV Accuracy: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")

        metrics_test = self.evaluate_model(X_test, y_test, "Test Set")
        metrics_val = self.evaluate_model(X_val, y_val, "Validation Set")

        metrics = {
            "test": metrics_test,
            "validation": metrics_val,
            "cv_accuracy_mean": float(cv_scores.mean()),
            "cv_accuracy_std": float(cv_scores.std())
        }

        success = self.save_model(metrics)
        if success:
            print("\n[✓] Training complete! Model ready for predictions.")

>>>>>>> Stashed changes
        return success


if __name__ == "__main__":
    classifier = MalwareClassifier()
    success = classifier.run()
    sys.exit(0 if success else 1)

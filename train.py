"""Train and evaluate the ARGUS-ONE Machine Learning models.

Generates the time-split benchmark dataset, trains Random Forest and
Gradient Boosted Trees (XGBoost), fits the Benign Anomaly Guard,
evaluates on held-out future traffic, and exports the CSV dataset files.

Usage:
    py -3.13 train.py
    py -3.13 train.py --runs-per-class 25
"""

import argparse
import sys
from pathlib import Path
import pandas as pd

# Add current folder to path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_ml


def main():
    parser = argparse.ArgumentParser(description="Train ARGUS-ONE ML Threat Classifiers")
    parser.add_argument("--runs-per-class", type=int, default=32, help="Samples per class for training")
    args = parser.parse_args()

    print(f"[*] Building time-split dataset ({args.runs_per_class} runs per class)...")
    X_train, y_train, X_test, y_test = argus_ml.build_ml_dataset(runs_per_class=args.runs_per_class)

    data_dir = ROOT / "ARGUS-ONE" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    # Export CSVs
    train_df = pd.DataFrame(X_train, columns=argus_ml.FEATURE_NAMES)
    train_df["label"] = y_train
    train_csv = data_dir / "ml_features_train.csv"
    train_df.to_csv(train_csv, index=False)

    test_df = pd.DataFrame(X_test, columns=argus_ml.FEATURE_NAMES)
    test_df["label"] = y_test
    test_csv = data_dir / "ml_features_test.csv"
    test_df.to_csv(test_csv, index=False)

    print(f"[+] Saved {len(train_df)} training records to: {train_csv.name}")
    print(f"[+] Saved {len(test_df)} testing records to: {test_csv.name}")

    print("\n[*] Training Random Forest and Gradient Boosted Models...")
    engine = argus_ml.get_ml_engine()
    metrics = engine.train(runs_per_class=args.runs_per_class)

    import numpy as np
    # Measure confidence scoring across test set
    confidences = []
    correct_count = 0
    for i in range(len(X_test)):
        feats = {argus_ml.FEATURE_NAMES[j]: float(X_test[i][j]) for j in range(len(argus_ml.FEATURE_NAMES))}
        p = engine.predict(feats)
        confidences.append(p.confidence)
        if p.threat_class == y_test[i]:
            correct_count += 1
    mean_conf = float(np.mean(confidences)) if confidences else 0.95
    pct_high_conf = float(np.mean([c >= 0.95 for c in confidences])) * 100.0

    print("\n=======================================================")
    print("           ARGUS-ONE MODEL EVALUATION RESULTS         ")
    print("=======================================================")
    for model_key, m in metrics.get("models", {}).items():
        print(f"\nModel: {m.get('name', model_key)}")
        print(f"  • Accuracy:        {m.get('accuracy', 0.0) * 100:.2f}%")
        print(f"  • Attack Recall:   {m.get('recall', 0.0) * 100:.2f}%")
        print(f"  • Precision:       {m.get('precision', 0.0) * 100:.2f}%")
        print(f"  • F1 Score:        {m.get('f1_score', 0.0):.4f}")
        print(f"  • Benign FPR:      {m.get('benign_false_positive_rate', 0.0) * 100:.2f}%")
        print(f"  • Latency:         {m.get('latency_ms', 0.0):.3f} ms/flow")

    print("\n[+] Confidence Scoring Analysis (Calibrated Decision Boundaries):")
    print(f"  • Mean Confidence:          {mean_conf * 100:.2f}%")
    print(f"  • High-Confidence (>=95%):  {pct_high_conf:.1f}% of all test flows")
    print(f"  • End-to-End Test Accuracy: {(correct_count / len(y_test)) * 100:.2f}%")

    print("\n[+] Top 5 Discriminative Features:")
    for feat, imp in metrics.get("top_features", [])[:5]:
        print(f"  • {feat:<24}: {imp * 100:.1f}%")

    print(f"\n[+] Active Engine: {engine.model_type.upper()}")
    print("=======================================================\n")


if __name__ == "__main__":
    main()

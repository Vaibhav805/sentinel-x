#!/usr/bin/env python3
"""
train_judge.py  —  Train the XGBoost Judge on CICIDS2017
Outputs: models/xgb_judge.json  (loaded by flux.py at runtime)

Usage:
    pip install xgboost scikit-learn pandas
    python train_judge.py --data /path/to/cicids2017/csvs/
"""

import argparse
import os
import glob
import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import LabelEncoder

# ── These are the 6 features flux.py computes in compute_features() ──────────
# They must map to CICIDS2017 columns (or be synthesised from them).
# Column names below match the trimmed CICIDS2017 header (spaces stripped).
CICIDS_FEATURE_MAP = {
    # our feature name        : CICIDS2017 column name (after strip)
    "entropy_ip"              : None,          # synthetic — see note below
    "pkt_rate"                : "Flow Packets/s",
    "unique_ips"              : None,          # synthetic
    "avg_pkt_size"            : "Average Packet Size",
    "tcp_ratio"               : None,          # synthetic from Protocol
    "udp_ratio"               : None,          # synthetic from Protocol
}

# CICIDS2017 label column
LABEL_COL = "Label"

# Attack labels to treat as MALICIOUS (everything else → BENIGN)
ATTACK_LABELS = {
    "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest",
    "DDoS",
    "PortScan",
    "FTP-Patator", "SSH-Patator",
    "Bot",
    "Web Attack – Brute Force",
    "Web Attack – XSS",
    "Web Attack – Sql Injection",
    "Infiltration",
    "Heartbleed",
}


def load_cicids(data_dir: str) -> pd.DataFrame:
    """Load and concatenate all CSVs in data_dir."""
    files = glob.glob(os.path.join(data_dir, "*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    print(f"[train_judge] Loading {len(files)} CSV(s)...")
    frames = []
    for f in files:
        df = pd.read_csv(f, encoding="utf-8", low_memory=False)
        df.columns = df.columns.str.strip()
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Map CICIDS2017 columns → the 6 features that flux.py computes live.

    entropy_ip  : CICIDS has no per-window IP entropy column, so we use
                  'Source IP' hashed → binned as a proxy (or set to 0 if absent).
    unique_ips  : Similarly approximated from flow-level data.
    tcp_ratio   : 1.0 if Protocol==6, else 0.0
    udp_ratio   : 1.0 if Protocol==17, else 0.0
    """
    out = pd.DataFrame()

    # pkt_rate
    col = "Flow Packets/s"
    out["pkt_rate"] = pd.to_numeric(df[col], errors="coerce").fillna(0).clip(0)

    # avg_pkt_size
    col = "Average Packet Size"
    if col in df.columns:
        out["avg_pkt_size"] = pd.to_numeric(df[col], errors="coerce").fillna(0).clip(0)
    else:
        # fallback: (Total Fwd + Bwd packets * avg len) / total pkts
        out["avg_pkt_size"] = 0.0

    # protocol ratios
    proto = pd.to_numeric(df.get("Protocol", pd.Series(0, index=df.index)),
                          errors="coerce").fillna(0).astype(int)
    out["tcp_ratio"] = (proto == 6).astype(float)
    out["udp_ratio"] = (proto == 17).astype(float)

    # entropy_ip — approximate using src-IP cardinality within the loaded batch
    if "Source IP" in df.columns:
        # encode IPs to integers, compute a rolling-style diversity proxy
        le = LabelEncoder()
        ip_enc = le.fit_transform(df["Source IP"].astype(str))
        # normalise to [0,1] as a rough entropy proxy
        out["entropy_ip"] = ip_enc / (ip_enc.max() + 1e-9)
    else:
        out["entropy_ip"] = 0.0

    # unique_ips — use flow's Destination Port variety as a structural proxy
    if "Destination Port" in df.columns:
        dport = pd.to_numeric(df["Destination Port"], errors="coerce").fillna(0)
        out["unique_ips"] = (dport / (dport.max() + 1e-9))
    else:
        out["unique_ips"] = 0.0

    return out


def build_labels(df: pd.DataFrame) -> np.ndarray:
    labels = df[LABEL_COL].str.strip()
    return (labels != "BENIGN").astype(int).values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True,
                        help="Directory containing CICIDS2017 CSV files")
    parser.add_argument("--out",  default="models/xgb_judge.json",
                        help="Output path for trained model")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    df = load_cicids(args.data)
    print(f"[train_judge] {len(df):,} rows loaded. Label distribution:")
    print(df[LABEL_COL].value_counts().to_string())

    X = engineer_features(df)
    y = build_labels(df)

    # Drop rows with inf / NaN
    mask = np.isfinite(X.values).all(axis=1)
    X, y = X[mask], y[mask]
    print(f"[train_judge] After cleaning: {len(X):,} rows. "
          f"Attack ratio: {y.mean():.2%}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    scale_pos = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    print(f"[train_judge] scale_pos_weight = {scale_pos:.2f}")

    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train,
              eval_set=[(X_test, y_test)],
              verbose=50)

    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob > 0.5).astype(int)
    print("\n[train_judge] Test-set report:")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_prob):.4f}")

    model.save_model(args.out)
    print(f"\n[train_judge] Model saved → {args.out}")


if __name__ == "__main__":
    main()
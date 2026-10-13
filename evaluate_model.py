#!/usr/bin/env python3

"""
Offline evaluation script for the eBPF Hybrid Intrusion Detection Framework.

This script evaluates the Random Forest classifier using the same
synthetic training dataset as the runtime ML engine.

It generates:

• Accuracy
• Precision
• Recall
• F1-score
• ROC Curve
• Confusion Matrix
• Feature Importance

without modifying ml_engine.py.
"""

import json
import os

import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    precision_score,
    recall_score,
    f1_score,
    roc_curve,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
FEATURE_NAMES = [
    "exec_count",
    "net_count",
    "lateral_count",
    "privesc_count",
    "persist_count",
    "exfil_count",
    "file_count",
    "alert_count",
    "stage_count",
    "unique_pids",
    "unique_comms",
    "net_exec_ratio",
    "lateral_net_ratio",
    "sensitive_file_ratio",
]
def generate_training_data():
    rng = np.random.default_rng(42)
    rows = []
    labels = []

    for _ in range(500):
        exec_count = int(rng.integers(0, 5))
        net_count = int(rng.integers(0, 6))
        file_count = int(rng.integers(0, 4))
        rows.append(
            [
                exec_count,
                net_count,
                0,
                0,
                0,
                0,
                file_count,
                0,
                0,
                int(rng.integers(1, 6)),
                int(rng.integers(1, 4)),
                net_count / max(exec_count, 1),
                0.0,
                file_count / max(exec_count + net_count + file_count, 1),
            ]
        )
        labels.append(0)

    for _ in range(500):
        exec_count = int(rng.integers(6, 20))
        net_count = int(rng.integers(3, 20))
        lateral_count = int(rng.integers(1, 7))
        privesc_count = int(rng.integers(0, 4))
        persist_count = int(rng.integers(0, 4))
        exfil_count = int(rng.integers(0, 4))
        file_count = int(rng.integers(2, 12))
        stage_count = int(rng.integers(2, 7))
        total = exec_count + net_count + file_count
        rows.append(
            [
                exec_count,
                net_count,
                lateral_count,
                privesc_count,
                persist_count,
                exfil_count,
                file_count,
                int(rng.integers(1, 6)),
                stage_count,
                int(rng.integers(3, 16)),
                int(rng.integers(3, 10)),
                net_count / max(exec_count, 1),
                lateral_count / max(net_count, 1),
                file_count / max(total, 1),
            ]
        )
        labels.append(1)

    return np.array(rows, dtype=float), np.array(labels)
import re

IGNORE_COMMS = {
    "systemd",
    "systemd-journal",
    "kubelet",
    "containerd",
    "dockerd",
    "promtail",
    "apt-check",
    "update-notifier",
    "dpkg",
    "ischroot",
    "livepatch-notification",
    "ubuntu-advantage-notification",
}
def build_dataset_from_json(filename):
    """
    Build a machine learning dataset directly from runtime eBPF events.
    """

    events = []

    with open(filename, "r") as fp:
        for line in fp:

            try:
                event = json.loads(line)

            except json.JSONDecodeError:
                continue

            comm = event.get("comm", "")

            if comm in IGNORE_COMMS:
                continue

            events.append(event)

    return events
OUTPUT_DIR = "figures"

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)
print("="*60)
print("Evaluating Random Forest")
print("="*60)

events = build_dataset_from_json(
    "/var/log/ebpf-events.json"
)

print(f"Loaded {len(events)} runtime events")

X_train,X_test,y_train,y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)
scaler = StandardScaler()

X_train = scaler.fit_transform(X_train)

X_test = scaler.transform(X_test)
rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=8,
    random_state=42
)

rf.fit(
    X_train,
    y_train
)
y_pred = rf.predict(X_test)

y_prob = rf.predict_proba(
    X_test
)[:,1]


roc_auc = roc_auc_score(y_test, y_prob)

print("ROC-AUC  :", roc_auc)
accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred
)

recall = recall_score(
    y_test,
    y_pred
)

f1 = f1_score(
    y_test,
    y_pred
)

print()

print("Accuracy :",accuracy)

print("Precision:",precision)

print("Recall   :",recall)

print("F1 Score :",f1)
metrics = {
    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1_score": float(f1),
    "roc_auc": float(roc_auc)
}

with open(
    os.path.join(
        OUTPUT_DIR,
        "metrics.json"
    ),
    "w"
) as fp:


    json.dump(
        metrics,
        fp,
        indent=4
    )
print()

print(classification_report(
    y_test,
    y_pred
))
####################################################
# Confusion Matrix
####################################################

cm = confusion_matrix(y_test, y_pred)

print("\nConfusion Matrix")
print(cm)

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["Normal", "Attack"]
)

fig, ax = plt.subplots(figsize=(5, 5))

disp.plot(ax=ax)

plt.title("Confusion Matrix")

plt.tight_layout()

plt.savefig(
    os.path.join(
        OUTPUT_DIR,
        "confusion_matrix.pdf"
    )
)

plt.close()
####################################################
# ROC Curve
####################################################

fpr, tpr, _ = roc_curve(y_test, y_prob)

roc_auc = auc(fpr, tpr)

plt.figure(figsize=(6, 6))

plt.plot(
    fpr,
    tpr,
    linewidth=2,
    label=f"AUC = {roc_auc:.3f}"
)

plt.plot([0, 1], [0, 1], "k--")

plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])

plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("Receiver Operating Characteristic")
plt.legend(loc="lower right")

plt.tight_layout()

plt.savefig(
    os.path.join(
        OUTPUT_DIR,
        "roc_curve.pdf"
    )
)

plt.close()
####################################################
# Feature Importance
####################################################

importance = rf.feature_importances_

indices = np.argsort(importance)

plt.figure(figsize=(8, 6))

plt.barh(
    range(len(indices)),
    importance[indices]
)

plt.yticks(
    range(len(indices)),
    np.array(FEATURE_NAMES)[indices]
)

plt.xlabel("Feature Importance")
plt.title("Random Forest Feature Importance")

plt.tight_layout()

plt.savefig(
    os.path.join(
        OUTPUT_DIR,
        "feature_importance.pdf"
    )
)

plt.close()
print("\nEvaluation complete.")
print(f"Results saved to '{OUTPUT_DIR}/'")
    

#!/usr/bin/env python3

"""
Experiment 3 — Machine Learning Model Comparison

Uses the EXACT preprocessing and feature extraction logic
from evaluate_model1.py.

Dataset:
    normal_events*.json
    attack_events*.json

Windowing:
    5-second windows
    minimum 5 events/window

Models:
    Logistic Regression
    SVM
    Decision Tree
    Random Forest
    XGBoost
    Isolation Forest
    One-Class SVM
    RF + IF Hybrid
"""

import glob
import json
import os
import re

import numpy as np
import pandas as pd

from sklearn.ensemble import (
    RandomForestClassifier,
    IsolationForest
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)
from sklearn.model_selection import (
    StratifiedKFold,
    cross_val_predict
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.svm import SVC, OneClassSVM
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier


WINDOW_SEC = 5

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

IGNORE_COMMS = {
    "swapper/0",
    "kube-apiserver",
    "docker-proxy",
    "kubelet",
    "containerd",
    "systemd",
    "systemd-resolve",
    "coredns",
    "kube-proxy",
    "etcd",
    "kindnetd",
    "firefox",
    "Socket Thread",
    "xdg-mime",
    "xdg-settings",
    "containerd-shim",
    "runc",
    "runc:[2:INIT]",
    "systemd-journal",
    "kubectl",
}

STAGE_ORDER = [
    "ENTRY",
    "RECON",
    "PRIVESC",
    "LATERAL",
    "PERSIST",
    "EXFIL",
]

STAGE_BITS = {
    1: "ENTRY",
    2: "RECON",
    4: "PRIVESC",
    8: "LATERAL",
    16: "PERSIST",
    32: "EXFIL",
}

COMMAND_STAGES = {
    "ENTRY": {
        "sh", "bash", "dash", "zsh", "ash"
    },

    "RECON": {
        "hostname", "whoami", "id", "env", "cat",
        "ls", "ps", "curl", "wget", "nslookup",
        "dig", "host", "ip", "ifconfig", "ss",
        "netstat", "arp", "nmap", "busybox"
    },

    "PRIVESC": {
        "sudo", "su", "pkexec", "find", "mount",
        "capsh", "unshare", "setcap", "getcap"
    },

    "LATERAL": {
        "nc", "ncat", "netcat", "ssh",
        "scp", "telnet", "socat",
        "psql", "mysql"
    },

    "PERSIST": {
        "crontab", "systemctl"
    },

    "EXFIL": {
        "tar", "gzip", "zip", "base64",
        "scp", "rsync", "openssl"
    }
}


def add_stage(stages, stage):
    if stage in STAGE_ORDER and stage not in stages:
        stages.append(stage)


def command_name(comm):
    return os.path.basename(
        str(comm or "")
    ).lower()


def stages_from_alert_mask(detail):
    match = re.search(
        r"stages_mask=(\d+)",
        detail or ""
    )

    if not match:
        return []

    mask = int(match.group(1))

    return [
        stage
        for bit, stage in STAGE_BITS.items()
        if mask & bit
    ]


def stage_from_detail(detail):
    match = re.search(
        r"\bStage=([A-Z]+)\b",
        detail or ""
    )

    if not match:
        return None

    return match.group(1)


def detail_has_any(detail, values):
    text = str(detail or "")

    return any(
        value in text
        for value in values
    )


def infer_stages(events):

    stages = []

    for event in events:

        event_type = event.get("type", "")
        detail = event.get("detail", "")

        if event_type == "STAGE":
            add_stage(
                stages,
                stage_from_detail(detail)
            )

        if event_type == "ALERT":
            for stage in stages_from_alert_mask(detail):
                add_stage(stages, stage)

        if event_type in {
            "LATERAL",
            "PRIVESC",
            "PERSIST",
            "EXFIL"
        }:
            add_stage(stages, event_type)

        if event_type == "EXEC":

            cmd = command_name(
                event.get("comm", "")
            )

            for stage, commands in COMMAND_STAGES.items():

                if cmd in commands:
                    add_stage(stages, stage)

        if event_type in {
            "FILE",
            "MKDIR",
            "UNLINK"
        }:

            if detail_has_any(
                detail,
                ["/etc/passwd", "/etc/os-release"]
            ):
                add_stage(stages, "RECON")

            if detail_has_any(
                detail,
                ["/proc/1/status", "/proc/self/status"]
            ):
                add_stage(stages, "PRIVESC")

            if detail_has_any(
                detail,
                [
                    "/tmp/update",
                    "/tmp/.persist",
                    "/tmp/cron",
                    "/etc/cron",
                    "/root/"
                ]
            ):
                add_stage(stages, "PERSIST")

            if detail_has_any(
                detail,
                ["/tmp/data", "/tmp/demo-data"]
            ):
                add_stage(stages, "EXFIL")

    return [
        stage
        for stage in STAGE_ORDER
        if stage in stages
    ]


def extract_features(events):

    types = [
        event.get("type")
        for event in events
    ]

    stages = infer_stages(events)

    exec_count = types.count("EXEC")
    net_count = types.count("NET")
    lateral_count = types.count("LATERAL")

    privesc_count = (
        types.count("PRIVESC")
        + int("PRIVESC" in stages)
    )

    persist_count = (
        types.count("PERSIST")
        + int("PERSIST" in stages)
    )

    exfil_count = (
        types.count("EXFIL")
        + int("EXFIL" in stages)
    )

    file_count = sum(
        1
        for t in types
        if t in {
            "FILE",
            "MKDIR",
            "UNLINK"
        }
    )

    alert_count = types.count("ALERT")

    stage_count = len(stages)

    unique_pids = len({
        event.get("pid", 0)
        for event in events
    })

    unique_comms = len({
        event.get("comm", "")
        for event in events
    })

    sensitive_files = sum(
        1
        for event in events
        if event.get("type") in {
            "FILE",
            "PERSIST",
            "EXFIL",
            "MKDIR",
            "UNLINK"
        }
    )

    return [
        exec_count,
        net_count,
        lateral_count,
        privesc_count,
        persist_count,
        exfil_count,
        file_count,
        alert_count,
        stage_count,
        unique_pids,
        unique_comms,
        net_count / max(exec_count, 1),
        lateral_count / max(net_count, 1),
        sensitive_files / max(len(events), 1),
    ]


def load_events(filename):

    events = []

    with open(filename, "r") as fp:

        for line in fp:

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

            except json.JSONDecodeError:
                continue

            comm = event.get("comm", "")

            if comm in IGNORE_COMMS:
                continue

            events.append(event)

    return events


def split_windows(events):

    if not events:
        return []

    windows = []
    current = []

    start_ts = events[0]["ts"]

    for event in events:

        ts = event["ts"]

        if ts - start_ts < WINDOW_SEC:

            current.append(event)

        else:

            if current:
                windows.append(current)

            current = [event]
            start_ts = ts

    if current:
        windows.append(current)

    return windows


def process_log(filename, label):

    events = load_events(filename)

    windows = split_windows(events)

    X = []
    y = []

    for window in windows:

        if len(window) < 5:
            continue

        features = extract_features(window)

        X.append(features)
        y.append(label)

    print(
        f"{os.path.basename(filename):25s}"
        f" windows={len(X):3d}"
    )

    return X, y


def build_dataset():

    X = []
    y = []

    normal_files = sorted(
        glob.glob("normal_events*.json")
    )

    attack_files = sorted(
        glob.glob("attack_events*.json")
        + glob.glob("attack_family_A_run*.json")
        + glob.glob("attack_family_B_run*.json")
        + glob.glob("attack_family_C_run*.json")
        + glob.glob("attack_family_D_run*.json")
    )

    print("\nNORMAL LOGS")
    print("-" * 50)

    for filename in normal_files:

        Xi, yi = process_log(
            filename,
            0
        )

        X.extend(Xi)
        y.extend(yi)

    print("\nATTACK LOGS")
    print("-" * 50)

    for filename in attack_files:

        Xi, yi = process_log(
            filename,
            1
        )

        X.extend(Xi)
        y.extend(yi)

    return (
        pd.DataFrame(
            X,
            columns=FEATURE_NAMES
        ),
        np.array(y)
    )


def evaluate_supervised(
    name,
    model,
    X,
    y,
    cv
):

    pred = cross_val_predict(
        model,
        X,
        y,
        cv=cv,
        method="predict"
    )

    try:

        score = cross_val_predict(
            model,
            X,
            y,
            cv=cv,
            method="predict_proba"
        )[:, 1]

    except Exception:

        score = cross_val_predict(
            model,
            X,
            y,
            cv=cv,
            method="decision_function"
        )

    '''return {
        "Model": name,
        "Accuracy": accuracy_score(y, pred),
        "Precision": precision_score(
            y,
            pred,
            zero_division=0
        ),
        "Recall": recall_score(
            y,
            pred,
            zero_division=0
        ),
        "F1": f1_score(
            y,
            pred,
            zero_division=0
        ),
        "ROC_AUC": roc_auc_score(
            y,
            score
        )
    }'''
    result = {
        "Model": name,
        "Accuracy": accuracy_score(y, pred),
        "Precision": precision_score(
            y,
            pred,
            zero_division=0
        ),
        "Recall": recall_score(
            y,
            pred,
            zero_division=0
        ),
        "F1": f1_score(
            y,
            pred,
            zero_division=0
        ),
        "ROC_AUC": roc_auc_score(
            y,
            score
        )
    }

    return result, pred, score


def evaluate_anomaly(
    name,
    model_type,
    X,
    y
):

    cv = StratifiedKFold(
        n_splits=5,
        shuffle=True,
        random_state=42
    )

    scores = np.zeros(len(y))

    for train_idx, test_idx in cv.split(X, y):

        normal_idx = train_idx[
            y[train_idx] == 0
        ]

        X_normal = X.iloc[normal_idx]

        scaler = StandardScaler()

        X_normal_scaled = scaler.fit_transform(
            X_normal
        )

        if model_type == "IF":

            model = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42
            )

        else:

            model = OneClassSVM(
                kernel="rbf",
                gamma="scale",
                nu=0.05
            )

        model.fit(X_normal_scaled)

        X_test_scaled = scaler.transform(
            X.iloc[test_idx]
        )

        scores[test_idx] = -model.decision_function(
            X_test_scaled
        )

    threshold = np.percentile(
        scores[y == 0],
        95
    )

    pred = (
        scores >= threshold
    ).astype(int)

    '''return {
        "Model": name,
        "Accuracy": accuracy_score(y, pred),
        "Precision": precision_score(
            y,
            pred,
            zero_division=0
        ),
        "Recall": recall_score(
            y,
            pred,
            zero_division=0
        ),
        "F1": f1_score(
            y,
            pred,
            zero_division=0
        ),
        "ROC_AUC": roc_auc_score(
            y,
            scores
        )
    }'''
    result = {
        "Model": name,
        "Accuracy": accuracy_score(y, pred),
        "Precision": precision_score(
            y,
            pred,
            zero_division=0
        ),
        "Recall": recall_score(
            y,
            pred,
            zero_division=0
        ),
        "F1": f1_score(
            y,
            pred,
            zero_division=0
        ),
        "ROC_AUC": roc_auc_score(
            y,
            scores
        )
    }

    return result, pred, scores


def evaluate_hybrid(X, y):

    cv = StratifiedKFold(
        n_splits=5,
        shuffle=True,
        random_state=42
    )

    predictions = np.zeros(len(y))
    scores = np.zeros(len(y))

    for train_idx, test_idx in cv.split(X, y):

        X_train = X.iloc[train_idx]
        X_test = X.iloc[test_idx]

        y_train = y[train_idx]

        scaler = StandardScaler()

        X_train_scaled = scaler.fit_transform(
            X_train
        )

        X_test_scaled = scaler.transform(
            X_test
        )

        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            class_weight="balanced",
            random_state=42
        )

        rf.fit(
            X_train_scaled,
            y_train
        )

        normal_train = X_train[
            y_train == 0
        ]

        if_scaler = StandardScaler()

        normal_scaled = if_scaler.fit_transform(
            normal_train
        )

        iso = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )

        iso.fit(normal_scaled)

        rf_score = rf.predict_proba(
            X_test_scaled
        )[:, 1]

        if_score = -iso.decision_function(
            if_scaler.transform(X_test)
        )

        # Min-max normalization within each test fold.
        lo = if_score.min()
        hi = if_score.max()

        if hi > lo:
            if_norm = (
                (if_score - lo)
                / (hi - lo)
            )
        else:
            if_norm = np.zeros_like(
                if_score
            )

        hybrid_score = (
            0.7 * rf_score
            + 0.3 * if_norm
        )

        scores[test_idx] = hybrid_score

        predictions[test_idx] = (
            hybrid_score >= 0.5
        ).astype(int)

    '''return {
        "Model": "RF + IF Hybrid",
        "Accuracy": accuracy_score(
            y,
            predictions
        ),
        "Precision": precision_score(
            y,
            predictions,
            zero_division=0
        ),
        "Recall": recall_score(
            y,
            predictions,
            zero_division=0
        ),
        "F1": f1_score(
            y,
            predictions,
            zero_division=0
        ),
        "ROC_AUC": roc_auc_score(
            y,
            scores
        )
    }'''
    result = {
        "Model": "RF + IF Hybrid",
        "Accuracy": accuracy_score(
            y,
            predictions
        ),
        "Precision": precision_score(
            y,
            predictions,
            zero_division=0
        ),
        "Recall": recall_score(
            y,
            predictions,
            zero_division=0
        ),
        "F1": f1_score(
            y,
            predictions,
            zero_division=0
        ),
        "ROC_AUC": roc_auc_score(
            y,
            scores
        )
    }

    return result, predictions, scores


print("=" * 70)
print("EXPERIMENT 3 — MACHINE LEARNING MODEL COMPARISON")
print("=" * 70)

X, y = build_dataset()

print("\n" + "=" * 70)
print("DATASET")
print("=" * 70)

print(
    f"Total windows : {len(X)}"
)

print(
    f"Normal        : {(y == 0).sum()}"
)

print(
    f"Attack        : {(y == 1).sum()}"
)

print(
    f"Features      : {len(FEATURE_NAMES)}"
)

cv = StratifiedKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)

models = [

    (
        "Logistic Regression",

        Pipeline([
            (
                "scale",
                StandardScaler()
            ),

            (
                "model",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    random_state=42
                )
            )
        ])
    ),

    (
        "SVM",

        Pipeline([
            (
                "scale",
                StandardScaler()
            ),

            (
                "model",
                SVC(
                    kernel="rbf",
                    probability=True,
                    class_weight="balanced",
                    random_state=42
                )
            )
        ])
    ),

    (
        "Decision Tree",

        DecisionTreeClassifier(
            max_depth=8,
            class_weight="balanced",
            random_state=42
        )
    ),

    (
        "Random Forest",

        RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            class_weight="balanced",
            random_state=42
        )
    ),

    (
        "XGBoost",

        XGBClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=42
        )
    )
]

results = []
roc_scores = {}
model_predictions = {}

print("\n" + "-" * 70)
print("SUPERVISED MODELS")
print("-" * 70)

for name, model in models:

    print(
        f"Running {name} ..."
    )

    result, pred, score = evaluate_supervised(
	    name,
	    model,
	    X,
	    y,
	    cv
    )

    results.append(result)
    roc_scores[name] = score
    model_predictions[name] = pred

    print(
        f"  Accuracy={result['Accuracy']:.4f} "
        f"Precision={result['Precision']:.4f} "
        f"Recall={result['Recall']:.4f} "
        f"F1={result['F1']:.4f} "
        f"AUC={result['ROC_AUC']:.4f}"
    )


print("\n" + "-" * 70)
print("ONE-CLASS / ANOMALY MODELS")
print("-" * 70)

print("Running Isolation Forest ...")

result, pred, score = evaluate_anomaly(
    "Isolation Forest",
    "IF",
    X,
    y
)

results.append(result)
roc_scores["Isolation Forest"] = score
model_predictions["Isolation Forest"] = pred

print("Running One-Class SVM ...")

result, pred, score = evaluate_anomaly(
    "One-Class SVM",
    "OCSVM",
    X,
    y
)

results.append(result)
roc_scores["One-Class SVM"] = score
model_predictions["One-Class SVM"] = pred


print("\n" + "-" * 70)
print("HYBRID MODEL")
print("-" * 70)

print("Running RF + IF Hybrid ...")

result, pred, score = evaluate_hybrid(
    X,
    y
)

results.append(result)
roc_scores["RF + IF Hybrid"] = score
model_predictions["RF + IF Hybrid"] = pred


results_df = pd.DataFrame(
    results
)

results_df = results_df[
    [
        "Model",
        "Accuracy",
        "Precision",
        "Recall",
        "F1",
        "ROC_AUC"
    ]
]

results_df.to_csv(
    "experiment3_ml_comparison_results.csv",
    index=False
)

print("\n" + "=" * 70)
print("EXPERIMENT 3 RESULTS")
print("=" * 70)

print(
    results_df.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)

print("\nSaved:")
print(
    "  experiment3_ml_comparison_results.csv"
)
# ============================================================
# ROC CURVES — ALL EIGHT MODELS
# ============================================================

from sklearn.metrics import roc_curve, auc
import matplotlib.pyplot as plt

print("\n" + "=" * 70)
print("GENERATING MODEL COMPARISON ROC CURVES")
print("=" * 70)

plt.figure(figsize=(9, 7))

# Keep the order consistent with the manuscript/table
plot_order = [
    "Logistic Regression",
    "SVM",
    "Decision Tree",
    "Random Forest",
    "XGBoost",
    "Isolation Forest",
    "One-Class SVM",
    "RF + IF Hybrid",
]

for name in plot_order:

    scores = roc_scores[name]

    fpr, tpr, _ = roc_curve(
        y,
        scores
    )

    roc_auc = auc(
        fpr,
        tpr
    )

    plt.plot(
        fpr,
        tpr,
        linewidth=2,
        label=f"{name} (AUC = {roc_auc:.4f})"
    )

# Random-classifier reference
plt.plot(
    [0, 1],
    [0, 1],
    linestyle="--",
    linewidth=1.5,
    label="Random classifier"
)

plt.xlim(
    0.0,
    1.0
)

plt.ylim(
    0.0,
    1.05
)

plt.xlabel(
    "False Positive Rate",
    fontsize=12
)

plt.ylabel(
    "True Positive Rate",
    fontsize=12
)

plt.title(
    "ROC Curves for Machine Learning Model Comparison",
    fontsize=14
)

plt.legend(
    loc="lower right",
    fontsize=9
)

plt.grid(
    True,
    alpha=0.3
)

plt.tight_layout()

plt.savefig(
    "model_comparison_roc.png",
    dpi=600,
    bbox_inches="tight"
)

plt.savefig(
    "model_comparison_roc.pdf",
    dpi=600,
    bbox_inches="tight"
)

plt.close()

print("\nSaved:")
print("  model_comparison_roc.png")
print("  model_comparison_roc.pdf")
# ============================================================
# CONFUSION MATRICES — ALL EIGHT MODELS
# ============================================================

from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt

print("\n" + "=" * 70)
print("GENERATING CONFUSION MATRICES")
print("=" * 70)

model_order = [
    "Logistic Regression",
    "SVM",
    "Decision Tree",
    "Random Forest",
    "XGBoost",
    "Isolation Forest",
    "One-Class SVM",
    "RF + IF Hybrid",
]

# Clean filenames for each model
filename_map = {
    "Logistic Regression": "logistic_regression",
    "SVM": "svm",
    "Decision Tree": "decision_tree",
    "Random Forest": "random_forest",
    "XGBoost": "xgboost",
    "Isolation Forest": "isolation_forest",
    "One-Class SVM": "one_class_svm",
    "RF + IF Hybrid": "rf_if_hybrid",
}

for name in model_order:

    pred = model_predictions[name]

    cm = confusion_matrix(
        y,
        pred,
        labels=[0, 1]
    )

    fig, ax = plt.subplots(
        figsize=(5.5, 4.8)
    )

    im = ax.imshow(
        cm,
        interpolation="nearest",
        cmap="Blues"
    )

    ax.figure.colorbar(
        im,
        ax=ax
    )

    ax.set(
        xticks=np.arange(2),
        yticks=np.arange(2),
        xticklabels=["Normal", "Attack"],
        yticklabels=["Normal", "Attack"],
        xlabel="Predicted label",
        ylabel="True label",
        title=f"{name} Confusion Matrix"
    )

    threshold = cm.max() / 2.0

    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):

            ax.text(
                j,
                i,
                str(cm[i, j]),
                ha="center",
                va="center",
                fontsize=14,
                fontweight="bold",
                color=(
                    "white"
                    if cm[i, j] > threshold
                    else "black"
                )
            )

    fig.tight_layout()

    # Use the clean filename mapping
    safe_name = filename_map[name]

    png_name = f"confusion_matrix_{safe_name}.png"
    pdf_name = f"confusion_matrix_{safe_name}.pdf"

    plt.savefig(
        png_name,
        dpi=600,
        bbox_inches="tight"
    )

    plt.savefig(
        pdf_name,
        dpi=600,
        bbox_inches="tight"
    )

    plt.close()

    print(f"Saved {png_name}")

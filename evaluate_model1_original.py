#!/usr/bin/env python3

"""
Offline evaluation using REAL runtime eBPF logs.

Reads:
    normal_events*.json
    attack_events*.json

Builds:
    Feature vectors using the SAME feature extraction logic
    used by ml_engine.py.

Outputs:
    confusion_matrix.pdf
    roc_curve.pdf
    feature_importance.pdf
    metrics.json
"""

import glob
import json
import os
import re

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
    roc_curve,
    roc_auc_score,
    f1_score,
)

#from sklearn.model_selection import train_test_split
from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    cross_val_score,
)
from sklearn.preprocessing import StandardScaler
OUTPUT_DIR = "figures"

WINDOW_SEC = 5

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)
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

    1:"ENTRY",

    2:"RECON",

    4:"PRIVESC",

    8:"LATERAL",

    16:"PERSIST",

    32:"EXFIL",

}
COMMAND_STAGES = {

"ENTRY":{"sh","bash","dash","zsh","ash"},

"RECON":{
"hostname","whoami","id","env","cat","ls","ps",
"curl","wget","nslookup","dig","host",
"ip","ifconfig","ss","netstat","arp",
"nmap","busybox"
},

"PRIVESC":{
"sudo","su","pkexec","find","mount",
"capsh","unshare","setcap","getcap"
},

"LATERAL":{
"nc","ncat","netcat","ssh",
"scp","telnet","socat",
"psql","mysql"
},

"PERSIST":{
"crontab",
"systemctl"
},

"EXFIL":{
"tar",
"gzip",
"zip",
"base64",
"scp",
"rsync",
"openssl"
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

        for bit,stage in STAGE_BITS.items()

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
            add_stage(stages, stage_from_detail(detail))

        if event_type == "ALERT":
            for stage in stages_from_alert_mask(detail):
                add_stage(stages, stage)

        if event_type in {"LATERAL", "PRIVESC", "PERSIST", "EXFIL"}:
            add_stage(stages, event_type)

        if event_type == "EXEC":
            cmd = command_name(event.get("comm", ""))
            for stage, commands in COMMAND_STAGES.items():
                if cmd in commands:
                    add_stage(stages, stage)

        if event_type in {"FILE", "MKDIR", "UNLINK"}:
            if detail_has_any(detail, ["/etc/passwd", "/etc/os-release"]):
                add_stage(stages, "RECON")
            if detail_has_any(detail, ["/proc/1/status", "/proc/self/status"]):
                add_stage(stages, "PRIVESC")
            if detail_has_any(detail, ["/tmp/update", "/tmp/.persist", "/tmp/cron", "/etc/cron", "/root/"]):
                add_stage(stages, "PERSIST")
            if detail_has_any(detail, ["/tmp/data", "/tmp/demo-data"]):
                add_stage(stages, "EXFIL")

    return [stage for stage in STAGE_ORDER if stage in stages]

def extract_features(events):
    types = [event.get("type") for event in events]
    stages = infer_stages(events)

    exec_count = types.count("EXEC")
    net_count = types.count("NET")
    lateral_count = types.count("LATERAL")
    privesc_count = types.count("PRIVESC") + int("PRIVESC" in stages)
    persist_count = types.count("PERSIST") + int("PERSIST" in stages)
    exfil_count = types.count("EXFIL") + int("EXFIL" in stages)
    file_count = sum(1 for t in types if t in {"FILE", "MKDIR", "UNLINK"})
    alert_count = types.count("ALERT")
    stage_count = len(stages)

    unique_pids = len({event.get("pid", 0) for event in events})
    unique_comms = len({event.get("comm", "") for event in events})
    sensitive_files = sum(
        1
        for event in events
        if event.get("type") in {"FILE", "PERSIST", "EXFIL", "MKDIR", "UNLINK"}
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
    """
    Read one JSON event log.
    """

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
def split_windows(events, window_size=WINDOW_SEC):
    """
    Split events into fixed-duration windows.
    """

    if not events:
        return []

    windows = []

    current = []

    start_ts = events[0]["ts"]

    for event in events:

        ts = event["ts"]

        if ts - start_ts < window_size:

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
    """
    Convert one runtime log into feature vectors.
    """

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

    print("\nLoading NORMAL logs\n")

    for filename in sorted(
        glob.glob("normal_events*.json")
    ):

        features, labels = process_log(
            filename,
            label=0
        )

        X.extend(features)

        y.extend(labels)

    print("\nLoading ATTACK logs\n")

    for filename in sorted(
        glob.glob("attack_events*.json")
    ):

        features, labels = process_log(
            filename,
            label=1
        )

        X.extend(features)

        y.extend(labels)

    print()

    print("="*60)

    print("Dataset Summary")

    print("="*60)

    print("Samples :", len(X))

    print("Features:", len(FEATURE_NAMES))

    print("Normal  :", y.count(0))

    print("Attack  :", y.count(1))

    print()

    return np.array(X), np.array(y)
####################################################
# Build Dataset
####################################################

print("=" * 60)
print("Evaluating Random Forest on Runtime eBPF Logs")
print("=" * 60)

X, y = build_dataset()

if len(X) < 20:
    raise RuntimeError(
        f"Dataset is too small ({len(X)} samples). "
        "Collect more runtime logs before training."
    )
    
####################################################
# 5-Fold Stratified Cross Validation
####################################################

cv = StratifiedKFold(
    n_splits=5,
    shuffle=True,
    random_state=42,
)

rf_cv = RandomForestClassifier(
    n_estimators=100,
    max_depth=8,
    random_state=42,
)

scores = cross_val_score(
    rf_cv,
    X,
    y,
    cv=cv,
    scoring="accuracy",
)

print("\n" + "=" * 60)
print("5-Fold Cross Validation")
print("=" * 60)

for i, score in enumerate(scores, start=1):
    print(f"Fold {i}: {score:.4f}")

print(f"\nMean Accuracy : {scores.mean():.4f}")
print(f"Std Deviation : {scores.std():.4f}")

####################################################
# Train/Test Split
####################################################

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

####################################################
# Normalize Features
####################################################

scaler = StandardScaler()

X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

####################################################
# Train Random Forest
####################################################

rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=8,
    random_state=42,
)

rf.fit(X_train, y_train)

####################################################
# Predictions
####################################################

y_pred = rf.predict(X_test)

y_prob = rf.predict_proba(X_test)[:, 1]

####################################################
# Evaluation Metrics
####################################################

accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0,
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0,
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0,
)

roc_auc = roc_auc_score(
    y_test,
    y_prob,
)

####################################################
# Print Results
####################################################

print("\n")
print("=" * 60)
print("Model Performance")
print("=" * 60)

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nClassification Report\n")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Normal",
            "Attack",
        ],
        zero_division=0,
    )
)

####################################################
# Save Metrics
####################################################

metrics = {

    "samples": int(len(X)),

    "normal_samples": int(np.sum(y == 0)),

    "attack_samples": int(np.sum(y == 1)),

    "accuracy": float(accuracy),

    "precision": float(precision),

    "recall": float(recall),

    "f1_score": float(f1),

    "roc_auc": float(roc_auc),

}

with open(
    os.path.join(
        OUTPUT_DIR,
        "metrics.json",
    ),
    "w",
) as fp:

    json.dump(
        metrics,
        fp,
        indent=4,
    )
####################################################
# Confusion Matrix
####################################################

cm = confusion_matrix(y_test, y_pred)

labels = ["Normal", "Attack"]

fig, ax = plt.subplots(figsize=(6, 5), dpi=300)

# Heatmap
im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)

# Colorbar
cbar = fig.colorbar(im, ax=ax)
cbar.ax.tick_params(labelsize=11)

# Tick labels
ax.set(
    xticks=np.arange(len(labels)),
    yticks=np.arange(len(labels)),
    xticklabels=labels,
    yticklabels=labels,
    xlabel="Predicted label",
    ylabel="True label",
)

ax.set_title("Confusion Matrix", fontsize=16, pad=12)

# Rotate x labels if needed
plt.setp(ax.get_xticklabels(), rotation=0, ha="center", fontsize=12)
plt.setp(ax.get_yticklabels(), fontsize=12)

# Add cell values
threshold = cm.max() / 2.0

for i in range(cm.shape[0]):
    for j in range(cm.shape[1]):

        ax.text(
            j,
            i,
            f"{cm[i, j]}",
            ha="center",
            va="center",
            fontsize=14,
            fontweight="bold",
            color="white" if cm[i, j] > threshold else "black",
        )

# Remove unnecessary grid lines
ax.grid(False)

fig.tight_layout()

plt.savefig(
    os.path.join(
        OUTPUT_DIR,
        "confusion_matrix.pdf",
    ),
    dpi=300,
    bbox_inches="tight",
)

plt.savefig(
    os.path.join(
        OUTPUT_DIR,
        "confusion_matrix.png",
    ),
    dpi=300,
    bbox_inches="tight",
)

plt.close()
'''
cm = confusion_matrix(y_test, y_pred)

print("\nConfusion Matrix")
print(cm)

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["Normal", "Attack"],
)

fig, ax = plt.subplots(figsize=(6, 6))

disp.plot(
    ax=ax,
    cmap="Blues",
    colorbar=True,
    values_format="d",
)

# Improve annotation readability
threshold = cm.max() / 2.0

for text, value in zip(disp.text_.ravel(), cm.ravel()):
    text.set_fontsize(14)
    text.set_fontweight("bold")
    text.set_color("red" if value > threshold else "green")

ax.set_title("Confusion Matrix", fontsize=16)
ax.set_xlabel("Predicted Label", fontsize=13)
ax.set_ylabel("True Label", fontsize=13)

plt.tight_layout()

plt.savefig(
    os.path.join(OUTPUT_DIR, "confusion_matrix.pdf"),
    dpi=600,
    bbox_inches="tight",
)

plt.close()

plt.tight_layout()

plt.savefig(
    os.path.join(
        OUTPUT_DIR,
        "confusion_matrix.pdf",
    ),
    dpi=300,
)

plt.close()
'''
####################################################
# ROC Curve
####################################################

fpr, tpr, _ = roc_curve(
    y_test,
    y_prob,
)

roc_auc_value = auc(
    fpr,
    tpr,
)

plt.figure(figsize=(6, 6))

plt.plot(
    fpr,
    tpr,
    linewidth=2,
    label=f"AUC = {roc_auc_value:.3f}",
)

plt.plot(
    [0, 1],
    [0, 1],
    linestyle="--",
)

plt.xlim(0.0, 1.0)
plt.ylim(0.0, 1.05)

plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")

plt.title("Receiver Operating Characteristic")

plt.legend(loc="lower right")

plt.grid(True)

plt.tight_layout()

plt.savefig(
    os.path.join(
        OUTPUT_DIR,
        "roc_curve.pdf",
    ),
    dpi=300,
)

plt.close()

####################################################
# Feature Importance
####################################################

importance = rf.feature_importances_

indices = np.argsort(importance)[::-1]

sorted_importance = importance[indices]

sorted_names = np.array(FEATURE_NAMES)[indices]

plt.figure(figsize=(9, 6))

plt.barh(
    range(len(sorted_names)),
    sorted_importance[::-1],
)

plt.yticks(
    range(len(sorted_names)),
    sorted_names[::-1],
)

plt.xlabel("Importance Score")

plt.title("Random Forest Feature Importance")

plt.tight_layout()

plt.savefig(
    os.path.join(
        OUTPUT_DIR,
        "feature_importance.pdf",
    ),
    dpi=300,
)

plt.close()

####################################################
# Save Feature Importance CSV
####################################################

with open(
    os.path.join(
        OUTPUT_DIR,
        "feature_importance.csv",
    ),
    "w",
) as fp:

    fp.write("Feature,Importance\n")

    for feature, score in zip(
        sorted_names,
        sorted_importance,
    ):

        fp.write(f"{feature},{score:.6f}\n")

####################################################
# Final Summary
####################################################

print("\n")

print("=" * 60)
print("Evaluation Complete")
print("=" * 60)

print(f"Dataset Samples : {len(X)}")
print(f"Training Samples: {len(X_train)}")
print(f"Testing Samples : {len(X_test)}")

print("\nGenerated Files")

print("---------------------------")

print("✓ metrics.json")
print("✓ confusion_matrix.pdf")
print("✓ roc_curve.pdf")
print("✓ feature_importance.pdf")
print("✓ feature_importance.csv")

print(f"\nResults saved in '{OUTPUT_DIR}/'")


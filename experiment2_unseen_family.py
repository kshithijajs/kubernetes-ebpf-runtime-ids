#!/usr/bin/env python3

import json
import glob
import os
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

WINDOW_SEC = 5
MIN_EVENTS = 5
RANDOM_STATE = 42

# Infrastructure/background processes.
# Keep attack tools such as tar, nc, curl, ps, etc.
# because they are meaningful behavioural features.
IGNORE_COMMS = {
    "swapper/0",
    "kube-apiserver",
    "docker-proxy",
    "kubelet",
    "containerd",
    "containerd-shim",
    "runc",
    "runc:[2:INIT]",
    "systemd",
    "systemd-journal",
    "systemd-resolve",
    "coredns",
    "kube-proxy",
    "etcd",
    "kindnetd",
    "firefox",
    "Socket Thread",
    "xdg-mime",
    "xdg-settings",
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

COMMAND_STAGES = {
    "ENTRY": {"sh", "bash", "dash", "zsh", "ash"},
    "RECON": {
        "hostname", "whoami", "id", "env", "cat", "ls", "ps",
        "curl", "wget", "nslookup", "dig", "host", "ip",
        "ifconfig", "ss", "netstat", "arp", "nmap", "busybox",
        "uname",
    },
    "PRIVESC": {
        "sudo", "su", "pkexec", "find", "mount", "capsh",
        "unshare", "setcap", "getcap",
    },
    "LATERAL": {
        "nc", "ncat", "netcat", "ssh", "scp", "telnet",
        "socat", "psql", "mysql",
    },
    "PERSIST": {
        "crontab", "systemctl",
    },
    "EXFIL": {
        "tar", "gzip", "zip", "base64", "scp", "rsync", "openssl",
    },
}


def infer_stages(events):
    stages = set()

    for event in events:
        typ = event.get("type", "")
        comm = event.get("comm", "")

        detail = event.get("detail", "")

        # Explicit stage records.
        for stage in STAGE_ORDER:
            if f"Stage={stage}" in detail:
                stages.add(stage)

        # Explicit event types.
        if typ == "LATERAL":
            stages.add("LATERAL")
        elif typ == "PRIVESC":
            stages.add("PRIVESC")
        elif typ == "PERSIST":
            stages.add("PERSIST")
        elif typ == "EXFIL":
            stages.add("EXFIL")

        # Command-based inference.
        if typ == "EXEC":
            for stage, commands in COMMAND_STAGES.items():
                if comm in commands:
                    stages.add(stage)

        # Filesystem-based inference.
        filename = event.get("filename", "")

        if typ in {"FILE", "MKDIR", "UNLINK"}:
            if filename in {"/etc/passwd", "/etc/os-release"}:
                stages.add("RECON")

            if filename == "/proc/1/status":
                stages.add("PRIVESC")

            if (
                filename.startswith("/tmp/update")
                or filename.startswith("/tmp/.persist")
                or filename.startswith("/tmp/cron")
                or filename.startswith("/etc/cron")
                or filename.startswith("/root/")
            ):
                stages.add("PERSIST")

            if (
                filename.startswith("/tmp/data")
                or filename.startswith("/tmp/demo-data")
            ):
                stages.add("EXFIL")

    return [s for s in STAGE_ORDER if s in stages]


def extract_features(events):
    types = [e.get("type", "") for e in events]
    stages = infer_stages(events)

    exec_count = types.count("EXEC")
    net_count = types.count("NET")
    lateral_count = types.count("LATERAL")

    privesc_count = types.count("PRIVESC")
    persist_count = types.count("PERSIST")
    exfil_count = types.count("EXFIL")

    file_count = sum(
        t in {"FILE", "MKDIR", "UNLINK"}
        for t in types
    )

    alert_count = types.count("ALERT")

    unique_pids = len({
        e.get("pid")
        for e in events
        if e.get("pid") is not None
    })

    unique_comms = len({
        e.get("comm")
        for e in events
        if e.get("comm")
    })

    total = max(len(events), 1)

    return [
        exec_count,
        net_count,
        lateral_count,
        privesc_count,
        persist_count,
        exfil_count,
        file_count,
        alert_count,
        len(stages),
        unique_pids,
        unique_comms,
        net_count / max(exec_count, 1),
        lateral_count / max(net_count, 1),
        file_count / total,
    ]


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


def load_events(filename):
    events = []

    with open(filename, "r") as f:
        for line in f:
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

    events = sorted(events, key=lambda x: x.get("ts", 0))

    windows = []
    current = []
    start_ts = events[0]["ts"]

    for event in events:
        ts = event["ts"]

        if ts - start_ts < WINDOW_SEC:
            current.append(event)
        else:
            if len(current) >= MIN_EVENTS:
                windows.append(current)

            current = [event]
            start_ts = ts

    if len(current) >= MIN_EVENTS:
        windows.append(current)

    return windows


def process_file(filename, label, family):
    events = load_events(filename)
    windows = split_windows(events)

    rows = []

    for i, window in enumerate(windows):
        features = extract_features(window)

        rows.append({
            **dict(zip(FEATURE_NAMES, features)),
            "label": label,
            "family": family,
            "source": os.path.basename(filename),
            "window": i,
        })

    return rows


def load_family_files(family, label):
    pattern = f"attack_family_{family}_run*.json"
    files = sorted(glob.glob(pattern))

    rows = []

    for filename in files:
        # Never include old/superseded files.
        if "_pre_" in filename or "superseded" in filename:
            continue

        rows.extend(process_file(filename, label, family))

    return rows


def load_normal_files():
    rows = []

    for filename in sorted(glob.glob("normal_events*.json")):
        rows.extend(process_file(filename, 0, "NORMAL"))

    return rows


def main():

    print("=" * 70)
    print("EXPERIMENT 2 — UNSEEN ATTACK FAMILY")
    print("=" * 70)

    # ------------------------------------------------------------
    # Training attacks: A-D
    # ------------------------------------------------------------

    train_rows = []

    for family in ["A", "B", "C", "D"]:
        family_rows = load_family_files(family, 1)
        train_rows.extend(family_rows)

        print(
            f"Family {family}: "
            f"{len(family_rows)} usable behavioural windows"
        )

    # ------------------------------------------------------------
    # Test attack: E
    # ------------------------------------------------------------

    test_attack_rows = load_family_files("E", 1)

    print(
        f"Family E (UNSEEN): "
        f"{len(test_attack_rows)} usable behavioural windows"
    )

    # ------------------------------------------------------------
    # Normal data
    #
    # For this first controlled evaluation we use the existing
    # normal recordings. Normal data are not attack-family data.
    # ------------------------------------------------------------

    normal_rows = load_normal_files()

    print(
        f"Normal: "
        f"{len(normal_rows)} usable behavioural windows"
    )

    if not test_attack_rows:
        print("\nERROR: No Family-E recordings found.")
        print("Collect attack_family_E_run*.json first.")
        return

    if not train_rows:
        print("\nERROR: No A-D training attack recordings found.")
        return

    # ------------------------------------------------------------
    # Dataset
    #
    # A-D + normal = training
    # E + normal = test
    # ------------------------------------------------------------

    X_train_attack = pd.DataFrame(train_rows)[FEATURE_NAMES]
    X_train_normal = pd.DataFrame(normal_rows)[FEATURE_NAMES]

    X_test_attack = pd.DataFrame(test_attack_rows)[FEATURE_NAMES]

    # Use a deterministic 80/20 split of normal windows.
    rng = np.random.default_rng(RANDOM_STATE)

    normal_indices = np.arange(len(normal_rows))
    rng.shuffle(normal_indices)

    split = int(0.80 * len(normal_indices))

    normal_train_idx = normal_indices[:split]
    normal_test_idx = normal_indices[split:]

    X_train_normal = X_train_normal.iloc[normal_train_idx]
    X_test_normal = pd.DataFrame(normal_rows)[
        FEATURE_NAMES
    ].iloc[normal_test_idx]

    y_train_attack = np.ones(len(X_train_attack))
    y_train_normal = np.zeros(len(X_train_normal))

    y_test_attack = np.ones(len(X_test_attack))
    y_test_normal = np.zeros(len(X_test_normal))

    X_train = pd.concat(
        [X_train_normal, X_train_attack],
        ignore_index=True,
    )

    y_train = np.concatenate(
        [y_train_normal, y_train_attack]
    )

    X_test = pd.concat(
        [X_test_normal, X_test_attack],
        ignore_index=True,
    )

    y_test = np.concatenate(
        [y_test_normal, y_test_attack]
    )

    # ------------------------------------------------------------
    # Scaling
    # ------------------------------------------------------------

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # ------------------------------------------------------------
    # Random Forest
    # ------------------------------------------------------------

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        random_state=RANDOM_STATE,
        class_weight="balanced",
    )

    model.fit(X_train_scaled, y_train)

    predictions = model.predict(X_test_scaled)
    probabilities = model.predict_proba(X_test_scaled)[:, 1]

    # ------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test,
        predictions,
        zero_division=0,
    )
    recall = recall_score(
        y_test,
        predictions,
        zero_division=0,
    )
    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0,
    )

    if len(np.unique(y_test)) == 2:
        auc = roc_auc_score(y_test, probabilities)
    else:
        auc = float("nan")

    cm = confusion_matrix(y_test, predictions)

    print("\n" + "=" * 70)
    print("UNSEEN-FAMILY RESULTS")
    print("=" * 70)

    print(f"Training attack windows : {len(X_train_attack)}")
    print(f"Training normal windows : {len(X_train_normal)}")
    print(f"Test attack windows     : {len(X_test_attack)}")
    print(f"Test normal windows     : {len(X_test_normal)}")

    print("\nMetrics")
    print("-" * 40)
    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1        : {f1:.4f}")
    print(f"ROC-AUC   : {auc:.4f}")

    print("\nConfusion Matrix")
    print(cm)

    print("\nClassification Report")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["Normal", "Unseen Family E"],
            zero_division=0,
        )
    )

    # ------------------------------------------------------------
    # Feature importance
    # ------------------------------------------------------------

    importance = pd.DataFrame({
        "Feature": FEATURE_NAMES,
        "Importance": model.feature_importances_,
    }).sort_values(
        "Importance",
        ascending=False,
    )

    print("\nFeature Importance")
    print(importance.to_string(index=False))

    # ------------------------------------------------------------
    # Save results
    # ------------------------------------------------------------

    result = pd.DataFrame({
        "metric": [
            "accuracy",
            "precision",
            "recall",
            "f1",
            "roc_auc",
        ],
        "value": [
            accuracy,
            precision,
            recall,
            f1,
            auc,
        ],
    })

    result.to_csv(
        "experiment2_unseen_family_results.csv",
        index=False,
    )

    importance.to_csv(
        "experiment2_unseen_family_feature_importance.csv",
        index=False,
    )

    print("\nSaved:")
    print("  experiment2_unseen_family_results.csv")
    print("  experiment2_unseen_family_feature_importance.csv")


if __name__ == "__main__":
    main()

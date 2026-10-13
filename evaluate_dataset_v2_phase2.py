#!/usr/bin/env python3

"""
Dataset V2 — Phase 2
Leakage-safe session-grouped comparison of:

    1. Random Forest
    2. Isolation Forest
    3. RF + IF Hybrid

Dataset:
    dataset_v2/dataset_v2_manifest.csv

Formal cohort:
    50 normal sessions
    10 Family A
    10 Family B
    10 Family C
    10 Family D
    10 Family E

Family E is RESERVED and is NOT used in this experiment.

Evaluation:
    Session-grouped 5-fold CV on Normal + Families A-D.

The existing 14-feature representation and 5-second windowing
are preserved from evaluate_model1.py.
"""

import csv
import json
import os
import re

import numpy as np

from sklearn.ensemble import (
    RandomForestClassifier,
    IsolationForest,
)

from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler


# ============================================================
# Configuration
# ============================================================

MANIFEST = "dataset_v2/dataset_v2_manifest.csv"

WINDOW_SEC = 5
MIN_EVENTS_PER_WINDOW = 5

N_SPLITS = 5
RANDOM_STATE = 42

RF_ESTIMATORS = 100
RF_MAX_DEPTH = 8

IF_ESTIMATORS = 100
IF_CONTAMINATION = "auto"

# Existing feature names
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

# Existing filtering configuration
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
        "hostname", "whoami", "id", "env", "cat", "ls", "ps",
        "curl", "wget", "nslookup", "dig", "host",
        "ip", "ifconfig", "ss", "netstat", "arp",
        "nmap", "busybox"
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
        "crontab",
        "systemctl"
    },

    "EXFIL": {
        "tar",
        "gzip",
        "zip",
        "base64",
        "scp",
        "rsync",
        "openssl"
    },
}


# ============================================================
# Existing stage inference — preserved
# ============================================================

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


# ============================================================
# Existing 14-feature extraction — preserved
# ============================================================

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
        if t in {"FILE", "MKDIR", "UNLINK"}
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


# ============================================================
# Event loading and windowing — preserved
# ============================================================

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


def split_windows(
    events,
    window_size=WINDOW_SEC
):

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


# ============================================================
# Dataset V2 loading
# ============================================================

def load_manifest():

    with open(MANIFEST, newline="") as fp:
        rows = list(csv.DictReader(fp))

    return rows


def load_session_events(source_file):

    return load_events(source_file)


def build_dataset():

    rows = load_manifest()

    # Family E is explicitly reserved.
    rows = [
        r
        for r in rows
        if not (
            r["label"] == "attack"
            and r["attack_family"] == "E"
        )
    ]

    X = []
    y = []
    groups = []

    session_summary = []

    for row in rows:

        events = load_session_events(
            row["source_file"]
        )

        windows = split_windows(events)

        usable = 0

        for window in windows:

            if len(window) < MIN_EVENTS_PER_WINDOW:
                continue

            X.append(
                extract_features(window)
            )

            y.append(
                int(row["label"] == "attack")
            )

            # Critical:
            # every window from the same recording
            # gets the same group identifier.
            groups.append(
                row["session_id"]
            )

            usable += 1

        session_summary.append(
            (
                row["session_id"],
                row["label"],
                row["attack_family"],
                len(events),
                usable,
            )
        )

    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=int)
    groups = np.asarray(groups)

    print()
    print("=" * 70)
    print("DATASET V2 — PHASE 2")
    print("=" * 70)

    print(
        f"Sessions used : {len(set(groups))}"
    )

    print(
        f"Windows       : {len(X)}"
    )

    print(
        f"Features      : {X.shape[1]}"
    )

    print(
        f"Normal windows: {(y == 0).sum()}"
    )

    print(
        f"Attack windows: {(y == 1).sum()}"
    )

    print(
        "Family E      : RESERVED"
    )

    print()

    print("Windows per session:")

    for (
        session_id,
        label,
        family,
        raw_events,
        usable_windows,
    ) in session_summary:

        print(
            f"{session_id:>4} "
            f"{label:>6} "
            f"{family or '-':>2} "
            f"events={raw_events:>4} "
            f"windows={usable_windows:>3}"
        )

    return X, y, groups


# ============================================================
# Metric calculation
# ============================================================

def calculate_metrics(
    y_true,
    y_pred,
    y_score
):

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    ).ravel()

    fpr = fp / max(
        fp + tn,
        1
    )

    return {
        "accuracy": accuracy_score(
            y_true,
            y_pred
        ),

        "precision": precision_score(
            y_true,
            y_pred,
            zero_division=0
        ),

        "recall": recall_score(
            y_true,
            y_pred,
            zero_division=0
        ),

        "f1": f1_score(
            y_true,
            y_pred,
            zero_division=0
        ),

        "roc_auc": roc_auc_score(
            y_true,
            y_score
        ),

        "pr_auc": average_precision_score(
            y_true,
            y_score
        ),

        "fpr": fpr,

        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


# ============================================================
# IF score normalization
# ============================================================

def fit_if_score_calibration(
    if_model,
    X_train_normal,
    X_train_all,
    y_train
):
    """
    Convert Isolation Forest decision_function into
    an anomaly score in [0, 1].

    Calibration uses TRAINING DATA ONLY.
    """

    raw_normal = -if_model.decision_function(
        X_train_normal
    )

    raw_all = -if_model.decision_function(
        X_train_all
    )

    low = np.percentile(
        raw_normal,
        5
    )

    high = np.percentile(
        raw_normal,
        95
    )

    if high <= low:
        high = low + 1.0

    train_score = np.clip(
        (raw_all - low) / (high - low),
        0,
        1
    )

    # Threshold selection is training-only.
    #
    # Choose the threshold that maximizes F1
    # on the training data.
    candidates = np.unique(
        np.quantile(
            train_score,
            np.linspace(
                0.50,
                0.99,
                100
            )
        )
    )

    best_threshold = 0.5
    best_f1 = -1

    for threshold in candidates:

        pred = (
            train_score >= threshold
        ).astype(int)

        score = f1_score(
            y_train,
            pred,
            zero_division=0
        )

        if score > best_f1:
            best_f1 = score
            best_threshold = float(
                threshold
            )

    return (
        low,
        high,
        best_threshold
    )


def apply_if_score(
    if_model,
    X,
    low,
    high
):

    raw = -if_model.decision_function(
        X
    )

    return np.clip(
        (raw - low) / max(
            high - low,
            1e-12
        ),
        0,
        1
    )


# ============================================================
# Main grouped evaluation
# ============================================================

def main():

    X, y, groups = build_dataset()

    splitter = StratifiedGroupKFold(
        n_splits=N_SPLITS,
        shuffle=True,
        random_state=RANDOM_STATE
    )

    model_names = [
        "Random Forest",
        "Isolation Forest",
        "RF + IF Hybrid",
    ]

    results = {
        name: []
        for name in model_names
    }

    all_predictions = {
        name: []
        for name in model_names
    }

    all_truth = []

    fold_number = 0

    for train_idx, test_idx in splitter.split(
        X,
        y,
        groups
    ):

        fold_number += 1

        X_train = X[train_idx]
        X_test = X[test_idx]

        y_train = y[train_idx]
        y_test = y[test_idx]

        train_groups = groups[train_idx]
        test_groups = groups[test_idx]

        print()
        print("=" * 70)
        print(f"FOLD {fold_number}")
        print("=" * 70)

        print(
            f"Training sessions: "
            f"{len(set(train_groups))}"
        )

        print(
            f"Testing sessions : "
            f"{len(set(test_groups))}"
        )

        print(
            f"Training windows: "
            f"{len(train_idx)}"
        )

        print(
            f"Testing windows : "
            f"{len(test_idx)}"
        )

        # ----------------------------------------------------
        # Scaling
        # ----------------------------------------------------

        scaler = StandardScaler()

        X_train_scaled = scaler.fit_transform(
            X_train
        )

        X_test_scaled = scaler.transform(
            X_test
        )

        # ----------------------------------------------------
        # Random Forest
        # ----------------------------------------------------

        rf = RandomForestClassifier(
            n_estimators=RF_ESTIMATORS,
            max_depth=RF_MAX_DEPTH,
            random_state=RANDOM_STATE,
            class_weight=None,
        )

        rf.fit(
            X_train_scaled,
            y_train
        )

        rf_score = rf.predict_proba(
            X_test_scaled
        )[:, 1]

        rf_pred = (
            rf_score >= 0.5
        ).astype(int)

        rf_metrics = calculate_metrics(
            y_test,
            rf_pred,
            rf_score
        )

        results["Random Forest"].append(
            rf_metrics
        )

        # ----------------------------------------------------
        # Isolation Forest
        # ----------------------------------------------------

        normal_train = (
            y_train == 0
        )

        X_train_normal = (
            X_train_scaled[normal_train]
        )

        if_model = IsolationForest(
            n_estimators=IF_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            random_state=RANDOM_STATE,
        )

        if_model.fit(
            X_train_normal
        )

        # Training-only IF calibration.
        low, high, if_threshold = (
            fit_if_score_calibration(
                if_model,
                X_train_normal,
                X_train_scaled,
                y_train
            )
        )

        if_score = apply_if_score(
            if_model,
            X_test_scaled,
            low,
            high
        )

        if_pred = (
            if_score >= if_threshold
        ).astype(int)

        if_metrics = calculate_metrics(
            y_test,
            if_pred,
            if_score
        )

        results["Isolation Forest"].append(
            if_metrics
        )

        # ----------------------------------------------------
        # RF + IF Hybrid
        # ----------------------------------------------------

        hybrid_score_train = (
            0.7 * rf.predict_proba(
                X_train_scaled
            )[:, 1]
            +
            0.3 * apply_if_score(
                if_model,
                X_train_scaled,
                low,
                high
            )
        )

        hybrid_thresholds = np.unique(
            np.quantile(
                hybrid_score_train,
                np.linspace(
                    0.50,
                    0.99,
                    100
                )
            )
        )

        best_hybrid_threshold = 0.5
        best_hybrid_f1 = -1

        for threshold in hybrid_thresholds:

            pred = (
                hybrid_score_train >= threshold
            ).astype(int)

            score = f1_score(
                y_train,
                pred,
                zero_division=0
            )

            if score > best_hybrid_f1:
                best_hybrid_f1 = score
                best_hybrid_threshold = float(
                    threshold
                )

        hybrid_score = (
            0.7 * rf_score
            +
            0.3 * if_score
        )

        hybrid_pred = (
            hybrid_score >= best_hybrid_threshold
        ).astype(int)

        hybrid_metrics = calculate_metrics(
            y_test,
            hybrid_pred,
            hybrid_score
        )

        results["RF + IF Hybrid"].append(
            hybrid_metrics
        )

        # ----------------------------------------------------
        # Store out-of-fold predictions
        # ----------------------------------------------------

        all_truth.extend(
            y_test.tolist()
        )

        all_predictions[
            "Random Forest"
        ].extend(
            zip(
                y_test.tolist(),
                rf_pred.tolist(),
                rf_score.tolist()
            )
        )

        all_predictions[
            "Isolation Forest"
        ].extend(
            zip(
                y_test.tolist(),
                if_pred.tolist(),
                if_score.tolist()
            )
        )

        all_predictions[
            "RF + IF Hybrid"
        ].extend(
            zip(
                y_test.tolist(),
                hybrid_pred.tolist(),
                hybrid_score.tolist()
            )
        )

        print()
        print(
            f"RF      F1={rf_metrics['f1']:.4f} "
            f"AUC={rf_metrics['roc_auc']:.4f}"
        )

        print(
            f"IF      F1={if_metrics['f1']:.4f} "
            f"AUC={if_metrics['roc_auc']:.4f}"
        )

        print(
            f"RF+IF   F1={hybrid_metrics['f1']:.4f} "
            f"AUC={hybrid_metrics['roc_auc']:.4f}"
        )

    # ========================================================
    # Final summary
    # ========================================================

    print()
    print("=" * 80)
    print("DATASET V2 — SESSION-GROUPED RESULTS")
    print("=" * 80)

    for model_name in model_names:

        model_results = results[
            model_name
        ]

        print()
        print(model_name)
        print("-" * len(model_name))

        for metric in [
            "accuracy",
            "precision",
            "recall",
            "f1",
            "roc_auc",
            "pr_auc",
            "fpr",
        ]:

            values = np.array([
                r[metric]
                for r in model_results
            ])

            print(
                f"{metric:10s}: "
                f"{values.mean():.4f} "
                f"+/- {values.std(ddof=1):.4f}"
            )

        print()

        cms = [
            [
                r["tn"],
                r["fp"],
                r["fn"],
                r["tp"]
            ]
            for r in model_results
        ]

        print("Fold confusion matrices:")
        for i, cm in enumerate(cms, 1):
            print(
                f"  Fold {i}: "
                f"TN={cm[0]} "
                f"FP={cm[1]} "
                f"FN={cm[2]} "
                f"TP={cm[3]}"
            )

    # ========================================================
    # Save results
    # ========================================================

    output = {
        "dataset": {
            "name": "Dataset V2",
            "formal_sessions": 100,
            "normal_sessions": 50,
            "attack_sessions": 50,
            "families_A_to_D": 40,
            "reserved_family_E": 10,
            "window_sec": WINDOW_SEC,
            "min_events_per_window": MIN_EVENTS_PER_WINDOW,
            "features": FEATURE_NAMES,
            "n_features": len(FEATURE_NAMES),
            "grouped_by_session": True,
            "n_splits": N_SPLITS,
            "random_state": RANDOM_STATE,
        },

        "models": {},

    }

    for model_name in model_names:

        model_output = {}

        for metric in [
            "accuracy",
            "precision",
            "recall",
            "f1",
            "roc_auc",
            "pr_auc",
            "fpr",
        ]:

            values = np.array([
                r[metric]
                for r in results[model_name]
            ])

            model_output[metric] = {
                "mean": float(
                    values.mean()
                ),
                "std": float(
                    values.std(ddof=1)
                ),
                "folds": [
                    float(v)
                    for v in values
                ],
            }

        model_output[
            "confusion_matrices"
        ] = [
            {
                "tn": r["tn"],
                "fp": r["fp"],
                "fn": r["fn"],
                "tp": r["tp"],
            }
            for r in results[model_name]
        ]

        output["models"][
            model_name
        ] = model_output

    output_path = (
        "dataset_v2_phase2_results.json"
    )

    with open(output_path, "w") as fp:

        json.dump(
            output,
            fp,
            indent=2
        )

    print()
    print(
        f"Results written to: {output_path}"
    )


if __name__ == "__main__":
    main()

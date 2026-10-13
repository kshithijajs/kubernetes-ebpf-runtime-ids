#!/usr/bin/env python3

"""
Dataset V2 — Phase 3
Leakage Audit / Feature Ablation

All configurations use:
    - frozen Dataset V2 formal cohort
    - Family E excluded/reserved
    - existing eBPF event filtering
    - existing stage inference
    - existing 14-feature extraction
    - 5-second windows
    - minimum 5 events/window
    - identical session-grouped 5-fold CV
    - identical Random Forest configuration

The purpose is to quantify the contribution of:
    1. event-statistical telemetry
    2. behavioral ratios
    3. stage-aware features
    4. the complete 14-feature representation
"""

import csv
import json
import os
import re

import numpy as np

from sklearn.ensemble import RandomForestClassifier
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


# ============================================================
# Exact existing feature definitions
# ============================================================

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


# ============================================================
# Feature-set definitions
# ============================================================

FEATURE_SETS = {

    "A_Event_Statistical": [
        "exec_count",
        "net_count",
        "lateral_count",
        "file_count",
        "unique_pids",
        "unique_comms",
    ],

    "B_Telemetry_Behavioral": [
        "exec_count",
        "net_count",
        "lateral_count",
        "file_count",
        "unique_pids",
        "unique_comms",
        "net_exec_ratio",
        "lateral_net_ratio",
        "sensitive_file_ratio",
        "alert_count",
    ],

    "C_Stage_Aware": [
        "exec_count",
        "net_count",
        "lateral_count",
        "file_count",
        "unique_pids",
        "unique_comms",
        "net_exec_ratio",
        "lateral_net_ratio",
        "sensitive_file_ratio",
        "alert_count",
        "privesc_count",
        "persist_count",
        "exfil_count",
        "stage_count",
    ],

    "D_Full_14": FEATURE_NAMES,
}


# ============================================================
# Existing filtering configuration
# ============================================================

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
# Existing stage inference
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
            add_stage(
                stages,
                event_type
            )

        if event_type == "EXEC":

            cmd = command_name(
                event.get("comm", "")
            )

            for stage, commands in COMMAND_STAGES.items():

                if cmd in commands:
                    add_stage(
                        stages,
                        stage
                    )

        if event_type in {
            "FILE",
            "MKDIR",
            "UNLINK"
        }:

            if detail_has_any(
                detail,
                [
                    "/etc/passwd",
                    "/etc/os-release"
                ]
            ):
                add_stage(
                    stages,
                    "RECON"
                )

            if detail_has_any(
                detail,
                [
                    "/proc/1/status",
                    "/proc/self/status"
                ]
            ):
                add_stage(
                    stages,
                    "PRIVESC"
                )

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
                add_stage(
                    stages,
                    "PERSIST"
                )

            if detail_has_any(
                detail,
                [
                    "/tmp/data",
                    "/tmp/demo-data"
                ]
            ):
                add_stage(
                    stages,
                    "EXFIL"
                )

    return [
        stage
        for stage in STAGE_ORDER
        if stage in stages
    ]


# ============================================================
# Existing feature extraction
# ============================================================

def extract_feature_dict(events):

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

    return {

        "exec_count": exec_count,
        "net_count": net_count,
        "lateral_count": lateral_count,
        "privesc_count": privesc_count,
        "persist_count": persist_count,
        "exfil_count": exfil_count,
        "file_count": file_count,
        "alert_count": alert_count,
        "stage_count": stage_count,
        "unique_pids": unique_pids,
        "unique_comms": unique_comms,

        "net_exec_ratio":
            net_count / max(exec_count, 1),

        "lateral_net_ratio":
            lateral_count / max(net_count, 1),

        "sensitive_file_ratio":
            sensitive_files / max(len(events), 1),
    }


# ============================================================
# Loading and windowing
# ============================================================

def load_events(filename):

    events = []

    with open(filename) as fp:

        for line in fp:

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("comm", "") in IGNORE_COMMS:
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


# ============================================================
# Build frozen Dataset V2 development set
# ============================================================

def build_dataset():

    with open(MANIFEST, newline="") as fp:
        rows = list(csv.DictReader(fp))

    # Family E remains completely reserved.
    rows = [
        r for r in rows
        if not (
            r["label"] == "attack"
            and r["attack_family"] == "E"
        )
    ]

    X_dict = []
    y = []
    groups = []

    for row in rows:

        events = load_events(
            row["source_file"]
        )

        windows = split_windows(events)

        for window in windows:

            if len(window) < MIN_EVENTS_PER_WINDOW:
                continue

            X_dict.append(
                extract_feature_dict(window)
            )

            y.append(
                int(row["label"] == "attack")
            )

            groups.append(
                row["session_id"]
            )

    return (
        X_dict,
        np.asarray(y, dtype=int),
        np.asarray(groups)
    )


# ============================================================
# Metrics
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
        tn + fp,
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
# Main experiment
# ============================================================

def main():

    X_dict, y, groups = build_dataset()

    print("=" * 75)
    print("DATASET V2 — PHASE 3 FEATURE ABLATION")
    print("=" * 75)

    print(
        f"Sessions: {len(set(groups))}"
    )

    print(
        f"Windows : {len(X_dict)}"
    )

    print(
        f"Normal  : {(y == 0).sum()}"
    )

    print(
        f"Attack  : {(y == 1).sum()}"
    )

    print(
        "Family E: RESERVED"
    )

    splitter = StratifiedGroupKFold(
        n_splits=N_SPLITS,
        shuffle=True,
        random_state=RANDOM_STATE
    )

    results = {
        name: []
        for name in FEATURE_SETS
    }

    for fold, (train_idx, test_idx) in enumerate(
        splitter.split(
            np.zeros(len(y)),
            y,
            groups
        ),
        start=1
    ):

        print()
        print("=" * 75)
        print(f"FOLD {fold}")
        print("=" * 75)

        print(
            f"Training sessions: "
            f"{len(set(groups[train_idx]))}"
        )

        print(
            f"Testing sessions : "
            f"{len(set(groups[test_idx]))}"
        )

        for config_name, feature_names in FEATURE_SETS.items():

            feature_indices = [
                FEATURE_NAMES.index(name)
                for name in feature_names
            ]

            # Convert dictionaries into arrays.
            X_all = np.asarray([
                [
                    x[name]
                    for name in feature_names
                ]
                for x in X_dict
            ], dtype=float)

            X_train = X_all[train_idx]
            X_test = X_all[test_idx]

            y_train = y[train_idx]
            y_test = y[test_idx]

            scaler = StandardScaler()

            X_train = scaler.fit_transform(
                X_train
            )

            X_test = scaler.transform(
                X_test
            )

            rf = RandomForestClassifier(
                n_estimators=RF_ESTIMATORS,
                max_depth=RF_MAX_DEPTH,
                random_state=RANDOM_STATE
            )

            rf.fit(
                X_train,
                y_train
            )

            score = rf.predict_proba(
                X_test
            )[:, 1]

            pred = (
                score >= 0.5
            ).astype(int)

            metrics = calculate_metrics(
                y_test,
                pred,
                score
            )

            results[
                config_name
            ].append(metrics)

            print(
                f"{config_name:<28} "
                f"F1={metrics['f1']:.4f} "
                f"AUC={metrics['roc_auc']:.4f} "
                f"FPR={metrics['fpr']:.4f}"
            )

    # ========================================================
    # Summary
    # ========================================================

    print()
    print("=" * 85)
    print("PHASE 3 — ABLATION SUMMARY")
    print("=" * 85)

    summary = {}

    for config_name, fold_results in results.items():

        summary[config_name] = {}

        print()
        print(config_name)
        print("-" * len(config_name))

        for metric in [
            "accuracy",
            "precision",
            "recall",
            "f1",
            "roc_auc",
            "pr_auc",
            "fpr",
        ]:

            values = np.asarray([
                r[metric]
                for r in fold_results
            ])

            mean = values.mean()
            std = values.std(ddof=1)

            summary[
                config_name
            ][metric] = {
                "mean": float(mean),
                "std": float(std),
                "folds": [
                    float(v)
                    for v in values
                ],
            }

            print(
                f"{metric:<10}: "
                f"{mean:.4f} +/- {std:.4f}"
            )

        print("Confusion matrices:")

        summary[
            config_name
        ]["confusion_matrices"] = []

        for i, r in enumerate(
            fold_results,
            start=1
        ):

            cm = {
                "tn": r["tn"],
                "fp": r["fp"],
                "fn": r["fn"],
                "tp": r["tp"],
            }

            summary[
                config_name
            ]["confusion_matrices"].append(cm)

            print(
                f"  Fold {i}: "
                f"TN={cm['tn']} "
                f"FP={cm['fp']} "
                f"FN={cm['fn']} "
                f"TP={cm['tp']}"
            )

    # ========================================================
    # Stage contribution
    # ========================================================

    auc_a = summary[
        "A_Event_Statistical"
    ]["roc_auc"]["mean"]

    auc_b = summary[
        "B_Telemetry_Behavioral"
    ]["roc_auc"]["mean"]

    auc_c = summary[
        "C_Stage_Aware"
    ]["roc_auc"]["mean"]

    auc_d = summary[
        "D_Full_14"
    ]["roc_auc"]["mean"]

    print()
    print("=" * 85)
    print("AUC DIFFERENCES")
    print("=" * 85)

    print(
        f"Behavioral vs event-statistical: "
        f"{auc_b - auc_a:+.4f}"
    )

    print(
        f"Stage-aware vs behavioral: "
        f"{auc_c - auc_b:+.4f}"
    )

    print(
        f"Full vs stage-aware: "
        f"{auc_d - auc_c:+.4f}"
    )

    output = {
        "experiment": "Dataset V2 Phase 3 Feature Ablation",
        "dataset": {
            "sessions": 90,
            "normal_sessions": 50,
            "attack_sessions": 40,
            "attack_families": ["A", "B", "C", "D"],
            "reserved_family": "E",
            "windows": len(X_dict),
            "features_total": len(FEATURE_NAMES),
            "window_sec": WINDOW_SEC,
            "min_events_per_window": MIN_EVENTS_PER_WINDOW,
            "grouped_cv": True,
            "n_splits": N_SPLITS,
            "random_state": RANDOM_STATE,
        },
        "feature_sets": FEATURE_SETS,
        "results": summary,
        "auc_differences": {
            "behavioral_minus_event_statistical":
                float(auc_b - auc_a),

            "stage_aware_minus_behavioral":
                float(auc_c - auc_b),

            "full_minus_stage_aware":
                float(auc_d - auc_c),
        }
    }

    output_file = (
        "dataset_v2_phase3_ablation_results.json"
    )

    with open(output_file, "w") as fp:
        json.dump(
            output,
            fp,
            indent=2
        )

    print()
    print(
        f"Results written to: {output_file}"
    )


if __name__ == "__main__":
    main()

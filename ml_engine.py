#!/usr/bin/env python3
"""
Hybrid detection engine for the eBPF Kubernetes intrusion demo.

The C loader is the source of truth for attack stage names. This engine
reuses those stages, adds lightweight ML scoring, and writes risk records for
Grafana/Loki ingestion.
"""

import collections
import json
import os
import re
import time

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler


EVENT_LOG = "/var/log/ebpf-events.json"
RISK_LOG = "/var/log/ebpf-risk.json"
POLL_SEC = 3
WINDOW_SEC = 30
IF_THRESH = -0.10
RF_THRESH = 0.60

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

STAGE_ORDER = ["ENTRY", "RECON", "PRIVESC", "LATERAL", "PERSIST", "EXFIL"]
STAGE_BITS = {
    1: "ENTRY",
    2: "RECON",
    4: "PRIVESC",
    8: "LATERAL",
    16: "PERSIST",
    32: "EXFIL",
}
STAGE_WEIGHTS = {
    "ENTRY": 10,
    "RECON": 10,
    "PRIVESC": 25,
    "LATERAL": 15,
    "PERSIST": 20,
    "EXFIL": 20,
}

COMMAND_STAGES = {
    "ENTRY": {"sh", "bash", "dash", "zsh", "ash"},
    "RECON": {
        "hostname",
        "whoami",
        "id",
        "env",
        "cat",
        "ls",
        "ps",
        "curl",
        "wget",
        "nslookup",
        "dig",
        "host",
        "ip",
        "ifconfig",
        "ss",
        "netstat",
        "arp",
        "nmap",
        "busybox",
    },
    "PRIVESC": {
        "sudo",
        "su",
        "pkexec",
        "find",
        "mount",
        "capsh",
        "unshare",
        "setcap",
        "getcap",
    },
    "LATERAL": {"nc", "ncat", "netcat", "ssh", "scp", "telnet", "socat", "psql", "mysql"},
    "PERSIST": {"crontab", "systemctl"},
    "EXFIL": {"tar", "gzip", "zip", "base64", "scp", "rsync", "openssl"},
}

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


def add_stage(stages, stage):
    if stage in STAGE_ORDER and stage not in stages:
        stages.append(stage)


def command_name(comm):
    return os.path.basename(str(comm or "")).lower()


def stages_from_alert_mask(detail):
    match = re.search(r"stages_mask=(\d+)", detail or "")
    if not match:
        return []

    mask = int(match.group(1))
    return [stage for bit, stage in STAGE_BITS.items() if mask & bit]


def stage_from_detail(detail):
    match = re.search(r"\bStage=([A-Z]+)\b", detail or "")
    if not match:
        return None
    return match.group(1)


def detail_has_any(detail, values):
    text = str(detail or "")
    return any(value in text for value in values)


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


def rule_engine(events):
    stages = infer_stages(events)
    types = {event.get("type", "") for event in events}
    triggered = len(stages) >= 2 or "ALERT" in types
    return triggered, stages


def compute_risk(stages, if_score, rf_prob):
    risk = sum(STAGE_WEIGHTS.get(stage, 10) for stage in stages)
    risk += max(0, int((-if_score) * 35))
    risk += int(rf_prob * 25)
    return min(risk, 100)


class ProcessRiskTracker:
    def __init__(self):
        self.processes = collections.defaultdict(
            lambda: {"risk": 0, "stages": [], "last_seen": 0, "alerts": 0}
        )

    def update(self, comm, pid, risk, stages):
        key = f"{comm}:{pid}"
        proc = self.processes[key]
        proc["risk"] = max(proc["risk"], risk)
        proc["last_seen"] = int(time.time())
        proc["alerts"] += 1
        for stage in stages:
            if stage not in proc["stages"]:
                proc["stages"].append(stage)

    def top(self, n=5):
        return sorted(self.processes.items(), key=lambda item: item[1]["risk"], reverse=True)[:n]


def main():
    print("=" * 55)
    print("  eBPF Hybrid ML Detection Engine")
    print("  Isolation Forest + Random Forest + stage rules")
    print("=" * 55)

    print("\n[1/3] Training Isolation Forest on normal baseline...")
    x_all, y_all = generate_training_data()
    normal_x = x_all[y_all == 0]
    iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    iso_forest.fit(normal_x)
    print("      Isolation Forest ready")

    print("[2/3] Training Random Forest on labeled data...")
    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x_all)
    rand_forest = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    rand_forest.fit(x_scaled, y_all)
    print("      Random Forest ready")
    print("[3/3] Starting event monitoring...\n")

    tracker = ProcessRiskTracker()
    risk_fp = open(RISK_LOG, "w", encoding="utf-8")
    seen_lines = 0
    all_events = []

    def flush_risk(risk, stages, if_score, rf_prob, rule_hit, rf_hit, if_hit, comm, pid):
        record = {
            "ts": int(time.time()),
            "type": "RISK",
            "risk_score": int(risk),
            "stages": stages,
            "if_score": round(float(if_score), 4),
            "rf_prob": round(float(rf_prob), 4),
            "rule_hit": 1 if rule_hit else 0,
            "rf_hit": 1 if rf_hit else 0,
            "if_hit": 1 if if_hit else 0,
            "comm": str(comm),
            "pid": int(pid),
            "detail": f"risk={risk} stages={','.join(stages)} if={float(if_score):.3f} rf={float(rf_prob):.3f}",
        }
        risk_fp.write(json.dumps(record) + "\n")
        risk_fp.flush()

    try:
        while True:
            if os.path.exists(EVENT_LOG):
                with open(EVENT_LOG, "r", encoding="utf-8", errors="replace") as event_fp:
                    lines = event_fp.readlines()

                if len(lines) < seen_lines:
                    seen_lines = 0
                    all_events = []

                for line in lines[seen_lines:]:
                    line = line.strip()
                    seen_lines += 1
                    if not line:
                        continue
                    try:
                        all_events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            now = int(time.time())
            all_events = [event for event in all_events if now - event.get("ts", 0) <= WINDOW_SEC * 4]
            window = [
                event
                for event in all_events
                if now - event.get("ts", 0) <= WINDOW_SEC
                and event.get("comm", "") not in IGNORE_COMMS
            ]

            if not window:
                time.sleep(POLL_SEC)
                continue

            rule_hit, stages = rule_engine(window)
            features = extract_features(window)
            x = np.array([features], dtype=float)
            x_sc = scaler.transform(x)

            if_score = float(iso_forest.score_samples(x)[0])
            if_hit = if_score < IF_THRESH
            rf_prob = float(rand_forest.predict_proba(x_sc)[0][1])
            rf_hit = rf_prob > RF_THRESH

            risk = compute_risk(stages, if_score, rf_prob)
            triggered = rule_hit or rf_hit or if_hit
            status = "ATTACK" if triggered else "NORMAL"

            print(
                f"{status:6s} | risk={risk:3d}/100 | stages={stages} | "
                f"IF={'ANOM' if if_hit else 'ok':4s} ({if_score:+.3f}) | "
                f"RF={'ATCK' if rf_hit else 'ok':4s} ({rf_prob:.2f}) | "
                f"rule={'HIT' if rule_hit else 'miss'}"
            )

            if triggered and window:
                last_event = window[-1]
                comm = str(last_event.get("comm", "unknown"))
                pid = int(last_event.get("pid", 0))
                tracker.update(comm, pid, risk, stages)

                print("\n  Top Risky Processes")
                for proc, info in tracker.top(3):
                    bar = "#" * max(1, info["risk"] // 10)
                    print(f"    {proc:<24} risk={info['risk']:3d} {bar}")
                print()

                flush_risk(risk, stages, if_score, rf_prob, rule_hit, rf_hit, if_hit, comm, pid)

            time.sleep(POLL_SEC)

    except KeyboardInterrupt:
        print("\nStopping ML engine.")
    finally:
        risk_fp.close()


if __name__ == "__main__":
    main()

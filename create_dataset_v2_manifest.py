#!/usr/bin/env python3

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("dataset_v2")
OUTPUT = ROOT / "dataset_v2_manifest.csv"

# Formal 100-session Dataset V2 cohort
NORMAL_SESSIONS = [
    f"N{i:03d}" for i in range(4, 48)
] + [
    f"N{i:03d}" for i in range(49, 55)
]

ATTACK_SESSIONS = {
    "A": [f"A{i:03d}" for i in range(1, 11)],
    "B": [f"B{i:03d}" for i in range(1, 11)],
    "C": [f"C{i:03d}" for i in range(1, 11)],
    "D": [f"D{i:03d}" for i in range(1, 11)],
    "E": [f"E{i:03d}" for i in range(1, 11)],
}


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_events(path):
    events = []

    with path.open() as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))

    return events


def session_info(category, session_id, family=None):
    path = ROOT / category / session_id / "events.json"

    if not path.exists():
        raise FileNotFoundError(path)

    events = load_events(path)

    timestamps = [
        e["ts"]
        for e in events
        if isinstance(e.get("ts"), (int, float))
    ]

    if timestamps:
        start_ts = min(timestamps)
        end_ts = max(timestamps)
        duration = end_ts - start_ts
    else:
        start_ts = ""
        end_ts = ""
        duration = 0

    event_types = {}
    for e in events:
        t = e.get("type", "UNKNOWN")
        event_types[t] = event_types.get(t, 0) + 1

    # Normalized event-sequence hash.
    # Timestamp is removed so identical recordings with different
    # timestamps receive the same hash.
    normalized = []

    for e in events:
        x = dict(e)
        x.pop("ts", None)
        normalized.append(x)

    normalized_blob = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    normalized_hash = hashlib.sha256(normalized_blob).hexdigest()

    return {
        "session_id": session_id,
        "label": "normal" if category == "normal" else "attack",
        "attack_family": family or "",
        "events": len(events),
        "duration_sec": round(duration, 3),
        "start_ts": start_ts,
        "end_ts": end_ts,
        "event_types": json.dumps(
            event_types,
            sort_keys=True,
            separators=(",", ":")
        ),
        "normalized_sequence_sha256": normalized_hash,
        "events_sha256": sha256_file(path),
        "source_file": str(path),
        "valid_json": True,
        "cohort": "Dataset_V2_formal",
        "collection_status": "included",
    }


def main():
    rows = []

    # Normal cohort
    for session_id in NORMAL_SESSIONS:
        rows.append(
            session_info(
                "normal",
                session_id,
                family=None
            )
        )

    # Attack cohort
    for family, sessions in ATTACK_SESSIONS.items():
        for session_id in sessions:
            rows.append(
                session_info(
                    "attack",
                    session_id,
                    family=family
                )
            )

    rows.sort(key=lambda r: (
        0 if r["label"] == "normal" else 1,
        r["attack_family"],
        r["session_id"]
    ))

    fieldnames = list(rows[0].keys())

    with OUTPUT.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print("=" * 60)
    print("Dataset V2 manifest created")
    print("=" * 60)
    print(f"Output: {OUTPUT}")
    print(f"Total sessions: {len(rows)}")

    normal = sum(r["label"] == "normal" for r in rows)
    attack = sum(r["label"] == "attack" for r in rows)

    print(f"Normal: {normal}")
    print(f"Attack: {attack}")

    for family in "ABCDE":
        count = sum(
            r["label"] == "attack" and
            r["attack_family"] == family
            for r in rows
        )
        print(f"Family {family}: {count}")

    unique_hashes = len({
        r["normalized_sequence_sha256"]
        for r in rows
    })

    print(f"Unique normalized sequences: {unique_hashes}")

    if len(rows) != 100:
        raise RuntimeError(
            f"Expected 100 formal sessions, found {len(rows)}"
        )

    if normal != 50:
        raise RuntimeError(
            f"Expected 50 normal sessions, found {normal}"
        )

    if attack != 50:
        raise RuntimeError(
            f"Expected 50 attack sessions, found {attack}"
        )

    for family in "ABCDE":
        count = sum(
            r["label"] == "attack" and
            r["attack_family"] == family
            for r in rows
        )
        if count != 10:
            raise RuntimeError(
                f"Expected 10 Family {family} sessions, found {count}"
            )

    print("\nDataset V2 formal cohort: PASS")
    print("50 normal + 10 A + 10 B + 10 C + 10 D + 10 E")


if __name__ == "__main__":
    main()

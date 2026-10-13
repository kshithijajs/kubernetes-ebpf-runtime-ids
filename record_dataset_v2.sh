#!/usr/bin/env bash

set -u
set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DATASET_DIR="$ROOT_DIR/dataset_v2"
RAW_LOG="/var/log/ebpf-events.json"
LOADER="$ROOT_DIR/build/loader"

NAMESPACE="demo"
ATTACKER_POD="attacker"

mkdir -p "$DATASET_DIR/normal"
mkdir -p "$DATASET_DIR/attack"
mkdir -p "$DATASET_DIR/failed"

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

echo "============================================================"
echo "Dataset V2 recorder"
echo "============================================================"
echo "Namespace : $NAMESPACE"
echo "Attacker  : $ATTACKER_POD"
echo "Dataset   : $DATASET_DIR"
echo

# ------------------------------------------------------------
# Preconditions
# ------------------------------------------------------------

command -v kubectl >/dev/null 2>&1 || die "kubectl not found"
command -v make >/dev/null 2>&1 || die "make not found"
command -v python3 >/dev/null 2>&1 || die "python3 not found"

[[ -x "$LOADER" ]] || {
    echo "[+] Building eBPF collector..."
    make all || die "Collector build failed"
}

kubectl get pod "$ATTACKER_POD" -n "$NAMESPACE" >/dev/null 2>&1 \
    || die "Attacker pod '$ATTACKER_POD' does not exist in namespace '$NAMESPACE'"

kubectl wait \
    --namespace "$NAMESPACE" \
    --for=condition=Ready \
    "pod/$ATTACKER_POD" \
    --timeout=30s >/dev/null \
    || die "Attacker pod is not Ready"

echo "[+] Kubernetes attacker pod verified"

echo "[+] Kubernetes attacker pod verified"

# ------------------------------------------------------------
# Session IDs
# ------------------------------------------------------------

next_normal_id() {
    local max=0
    local d n

    for d in "$DATASET_DIR"/normal/N[0-9][0-9][0-9]; do
        [[ -d "$d" ]] || continue

        n="${d##*/}"
        n="${n#N}"

        [[ "$n" =~ ^[0-9]+$ ]] || continue

        (( 10#$n > max )) && max=$((10#$n))
    done

    printf "N%03d" "$((max + 1))"
}

next_attack_id() {
    local family="$1"
    local max=0
    local d n

    for d in "$DATASET_DIR"/attack/${family}[0-9][0-9][0-9]; do
        [[ -d "$d" ]] || continue

        n="${d##*/}"
        n="${n#$family}"

        [[ "$n" =~ ^[0-9]+$ ]] || continue

        (( 10#$n > max )) && max=$((10#$n))
    done

    printf "%s%03d" "$family" "$((max + 1))"
}

# ------------------------------------------------------------
# Collector
# ------------------------------------------------------------

LOADER_PID=""

start_collector() {

    echo "[+] Building collector..."
    make all >/dev/null || die "Collector build failed"

    # Ensure no previous loader remains.
    sudo pkill -INT -x loader 2>/dev/null || true
    sleep 1

    echo "[+] Starting eBPF collector..."

    sudo "$LOADER" > /tmp/dataset_v2_loader.log 2>&1 &
    LOADER_PID=$!

    sleep 2

    if ! kill -0 "$LOADER_PID" 2>/dev/null; then
        echo
        cat /tmp/dataset_v2_loader.log >&2
        die "eBPF loader failed to start"
    fi

    [[ -f "$RAW_LOG" ]] \
        || die "Collector did not create $RAW_LOG"

    echo "[+] Collector running: PID=$LOADER_PID"
}

stop_collector() {

    if [[ -n "$LOADER_PID" ]] &&
       kill -0 "$LOADER_PID" 2>/dev/null; then

        echo "[+] Stopping collector..."

        kill -INT "$LOADER_PID" 2>/dev/null || true

        for _ in {1..30}; do
            if ! kill -0 "$LOADER_PID" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done

        if kill -0 "$LOADER_PID" 2>/dev/null; then
            echo "[WARN] Loader did not exit after SIGINT"
            kill -TERM "$LOADER_PID" 2>/dev/null || true
        fi

        wait "$LOADER_PID" 2>/dev/null || true
    fi

    LOADER_PID=""
}

cleanup() {
    stop_collector
}

trap cleanup EXIT INT TERM

# ------------------------------------------------------------
# Validate raw JSON
# ------------------------------------------------------------

validate_json() {
    local file="$1"

    python3 - "$file" <<'PY'
import json
import sys

path = sys.argv[1]

total = 0
bad = 0

with open(path, "r", errors="replace") as f:
    for line in f:
        line = line.strip()

        if not line:
            continue

        total += 1

        try:
            json.loads(line)
        except Exception:
            bad += 1

print(f"VALIDATION_LINES={total}")
print(f"INVALID_JSON={bad}")

if total == 0 or bad != 0:
    sys.exit(1)
PY
}

# ------------------------------------------------------------
# Save recording
# ------------------------------------------------------------

save_recording() {

    local label="$1"
    local session_id="$2"
    local family="$3"
    local start_epoch="$4"

    local session_dir="$DATASET_DIR/$label/$session_id"
    local end_epoch
    local duration
    local bytes
    local lines

    mkdir -p "$session_dir"

    if [[ ! -f "$RAW_LOG" ]]; then
        echo "[ERROR] No event log produced"
        return 1
    fi

    cp "$RAW_LOG" "$session_dir/events.json"

    end_epoch="$(date +%s)"
    duration=$((end_epoch - start_epoch))

    bytes="$(wc -c < "$session_dir/events.json" | tr -d ' ')"
    lines="$(grep -cve '^[[:space:]]*$' "$session_dir/events.json" || true)"

    echo
    echo "[+] Validating recording..."

    if ! validate_json "$session_dir/events.json"; then
        echo "[ERROR] Invalid or empty recording"
        return 1
    fi

    cat > "$session_dir/metadata.json" <<META
{
  "session_id": "$session_id",
  "label": "$label",
  "attack_family": "$family",
  "namespace": "$NAMESPACE",
  "attacker_pod": "$ATTACKER_POD",
  "start_epoch": $start_epoch,
  "end_epoch": $end_epoch,
  "duration_seconds": $duration,
  "raw_event_lines": $lines,
  "raw_file_bytes": $bytes
}
META

    echo
    echo "------------------------------------------------------------"
    echo "VALID RECORDING"
    echo "------------------------------------------------------------"
    echo "Session      : $session_id"
    echo "Label        : $label"
    echo "Family       : $family"
    echo "Duration     : ${duration}s"
    echo "Raw events   : $lines"
    echo "File size    : $bytes bytes"
    echo "Directory    : $session_dir"
    echo "------------------------------------------------------------"

    return 0
}

# ------------------------------------------------------------
# Execute workload inside attacker
# ------------------------------------------------------------

run_normal_workload() {
    echo "[NORMAL] Running benign workload..."
    echo "[normal] start"

    for i in 1 2 3 4 5; do
        kubectl exec -n "$NAMESPACE" "$ATTACKER_POD" -- \
            curl -q --connect-timeout 2 --max-time 4 \
            http://frontend >/dev/null 2>&1 || true

        kubectl exec -n "$NAMESPACE" "$ATTACKER_POD" -- \
            curl -q --connect-timeout 2 --max-time 4 \
            http://backend:5000 >/dev/null 2>&1 || true

        sleep 1
    done

    echo "[normal] complete"
}

run_attack_workload() {

    local family="$1"
    local script="$ROOT_DIR/attack_family_${family}.sh"

    [[ -f "$script" ]] \
        || {
            echo "[ERROR] Missing $script"
            return 1
        }

    echo "[ATTACK] Running Family $family..."

    kubectl exec -i -n "$NAMESPACE" "$ATTACKER_POD" \
        -- sh -c '
            cat > /tmp/dataset_v2_attack.sh &&
            chmod 755 /tmp/dataset_v2_attack.sh &&
            /tmp/dataset_v2_attack.sh
        ' < "$script"

    local rc=$?

    kubectl exec -n "$NAMESPACE" "$ATTACKER_POD" \
        -- rm -f /tmp/dataset_v2_attack.sh >/dev/null 2>&1 || true

    return "$rc"
}

# ------------------------------------------------------------
# Record normal
# ------------------------------------------------------------

record_normal() {

    local id
    local start

    id="$(next_normal_id)"

    echo
    echo "============================================================"
    echo "NORMAL SESSION $id"
    echo "============================================================"

    start="$(date +%s)"

    start_collector

    if ! run_normal_workload; then
        echo "[ERROR] Normal workload failed"
        stop_collector
        return 1
    fi

    stop_collector

    save_recording normal "$id" "NONE" "$start"
}

# ------------------------------------------------------------
# Record attack
# ------------------------------------------------------------

record_attack() {

    local family="$1"
    local id
    local start

    id="$(next_attack_id "$family")"

    echo
    echo "============================================================"
    echo "ATTACK SESSION $id"
    echo "Family: $family"
    echo "============================================================"

    start="$(date +%s)"

    start_collector

    if ! run_attack_workload "$family"; then
        echo "[ERROR] Attack workload failed"
        stop_collector
        return 1
    fi

    stop_collector

    save_recording attack "$id" "$family" "$start"
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

case "${1:-}" in

    --normal)
        count="${2:-1}"

        [[ "$count" =~ ^[0-9]+$ ]] \
            || die "Normal count must be an integer"

        for ((i=1; i<=count; i++)); do
            echo
            echo "######## NORMAL $i / $count ########"
            record_normal || echo "[FAILED] Normal session"
        done
        ;;

    --attack-family)
        family="${2:-}"
        count="${3:-1}"

        case "$family" in
            A|B|C|D|E) ;;
            *) die "Family must be A, B, C, D or E" ;;
        esac

        [[ "$count" =~ ^[0-9]+$ ]] \
            || die "Attack count must be an integer"

        for ((i=1; i<=count; i++)); do
            echo
            echo "######## FAMILY $family — $i / $count ########"
            record_attack "$family" || echo "[FAILED] Attack session"
        done
        ;;

    --attack)
        count="${2:-1}"

        [[ "$count" =~ ^[0-9]+$ ]] \
            || die "Attack count must be an integer"

        families=(A B C D E)

        for ((i=1; i<=count; i++)); do
            family="${families[$(( (i-1) % 5 ))]}"

            echo
            echo "######## ATTACK $i / $count — FAMILY $family ########"

            record_attack "$family" || echo "[FAILED] Attack session"
        done
        ;;

    *)
        echo
        echo "Usage:"
        echo
        echo "  sudo ./record_dataset_v2.sh --normal 1"
        echo "  sudo ./record_dataset_v2.sh --attack-family A 1"
        echo "  sudo ./record_dataset_v2.sh --attack 50"
        echo
        exit 1
        ;;
esac

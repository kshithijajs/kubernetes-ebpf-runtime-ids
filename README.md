# eBPF Multi-Stage Intrusion Detection Demo

This project is a Kubernetes runtime intrusion-detection demo. It creates a
small Kind cluster with frontend, backend, database, and attacker workloads.
An eBPF program collects kernel events, a C loader converts them to JSON, and
`ml_engine.py` adds rule-based stages plus lightweight ML risk scoring.

## Six Stages

The code, attack script, and workbook now use the same stage model:

1. ENTRY - shell entry such as `bash` or `sh`
2. RECON - discovery commands and sensitive reads such as `/etc/passwd`
3. PRIVESC - safe privilege escalation simulation such as SUID chmod or proc inspection
4. LATERAL - internal TCP movement to Kubernetes services
5. PERSIST - cron/update-style artifacts under `/tmp`, `/etc/cron`, or `/root`
6. EXFIL - data staging/archive/upload simulation under `/tmp/data` and `/tmp/demo-data`

## Linux Prerequisites

Run the detector on the Linux host or VM where the Kind node runs:

```sh
sudo apt-get update
sudo apt-get install -y clang llvm gcc make libbpf-dev libelf-dev zlib1g-dev python3-pip
python3 -m pip install -r requirements.txt
```

## Deploy The Lab

From this `ebpf-demo` directory:

```sh
kind create cluster --config ../kind-cluster.yaml
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/
kubectl wait -n demo --for=condition=Ready pod/attacker --timeout=240s
kubectl wait -n demo --for=condition=Available deployment/backend --timeout=180s
kubectl wait -n demo --for=condition=Available deployment/frontend --timeout=180s
kubectl wait -n demo --for=condition=Available deployment/database --timeout=180s
```

The attacker pod installs the tools used by the attack script before it becomes
ready. Start the detector after the lab is up so package-install noise is not
mixed into the attack run.

## Build And Run Detection

Use two terminals:

```sh
make clean all
sudo ./build/loader
```

```sh
sudo -E python3 ml_engine.py
```

The loader writes `/var/log/ebpf-events.json`.
The ML engine writes `/var/log/ebpf-risk.json`.

## Run The Attack Sequence

Use a third terminal:

```sh
kubectl cp attack_sequence_commands.sh demo/attacker:/tmp/attack_sequence_commands.sh
kubectl exec -n demo -it attacker -- sh /tmp/attack_sequence_commands.sh
```

Expected loader result:

```text
Stages completed: 6/6
```

## Grafana/Loki Notes

The repo does not include a full Grafana/Loki stack. If Grafana is already
configured, make sure Promtail or another collector scrapes:

```text
/var/log/ebpf-events.json
/var/log/ebpf-risk.json
```

Useful Loki filters:

```logql
{filename="/var/log/ebpf-events.json"} | json | type="STAGE"
{filename="/var/log/ebpf-events.json"} | json | type="ALERT"
{filename="/var/log/ebpf-risk.json"} | json | type="RISK"
```
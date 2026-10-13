#!/bin/sh

run() {
    printf '\n$ %s\n' "$*"
    sh -c "$*" || true
}

printf '\n========== Family E: Unseen Behavioural Combination ==========\n'

# Different shell-entry pattern
run "sh -c 'echo unseen-family-entry'"

# System and network discovery
run "uname -r"
run "ip route"
run "ss -tuln"
run "cat /etc/hostname"

# Process/kernel inspection
run "cat /proc/self/status >/dev/null"

# Capability/SUID-oriented discovery
run "getcap -r / 2>/dev/null | head"
run "find / -perm -4000 -type f 2>/dev/null | head"

# Different service interaction pattern
run "curl -s http://frontend/ >/dev/null"
run "curl -s http://backend:5000/secret >/dev/null"

# Different persistence-style artifact
run "mkdir -p /tmp/family-e-state"
run "printf 'runtime-state\n' > /tmp/family-e-state/config"
run "chmod 644 /tmp/family-e-state/config"

# Different local collection pattern
run "mkdir -p /tmp/family-e-collection"
run "cp /etc/hostname /tmp/family-e-collection/system"
run "cp /etc/resolv.conf /tmp/family-e-collection/resolver"

# Archive with a different structure
run "tar -czf /tmp/family-e-bundle.tar.gz -C /tmp family-e-collection"

printf '\nFamily E complete. This family is reserved exclusively for testing.\n'

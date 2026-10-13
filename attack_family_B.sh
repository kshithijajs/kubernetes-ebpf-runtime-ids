#!/bin/sh

run() {
    printf '\n$ %s\n' "$*"
    sh -c "$*" || true
}

printf '\n========== Family B: Network/Service Discovery ==========\n'

run "sh -c 'echo family-B-entry'"

# Host and network discovery
run "hostname"
run "ip addr"
run "ip route"
run "ss -tuln"
run "cat /etc/resolv.conf"
run "cat /etc/hosts"

# Process discovery
run "ps -ef"

# Service probing / simulated lateral activity
run "nc -vz backend 5000"
run "nc -vz database 5432"

printf '\nFamily B complete.\n'

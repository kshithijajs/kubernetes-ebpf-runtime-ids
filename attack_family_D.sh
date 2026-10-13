#!/bin/sh

run() {
    printf '\n$ %s\n' "$*"
    sh -c "$*" || true
}

printf '\n========== Family D: Persistence/Data Staging ==========\n'

run "dash -c 'echo family-D-entry'"

# Minimal discovery
run "hostname"
run "whoami"
run "id"
run "ls -la /tmp"

# Simulated persistence
run "mkdir -p /tmp/family-d-persist"
run "printf '#!/bin/sh\necho simulated-update\n' > /tmp/family-d-persist/update.sh"
run "chmod 755 /tmp/family-d-persist/update.sh"
run "printf '* * * * * /tmp/family-d-persist/update.sh\n' > /tmp/family-d-persist/cron"

# Local data staging
run "mkdir -p /tmp/family-d-stage"
run "cp /etc/hostname /tmp/family-d-stage/hostname.copy"
run "cp /etc/os-release /tmp/family-d-stage/os-release.copy"
run "cp /etc/hosts /tmp/family-d-stage/hosts.copy"

# Archive locally; no network transfer
run "tar -czf /tmp/family-d-stage.tar.gz -C /tmp family-d-stage"

run "ls -lh /tmp/family-d-persist"
run "ls -lh /tmp/family-d-stage.tar.gz"

printf '\nFamily D complete.\n'

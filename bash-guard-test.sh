#!/usr/bin/env bash
# =============================================================================
# bash-guard-test.sh — Exhaustive test suite for bash-guard.sh
# =============================================================================
# Run: bash bash-guard-test.sh
#
# Each test pipes JSON to bash-guard.sh and checks whether the output matches
# one of three expected outcomes:
#   allow  — JSON output containing "permissionDecision":"allow"
#   block  — No output (silent exit 0 → falls through to permission prompt)
#   ask    — JSON output containing "permissionDecision":"ask"
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$SCRIPT_DIR/bash-guard.sh"

PASS=0
FAIL=0
ERRORS=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
run_guard() {
  local escaped
  escaped=$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')
  printf '{"tool_input":{"command":"%s"}}' "$escaped" | bash "$GUARD" 2>/dev/null
}

expect_allow() {
  local cmd="$1"
  local label="${2:-$cmd}"
  local out
  out=$(run_guard "$cmd")
  if printf '%s' "$out" | grep -q '"permissionDecision":"allow"'; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    ERRORS+=("FAIL [expect allow]: $label  →  got: ${out:-<no output>}")
  fi
}

expect_block() {
  local cmd="$1"
  local label="${2:-$cmd}"
  local out
  out=$(run_guard "$cmd")
  if [[ -z "$out" ]]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    ERRORS+=("FAIL [expect block]: $label  →  got: $out")
  fi
}

expect_ask() {
  local cmd="$1"
  local label="${2:-$cmd}"
  local out
  out=$(run_guard "$cmd")
  if printf '%s' "$out" | grep -q '"permissionDecision":"ask"'; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    ERRORS+=("FAIL [expect ask]:   $label  →  got: ${out:-<no output>}")
  fi
}

section() {
  printf '\n  %-50s ' "$1"
}

# ===========================================================================
printf '=%.0s' {1..70}
printf '\n  bash-guard.sh test suite\n'
printf '=%.0s' {1..70}
printf '\n'

# ===========================================================================
# PHASE 1: Shell construct detection
# ===========================================================================
section "Phase 1: command substitution \$()"
expect_block 'echo $(whoami)' 'echo \$(whoami)'
expect_block 'ls $(pwd)' 'ls \$(pwd)'
expect_block 'cat $(find . -name x)' 'cat \$(find . -name x)'

section "Phase 1: backtick substitution"
expect_block 'echo `whoami`' 'echo \`whoami\`'
expect_block 'ls `pwd`' 'ls \`pwd\`'

section "Phase 1: output redirection >"
expect_block 'echo hello > file.txt'
expect_block 'ls >> output.log'
expect_block 'cat foo > bar'

section "Phase 1: safe redirections allowed"
expect_allow 'ls 2>&1'
expect_allow 'ls 2>/dev/null'
expect_allow 'ls >/dev/null'
expect_allow 'ls >/dev/null 2>&1'
expect_allow 'ls &>/dev/null'

section "Phase 1: quoted operators not triggering split"
expect_allow 'echo "_"' 'echo with quoted string (double)'
expect_allow "echo '_'" 'echo with quoted string (single)'

section "Phase 1: redirection inside quotes (conservative)"
expect_allow "echo 'hello world'" 'echo with single-quoted string'

section "Phase 1: process substitution <(...)"
expect_block 'cat <(ls)' 'cat <(ls) — runs ls'
expect_block 'cat <(rm -rf /)' 'cat <(rm -rf /) — runs rm'
expect_block 'diff <(ls /tmp) <(ls /var)' 'diff <(cmd1) <(cmd2)'
expect_block 'wc -l <(find . -name x)' 'wc -l <(find ...)'
# >() is already caught by the redirect check
expect_block 'echo hello >(cat)' 'echo >(cat) — caught by > check'

printf ' done'

# ===========================================================================
# PHASE 2: Segment splitting and chaining
# ===========================================================================
section "Chaining: safe && safe"
expect_allow 'ls && pwd'
expect_allow 'whoami && date && hostname'

section "Chaining: safe || safe"
expect_allow 'ls || pwd'

section "Chaining: safe ; safe"
expect_allow 'ls; pwd'
expect_allow 'ls ; pwd ; date'

section "Chaining: safe | safe"
expect_allow 'ls | grep foo'
expect_allow 'ps aux | grep nginx | wc -l'
expect_allow 'cat file.txt | head -5 | wc -l'

section "Chaining: safe && dangerous"
expect_block 'ls && rm -rf /'
expect_block 'pwd && curl http://evil.com'

section "Chaining: dangerous | safe"
expect_block 'curl http://x | grep foo'

section "Chaining: safe | dangerous"
expect_block 'ls | xargs rm'

printf ' done'

# ===========================================================================
# Global: --version passthrough
# ===========================================================================
section "--version for any command"
expect_allow 'python --version'
expect_allow 'node --version'
expect_allow 'rustc --version'
expect_allow 'cargo --version'
expect_allow 'ruby --version'
expect_allow 'java --version'
expect_allow 'gcc --version'

printf ' done'

# ===========================================================================
# Global: env var prefix stripping
# ===========================================================================
section "Env var prefix stripping"
expect_allow 'FOO=bar ls'
expect_allow 'FOO=bar BAR=baz ls -la'
expect_allow 'LANG=C sort file.txt'
expect_block 'FOO=bar rm file' 'env prefix + dangerous cmd'

printf ' done'

# ===========================================================================
# Global: absolute path handling
# ===========================================================================
section "Absolute paths"
expect_allow '/usr/bin/ls -la'
expect_allow '/bin/cat file.txt'
expect_allow '/usr/bin/head -n 10 file'
expect_block '/bin/rm -rf /'

printf ' done'

# ===========================================================================
# Global: empty / malformed input
# ===========================================================================
section "Empty / missing command"
# Empty command → exit 0 with no output (bail on empty CMD)
out=$(printf '{"tool_input":{"command":""}}' | bash "$GUARD" 2>/dev/null)
if [[ -z "$out" ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); ERRORS+=("FAIL: empty cmd should produce no output"); fi

out=$(printf '{"tool_input":{}}' | bash "$GUARD" 2>/dev/null)
if [[ -z "$out" ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); ERRORS+=("FAIL: missing cmd key should produce no output"); fi

out=$(printf '{}' | bash "$GUARD" 2>/dev/null)
if [[ -z "$out" ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); ERRORS+=("FAIL: empty JSON should produce no output"); fi

printf ' done'

# ===========================================================================
# Trivially safe commands (SAFE_RE) — spot checks across all categories
# ===========================================================================
section "Safe: text processing"
expect_allow 'cat file.txt'
expect_allow 'head -n 20 file.txt'
expect_allow 'tail -f log.txt'
expect_allow 'wc -l file.txt'
expect_allow 'grep -r pattern dir/'
expect_allow 'rg pattern'
expect_allow 'diff a.txt b.txt'
expect_allow 'uniq -c'
expect_allow 'cut -d: -f1 /etc/passwd'
expect_allow 'tr a-z A-Z'
expect_allow 'rev'
expect_allow 'tac file.txt'
expect_allow 'comm file1 file2'
expect_allow 'paste file1 file2'
expect_allow 'join file1 file2'
expect_allow 'fold -w 80'
expect_allow 'nl file.txt'
expect_allow 'column -t'
expect_allow 'seq 1 10'
expect_allow 'printf "%s\n" hello'
expect_allow 'echo hello world'
expect_allow 'base64 file.txt'

section "Safe: file info"
expect_allow 'ls -la /tmp'
expect_allow 'ls -lahR /var'
expect_allow 'file binary.exe'
expect_allow 'stat file.txt'
expect_allow 'readlink -f link'
expect_allow 'du -sh /tmp'
expect_allow 'df -h'
expect_allow 'basename /path/to/file'
expect_allow 'dirname /path/to/file'
expect_allow 'realpath ./relative'

section "Safe: system info"
expect_allow 'pwd'
expect_allow 'whoami'
expect_allow 'hostname'
expect_allow 'hostname -f'
expect_allow 'uname -a'
expect_allow 'id'
expect_allow 'id -u'
expect_allow 'groups'
expect_allow 'tty'
expect_allow 'date'
expect_allow 'date +%Y-%m-%d'
expect_allow 'uptime'
expect_allow 'free -h'
expect_allow 'nproc'
expect_allow 'lscpu'
expect_allow 'lsblk'
expect_allow 'printenv'
expect_allow 'printenv PATH'
expect_allow 'locale'
expect_allow 'locale -a'

section "Safe: process info"
expect_allow 'ps'
expect_allow 'ps aux'
expect_allow 'ps -ef'
expect_allow 'ps aux --sort=-%mem'
expect_allow 'pgrep -l nginx'
expect_allow 'pgrep -u root -f sshd'
expect_allow 'pidof nginx'
expect_allow 'pstree'
expect_allow 'pstree -p'
expect_allow 'lsof'
expect_allow 'lsof -i :8080'
expect_allow 'lsof -p 1234'
expect_allow 'lsof +D /tmp'

section "Safe: networking"
expect_allow 'ss -tlnp'
expect_allow 'ss -a'
expect_allow 'ss -tunlp'
expect_allow 'netstat -an'
expect_allow 'netstat -tlnp'
expect_allow 'netstat -rn'

section "Safe: user info"
expect_allow 'who'
expect_allow 'who -a'
expect_allow 'w'
expect_allow 'last'
expect_allow 'last -n 10'
expect_allow 'last reboot'

section "Safe: system stats"
expect_allow 'vmstat'
expect_allow 'vmstat 1 5'
expect_allow 'vmstat -s'
expect_allow 'iostat'
expect_allow 'iostat -x 1 3'
expect_allow 'mpstat'
expect_allow 'mpstat -P ALL 1 3'

section "Safe: hardware info"
expect_allow 'lspci'
expect_allow 'lspci -v'
expect_allow 'lspci -vvv'
expect_allow 'lspci -nn'
expect_allow 'lsusb'
expect_allow 'lsusb -t'
expect_allow 'lsusb -v'

section "Safe: filesystem info"
expect_allow 'findmnt'
expect_allow 'findmnt -t ext4'
expect_allow 'findmnt --json'

section "Safe: package query"
expect_allow 'apt-cache search nginx'
expect_allow 'apt-cache show nginx'
expect_allow 'apt-cache policy nginx'
expect_allow 'apt-cache depends nginx'
expect_allow 'apt-cache showpkg nginx'
expect_allow 'dpkg-query -l'
expect_allow 'dpkg-query -W'
expect_allow 'dpkg-query -s nginx'

section "Safe: lookup"
expect_allow 'which ls'
expect_allow 'type ls'
expect_allow 'command -v ls'
expect_allow 'hash ls'
expect_allow 'man ls'
expect_allow 'whatis ls'
expect_allow 'apropos search'
expect_allow 'getent passwd root'
expect_allow 'getent hosts localhost'

section "Safe: crypto/encoding"
expect_allow 'sha256sum file.txt'
expect_allow 'sha1sum file.txt'
expect_allow 'md5sum file.txt'
expect_allow 'cksum file.txt'
expect_allow 'xxd file.bin'
expect_allow 'hexdump -C file.bin'
expect_allow 'od -A x file.bin'
expect_allow 'strings binary.exe'

section "Safe: DNS"
expect_allow 'nslookup example.com'
expect_allow 'dig example.com'
expect_allow 'dig +short example.com A'
expect_allow 'host example.com'

section "Safe: shell builtins"
expect_allow 'cd /tmp'
expect_allow 'true'
expect_allow 'false'
expect_allow 'test -f file.txt'
expect_allow '[ -f file.txt ]' '[ -f file.txt ]'
expect_allow 'tput cols'
expect_allow 'clear'

section "Safe: structured data"
expect_allow 'jq . file.json'
expect_allow 'jq -r .name file.json'

printf ' done'

# ===========================================================================
# hostname handler
# ===========================================================================
section "hostname: safe (display only)"
expect_allow 'hostname'
expect_allow 'hostname -f'
expect_allow 'hostname -i'
expect_allow 'hostname -d'
expect_allow 'hostname -s'
expect_allow 'hostname -A'
expect_allow 'hostname -I'
expect_allow 'hostname -y'
expect_allow 'hostname --fqdn'

section "hostname: dangerous (sets hostname)"
expect_block 'hostname evil.example.com' 'hostname NAME (sets hostname)'
expect_block 'hostname new-host' 'hostname new-host'
expect_block 'hostname -b newname' 'hostname -b (set if empty)'
expect_block 'hostname -F /etc/hostname' 'hostname -F (set from file)'
expect_block 'hostname --file /etc/hostname' 'hostname --file'

printf ' done'

# ===========================================================================
# date handler
# ===========================================================================
section "date: safe (display only)"
expect_allow 'date'
expect_allow 'date -u'
expect_allow 'date +%Y-%m-%d'
expect_allow 'date +%s'
expect_allow 'date -d "2024-01-01"'
expect_allow 'date -d tomorrow'
expect_allow 'date --date="last friday"'
expect_allow 'date -R'
expect_allow 'date -I'
expect_allow 'date --iso-8601'
expect_allow 'date -r /etc/passwd' 'date -r (display file mtime)'

section "date: dangerous (sets clock)"
expect_block 'date -s "2020-01-01"' 'date -s (set clock)'
expect_block 'date --set="2020-01-01"' 'date --set'
expect_block 'date -us "2020-01-01"' 'date -us (combined flags with s)'

printf ' done'

# ===========================================================================
# command handler
# ===========================================================================
section "command: safe (lookup only)"
expect_allow 'command -v ls'
expect_allow 'command -v git'
expect_allow 'command -V ls'

section "command: dangerous (executes command)"
expect_block 'command ls' 'command ls (executes ls)'
expect_block 'command rm -rf /' 'command rm -rf / (executes rm)'
expect_block 'command python script.py' 'command python (executes python)'
expect_block 'command' 'bare command'

printf ' done'

# ===========================================================================
# yq handler
# ===========================================================================
section "yq: safe (stdout only)"
expect_allow 'yq . file.yaml'
expect_allow 'yq .spec deployment.yaml'
expect_allow 'yq -r .name file.yaml'
expect_allow 'yq eval .metadata file.yaml'
expect_allow 'yq -o json file.yaml'
expect_allow 'yq --output-format json file.yaml'

section "yq: dangerous (-i modifies files)"
expect_block 'yq -i .key=val file.yaml' 'yq -i (in-place edit)'
expect_block 'yq --inplace .key=val file.yaml' 'yq --inplace'
expect_block 'yq eval -i .key=val file.yaml' 'yq eval -i'

printf ' done'

# ===========================================================================
# find handler
# ===========================================================================
section "find: safe"
expect_allow 'find . -name "*.txt"'
expect_allow 'find /tmp -type f -size +1M'
expect_allow 'find . -name "*.log" -print0'
expect_allow 'find . -maxdepth 2 -type d'
expect_allow 'find . -newer file.txt'
expect_allow 'find . -empty'

section "find: dangerous"
expect_block 'find . -delete'
expect_block 'find . -name "*.tmp" -delete'
expect_block 'find . -exec rm {} \;' 'find -exec rm'
expect_block 'find . -execdir chmod 777 {} \;' 'find -execdir'
expect_block 'find . -ok rm {} \;' 'find -ok'
expect_block 'find . -fprint output.txt' 'find -fprint'
expect_block 'find . -fprint0 output.txt' 'find -fprint0'
expect_block 'find . -fprintf output.txt "%p"' 'find -fprintf'
expect_block 'find . -fls output.txt' 'find -fls'

printf ' done'

# ===========================================================================
# sort handler
# ===========================================================================
section "sort: safe"
expect_allow 'sort file.txt'
expect_allow 'sort -r file.txt'
expect_allow 'sort -n -k2 file.txt'
expect_allow 'sort -u file.txt'
expect_allow 'sort -t: -k3 -n /etc/passwd'

section "sort: dangerous (-o writes to file)"
expect_block 'sort -o sorted.txt file.txt'
expect_block 'sort --output sorted.txt file.txt'
expect_block 'sort -no sorted.txt file.txt' 'sort -no (combined flags with o)'
expect_block 'sort -rno sorted.txt file.txt' 'sort -rno (combined flags with o)'

printf ' done'

# ===========================================================================
# ip handler
# ===========================================================================
section "ip: safe"
expect_allow 'ip addr'
expect_allow 'ip addr show'
expect_allow 'ip link show'
expect_allow 'ip route'
expect_allow 'ip route show'
expect_allow 'ip route list'
expect_allow 'ip -4 addr'
expect_allow 'ip -6 addr show'
expect_allow 'ip neigh show'
expect_allow 'ip -s link'

section "ip: dangerous"
expect_block 'ip addr add 10.0.0.1/24 dev eth0'
expect_block 'ip route add default via 10.0.0.1'
expect_block 'ip link set eth0 up'
expect_block 'ip addr del 10.0.0.1/24 dev eth0'
expect_block 'ip route delete default'
expect_block 'ip addr flush dev eth0'
expect_block 'ip neigh replace 10.0.0.1 dev eth0'

printf ' done'

# ===========================================================================
# git handler
# ===========================================================================
section "git: always-safe subcommands"
expect_allow 'git diff'
expect_allow 'git diff --staged'
expect_allow 'git diff HEAD~3'
expect_allow 'git log'
expect_allow 'git log --oneline -10'
expect_allow 'git log --graph --all'
expect_allow 'git show HEAD'
expect_allow 'git show abc123:file.txt'
expect_allow 'git status'
expect_allow 'git status -s'
expect_allow 'git rev-parse HEAD'
expect_allow 'git rev-parse --git-dir'
expect_allow 'git describe --tags'
expect_allow 'git shortlog -sn'
expect_allow 'git blame file.txt'
expect_allow 'git ls-files'
expect_allow 'git ls-files --others'
expect_allow 'git ls-tree HEAD'
expect_allow 'git cat-file -p HEAD'
expect_allow 'git rev-list HEAD'
expect_allow 'git name-rev HEAD'
expect_allow 'git for-each-ref refs/heads'
expect_allow 'git show-ref'
expect_allow 'git ls-remote origin'

section "git: --no-pager / -C prefix"
expect_allow 'git --no-pager log'
expect_allow 'git --no-pager diff'
expect_allow 'git -C /path/to/repo status'
expect_allow 'git -C /repo --no-pager log'

section "git stash: safe"
expect_allow 'git stash list'
expect_allow 'git stash show'
expect_allow 'git stash show -p'

section "git stash: dangerous"
expect_block 'git stash'
expect_block 'git stash push'
expect_block 'git stash pop'
expect_block 'git stash apply'
expect_block 'git stash drop'
expect_block 'git stash clear'

section "git branch: safe"
expect_allow 'git branch'
expect_allow 'git branch -r'
expect_allow 'git branch -a'
expect_allow 'git branch -v'
expect_allow 'git branch -vv'
expect_allow 'git branch --list'
expect_allow 'git branch --list "feature/*"'

section "git branch: dangerous"
expect_block 'git branch -d feature'
expect_block 'git branch -D feature'
expect_block 'git branch -m old new'
expect_block 'git branch -M old new'
expect_block 'git branch -c feature copy'
expect_block 'git branch -C feature copy'
expect_block 'git branch -vd feature' 'git branch -vd (d in combined flags)'
expect_block 'git branch -avD feature' 'git branch -avD (D in combined flags)'

section "git tag: safe"
expect_allow 'git tag'
expect_allow 'git tag -l'
expect_allow 'git tag --list'
expect_allow 'git tag -l "v1.*"'
expect_allow 'git tag -n'

section "git tag: dangerous"
expect_block 'git tag -a v1.0'
expect_block 'git tag -s v1.0'
expect_block 'git tag -d v1.0'
expect_block 'git tag -f v1.0'
expect_block 'git tag -ad v1.0' 'git tag -ad (combined flags)'
expect_block 'git tag -sf v1.0' 'git tag -sf (combined flags)'

section "git remote: safe"
expect_allow 'git remote'
expect_allow 'git remote -v'
expect_allow 'git remote show origin'
expect_allow 'git remote get-url origin'

section "git remote: dangerous"
expect_block 'git remote add upstream url'
expect_block 'git remote remove origin'
expect_block 'git remote rm origin'
expect_block 'git remote rename origin upstream'
expect_block 'git remote set-url origin url'
expect_block 'git remote prune origin'

section "git config: safe"
expect_allow 'git config --list'
expect_allow 'git config -l'
expect_allow 'git config --get user.name'
expect_allow 'git config --get-all user.name'
expect_allow 'git config --get-regexp "user.*"'
expect_allow 'git config --show-origin user.name'
expect_allow 'git config --show-scope user.name'

section "git config: dangerous"
expect_block 'git config user.name "Nick"' 'git config set (bare)'
expect_block 'git config --add user.name "Nick"'
expect_block 'git config --unset user.name'
expect_block 'git config --unset-all user.name'
expect_block 'git config --edit'
expect_block 'git config -e'
expect_block 'git config --replace-all user.name "Nick"'
expect_block 'git config --rename-section old new'
expect_block 'git config --remove-section old'

section "git reflog: safe"
# NOTE: bare 'git reflog' is blocked due to pre-existing sed bug — sed pattern
# 's/.*\breflog\s+//' requires trailing whitespace, leaving full string when
# reflog is the last word. Tracked as known limitation.
expect_block 'git reflog' 'git reflog (bare — known limitation)'
expect_allow 'git reflog show'
expect_allow 'git reflog show HEAD'
expect_allow 'git reflog exists refs/stash'

section "git reflog: dangerous"
expect_block 'git reflog expire'
expect_block 'git reflog delete'

section "git: dangerous subcommands"
expect_block 'git push'
expect_block 'git push origin main'
expect_block 'git commit -m "msg"'
expect_block 'git add .'
expect_block 'git add -A'
expect_block 'git reset --hard'
expect_block 'git checkout -- .'
expect_block 'git merge feature'
expect_block 'git rebase main'
expect_block 'git cherry-pick abc123'
expect_block 'git revert HEAD'
expect_block 'git clean -fd'
expect_block 'git rm file.txt'
expect_block 'git mv old.txt new.txt'
expect_block 'git pull'
expect_block 'git fetch' 'git fetch (network operation)'
expect_block 'git clone url'
expect_block 'git init'

printf ' done'

# ===========================================================================
# docker handler
# ===========================================================================
section "docker: safe top-level"
expect_allow 'docker ps'
expect_allow 'docker ps -a'
expect_allow 'docker images'
expect_allow 'docker images -q'
expect_allow 'docker inspect abc123'
expect_allow 'docker logs abc123'
expect_allow 'docker logs -f abc123'
expect_allow 'docker stats'
expect_allow 'docker stats --no-stream'
expect_allow 'docker top abc123'
expect_allow 'docker port abc123'
expect_allow 'docker version'
expect_allow 'docker info'
expect_allow 'docker diff abc123'
expect_allow 'docker --version'
expect_allow 'docker --help'

section "docker: safe nested subcommands"
expect_allow 'docker image ls'
expect_allow 'docker image list'
expect_allow 'docker image inspect abc123'
expect_allow 'docker image history abc123'
expect_allow 'docker container ls'
expect_allow 'docker container inspect abc123'
expect_allow 'docker container logs abc123'
expect_allow 'docker container stats'
expect_allow 'docker container top abc123'
expect_allow 'docker container port abc123'
expect_allow 'docker container diff abc123'
expect_allow 'docker network ls'
expect_allow 'docker network inspect bridge'
expect_allow 'docker volume ls'
expect_allow 'docker volume inspect vol1'
expect_allow 'docker compose ps'
expect_allow 'docker compose logs'
expect_allow 'docker compose ls'
expect_allow 'docker compose images'
expect_allow 'docker compose config'
expect_allow 'docker compose version'

section "docker: dangerous"
expect_block 'docker run ubuntu'
expect_block 'docker exec -it abc123 bash'
expect_block 'docker build .'
expect_block 'docker rm abc123'
expect_block 'docker rmi abc123'
expect_block 'docker push image:tag'
expect_block 'docker pull ubuntu'
expect_block 'docker stop abc123'
expect_block 'docker start abc123'
expect_block 'docker kill abc123'
expect_block 'docker restart abc123'
expect_block 'docker image rm abc123'
expect_block 'docker image prune'
expect_block 'docker container rm abc123'
expect_block 'docker container kill abc123'
expect_block 'docker network create mynet'
expect_block 'docker network rm mynet'
expect_block 'docker volume create myvol'
expect_block 'docker volume rm myvol'
expect_block 'docker compose up'
expect_block 'docker compose down'
expect_block 'docker compose build'
expect_block 'docker compose run web bash'
expect_block 'docker compose exec web bash'

printf ' done'

# ===========================================================================
# systemctl handler
# ===========================================================================
section "systemctl: safe"
expect_allow 'systemctl status nginx'
expect_allow 'systemctl is-active nginx'
expect_allow 'systemctl is-enabled nginx'
expect_allow 'systemctl is-failed nginx'
expect_allow 'systemctl show nginx'
expect_allow 'systemctl list-units'
expect_allow 'systemctl list-unit-files'
expect_allow 'systemctl list-sockets'
expect_allow 'systemctl list-timers'
expect_allow 'systemctl list-dependencies nginx'
expect_allow 'systemctl cat nginx'
expect_allow 'systemctl help'

section "systemctl: dangerous"
expect_block 'systemctl start nginx'
expect_block 'systemctl stop nginx'
expect_block 'systemctl restart nginx'
expect_block 'systemctl reload nginx'
expect_block 'systemctl enable nginx'
expect_block 'systemctl disable nginx'
expect_block 'systemctl mask nginx'
expect_block 'systemctl unmask nginx'
expect_block 'systemctl daemon-reload'
expect_block 'systemctl daemon-reexec'
expect_block 'systemctl edit nginx'
expect_block 'systemctl set-property nginx CPUQuota=50%' 'systemctl set-property'
expect_block 'systemctl kill nginx'
expect_block 'systemctl reset-failed'

printf ' done'

# ===========================================================================
# crontab handler
# ===========================================================================
section "crontab: safe"
expect_allow 'crontab -l'
expect_allow 'crontab -l -u root' 'crontab -l -u root'
expect_allow 'crontab -u root -l' 'crontab -u root -l'

section "crontab: dangerous"
expect_block 'crontab -e'
expect_block 'crontab -r'
expect_block 'crontab -ri'
expect_block 'crontab -i -r'
expect_block 'crontab myfile.txt' 'crontab <file> (install)'
expect_block 'crontab' 'bare crontab'

printf ' done'

# ===========================================================================
# dmesg handler
# ===========================================================================
section "dmesg: safe"
expect_allow 'dmesg'
expect_allow 'dmesg -T'
expect_allow 'dmesg --since yesterday'
expect_allow 'dmesg -l err,warn'
expect_allow 'dmesg -H'
expect_allow 'dmesg --human'
expect_allow 'dmesg -w' 'dmesg -w (follow)'
expect_allow 'dmesg -x'
expect_allow 'dmesg --facility=kern'

section "dmesg: dangerous"
expect_block 'dmesg -C'
expect_block 'dmesg --clear'
expect_block 'dmesg -c'
expect_block 'dmesg --read-clear'
expect_block 'dmesg -D'
expect_block 'dmesg --console-off'
expect_block 'dmesg -E'
expect_block 'dmesg --console-on'
expect_block 'dmesg -n 1'
expect_block 'dmesg --console-level 1'

printf ' done'

# ===========================================================================
# journalctl handler
# ===========================================================================
section "journalctl: safe"
expect_allow 'journalctl'
expect_allow 'journalctl -u nginx'
expect_allow 'journalctl -u nginx -n 50'
expect_allow 'journalctl --since today'
expect_allow 'journalctl --since "2024-01-01" --until "2024-01-02"'
expect_allow 'journalctl -f'
expect_allow 'journalctl -p err'
expect_allow 'journalctl -b'
expect_allow 'journalctl -b -1'
expect_allow 'journalctl -k'
expect_allow 'journalctl --no-pager'
expect_allow 'journalctl -o json'
expect_allow 'journalctl --disk-usage'
expect_allow 'journalctl --list-boots'
expect_allow 'journalctl _PID=1'

section "journalctl: dangerous"
expect_block 'journalctl --rotate'
expect_block 'journalctl --vacuum-size=100M'
expect_block 'journalctl --vacuum-time=2weeks'
expect_block 'journalctl --vacuum-files=5'
expect_block 'journalctl --flush'
expect_block 'journalctl --sync'
expect_block 'journalctl --relinquish-var'
expect_block 'journalctl --smart-relinquish-var'
expect_block 'journalctl --setup-keys'
expect_block 'journalctl --update-catalog'
# Combining safe + dangerous should still block
expect_block 'journalctl -u nginx --rotate' 'journalctl safe flags + --rotate'
expect_block 'journalctl --vacuum-size=100M --vacuum-time=2weeks' 'journalctl multiple vacuum flags'

printf ' done'

# ===========================================================================
# tree handler
# ===========================================================================
section "tree: safe"
expect_allow 'tree'
expect_allow 'tree -L 2'
expect_allow 'tree -a'
expect_allow 'tree -d'
expect_allow 'tree --dirsfirst'
expect_allow 'tree -I "node_modules"'
expect_allow 'tree -h'
expect_allow 'tree -p'
expect_allow 'tree -f'
expect_allow 'tree --charset unicode'
expect_allow 'tree -L 3 -I "__pycache__"'
expect_allow 'tree -J' 'tree -J (JSON output)'

section "tree: dangerous"
expect_block 'tree -o out.txt'
expect_block 'tree --output out.txt'
expect_block 'tree -R' 'tree -R (creates 00Tree.html)'
expect_block 'tree -aR' 'tree -aR (R in combined flags)'
expect_block 'tree -dRa' 'tree -dRa (R in combined flags)'
expect_block 'tree -do' 'tree -do (o in combined flags)'
expect_block 'tree -L 2 -o output.html'

printf ' done'

# ===========================================================================
# tar handler
# ===========================================================================
section "tar: safe (list mode)"
expect_allow 'tar -tf archive.tar.gz'
expect_allow 'tar -tvf archive.tar.gz'
expect_allow 'tar -tzf archive.tar.gz'
expect_allow 'tar --list -f archive.tar'
expect_allow 'tar -t -f archive.tar'
expect_allow 'tar -tvzf archive.tar.gz'

section "tar: dangerous (no list flag)"
expect_block 'tar -xzf archive.tar.gz'
expect_block 'tar -xf archive.tar'
expect_block 'tar -czf out.tar.gz dir/'
expect_block 'tar -cf out.tar file.txt'
expect_block 'tar -rf archive.tar newfile'
expect_block 'tar -uf archive.tar'
expect_block 'tar -Af a.tar b.tar'
expect_block 'tar --create -f out.tar dir/'
expect_block 'tar --extract -f archive.tar'
expect_block 'tar --append -f archive.tar file'
expect_block 'tar --delete -f archive.tar file'

section "tar: dangerous (list + write = conflict)"
expect_block 'tar -txf archive.tar.gz' 'tar -txf (list + extract combined)'
expect_block 'tar -tcf archive.tar.gz' 'tar -tcf (list + create combined)'
expect_block 'tar --list --extract -f a.tar' 'tar --list --extract'
expect_block 'tar --list --delete -f a.tar' 'tar --list --delete'

section "tar: GNU-style no-dash flags"
expect_allow 'tar tf archive.tar' 'tar tf (GNU-style list)'
expect_allow 'tar tvf archive.tar.gz' 'tar tvf (GNU-style verbose list)'
expect_allow 'tar tzf archive.tar.gz' 'tar tzf (GNU-style list gzip)'
expect_block 'tar xf archive.tar' 'tar xf (GNU-style extract)'
expect_block 'tar cf out.tar dir/' 'tar cf (GNU-style create)'
expect_block 'tar txf archive.tar' 'tar txf (GNU-style list+extract conflict)'

section "tar: bare tar (no flags)"
expect_block 'tar' 'bare tar'
expect_block 'tar archive.tar.gz' 'tar with just filename'

printf ' done'

# ===========================================================================
# dpkg handler
# ===========================================================================
section "dpkg: safe query flags"
expect_allow 'dpkg -l'
expect_allow 'dpkg -l nginx'
expect_allow 'dpkg -L nginx'
expect_allow 'dpkg --listfiles nginx'
expect_allow 'dpkg -s nginx'
expect_allow 'dpkg --status nginx'
expect_allow 'dpkg -S /usr/bin/ls'
expect_allow 'dpkg --search /usr/bin/ls'
expect_allow 'dpkg -p nginx'
expect_allow 'dpkg --print-avail nginx'
expect_allow 'dpkg --print-architecture'
expect_allow 'dpkg --print-foreign-architectures'
expect_allow 'dpkg --get-selections'
expect_allow 'dpkg --compare-versions 1.0 gt 0.9'
expect_allow 'dpkg -C'
expect_allow 'dpkg --audit'
expect_allow 'dpkg -V'
expect_allow 'dpkg --verify'

section "dpkg: dangerous"
expect_block 'dpkg -i package.deb'
expect_block 'dpkg --install package.deb'
expect_block 'dpkg -r nginx'
expect_block 'dpkg --remove nginx'
expect_block 'dpkg -P nginx'
expect_block 'dpkg --purge nginx'
expect_block 'dpkg --unpack package.deb'
expect_block 'dpkg --configure nginx'
expect_block 'dpkg --configure -a'
expect_block 'dpkg --triggers-only nginx'
expect_block 'dpkg --set-selections'
expect_block 'dpkg --clear-selections'
expect_block 'dpkg --clear-avail'
expect_block 'dpkg --add-architecture arm64'
expect_block 'dpkg --remove-architecture arm64'
expect_block 'dpkg --update-avail'
expect_block 'dpkg --merge-avail Packages'

section "dpkg: unknown/bare"
expect_block 'dpkg' 'bare dpkg'

printf ' done'

# ===========================================================================
# npm handler
# ===========================================================================
section "npm: safe subcommands"
expect_allow 'npm list'
expect_allow 'npm ls'
expect_allow 'npm ls --depth=0'
expect_allow 'npm ls -g'
expect_allow 'npm view react'
expect_allow 'npm info react'
expect_allow 'npm show react'
expect_allow 'npm outdated'
expect_allow 'npm explain react'
expect_allow 'npm why react'
expect_allow 'npm root'
expect_allow 'npm prefix'
expect_allow 'npm bin'
expect_allow 'npm fund'
expect_allow 'npm help'
expect_allow 'npm help install'
expect_allow 'npm diff'
expect_allow 'npm find-dupes'
expect_allow 'npm --help'
expect_allow 'npm --version'

section "npm: audit"
expect_allow 'npm audit'
expect_allow 'npm audit --json'
expect_block 'npm audit fix'
expect_block 'npm audit fix --force'

section "npm: config"
expect_allow 'npm config list'
expect_allow 'npm config get registry'
expect_allow 'npm config ls'
expect_block 'npm config set registry http://x'
expect_block 'npm config edit'
expect_block 'npm config delete key'

section "npm: dangerous"
expect_block 'npm install'
expect_block 'npm install react'
expect_block 'npm i react'
expect_block 'npm ci'
expect_block 'npm run build'
expect_block 'npm run test'
expect_block 'npm start'
expect_block 'npm test'
expect_block 'npm exec -- cowsay'
expect_block 'npm x cowsay'
expect_block 'npm publish'
expect_block 'npm pack'
expect_block 'npm link'
expect_block 'npm uninstall react'
expect_block 'npm update'
expect_block 'npm cache clean --force'
expect_block 'npm init'
expect_block 'npm create'
expect_block 'npm' 'bare npm'

printf ' done'

# ===========================================================================
# pip / pip3 handler
# ===========================================================================
section "pip: safe subcommands"
expect_allow 'pip list'
expect_allow 'pip list --outdated'
expect_allow 'pip show requests'
expect_allow 'pip show -f requests'
expect_allow 'pip freeze'
expect_allow 'pip check'
expect_allow 'pip help'
expect_allow 'pip help install'
expect_allow 'pip inspect'
expect_allow 'pip index versions requests'
expect_allow 'pip --help'
expect_allow 'pip --version'

section "pip3: safe subcommands"
expect_allow 'pip3 list'
expect_allow 'pip3 show requests'
expect_allow 'pip3 freeze'
expect_allow 'pip3 check'
expect_allow 'pip3 help'
expect_allow 'pip3 inspect'
expect_allow 'pip3 --help'
expect_allow 'pip3 --version'

section "pip: dangerous"
expect_block 'pip install requests'
expect_block 'pip install -r requirements.txt'
expect_block 'pip install --upgrade requests'
expect_block 'pip uninstall requests'
expect_block 'pip download requests'
expect_block 'pip wheel requests'
expect_block 'pip cache purge'
expect_block 'pip config set global.index-url http://x'
expect_block 'pip hash file.whl'
expect_block 'pip' 'bare pip'

section "pip3: dangerous"
expect_block 'pip3 install requests'
expect_block 'pip3 uninstall requests'
expect_block 'pip3' 'bare pip3'

printf ' done'

# ===========================================================================
# gem handler
# ===========================================================================
section "gem: safe subcommands"
expect_allow 'gem list'
expect_allow 'gem list --local'
expect_allow 'gem info rails'
expect_allow 'gem environment'
expect_allow 'gem help'
expect_allow 'gem help install'
expect_allow 'gem specification rails'
expect_allow 'gem contents rails'
expect_allow 'gem search rails'
expect_allow 'gem search --remote rails'
expect_allow 'gem which rake'
expect_allow 'gem outdated'
expect_allow 'gem dependency rails'
expect_allow 'gem --help'
expect_allow 'gem --version'

section "gem: dangerous"
expect_block 'gem install rails'
expect_block 'gem install rails -v 7.0'
expect_block 'gem uninstall rails'
expect_block 'gem update'
expect_block 'gem update rails'
expect_block 'gem push gem-1.0.gem'
expect_block 'gem yank gem -v 1.0'
expect_block 'gem build gemspec'
expect_block 'gem cleanup'
expect_block 'gem fetch rails'
expect_block 'gem exec rake'
expect_block 'gem pristine --all'
expect_block 'gem server'
expect_block 'gem' 'bare gem'

printf ' done'

# ===========================================================================
# kubectl handler
# ===========================================================================
section "kubectl: safe subcommands"
expect_allow 'kubectl get pods'
expect_allow 'kubectl get pods -n kube-system'
expect_allow 'kubectl get pods -A'
expect_allow 'kubectl get pods -o wide'
expect_allow 'kubectl get pods -o json'
expect_allow 'kubectl get svc,deploy'
expect_allow 'kubectl get all'
expect_allow 'kubectl describe pod my-pod'
expect_allow 'kubectl describe node my-node'
expect_allow 'kubectl logs my-pod'
expect_allow 'kubectl logs my-pod -c container'
expect_allow 'kubectl logs -f my-pod'
expect_allow 'kubectl logs --tail=100 my-pod'
expect_allow 'kubectl version'
expect_allow 'kubectl version --client'
expect_allow 'kubectl api-resources'
expect_allow 'kubectl api-versions'
expect_allow 'kubectl explain pod.spec'
expect_allow 'kubectl top pods'
expect_allow 'kubectl top nodes'
expect_allow 'kubectl auth can-i create pods'
expect_allow 'kubectl events'
expect_allow 'kubectl diff -f manifest.yaml'
expect_allow 'kubectl cluster-info'
expect_allow 'kubectl --help'
expect_allow 'kubectl --version'

section "kubectl config: safe"
expect_allow 'kubectl config view'
expect_allow 'kubectl config current-context'
expect_allow 'kubectl config get-contexts'
expect_allow 'kubectl config get-clusters'
expect_allow 'kubectl config get-users'

section "kubectl config: dangerous"
expect_block 'kubectl config set-context my-ctx'
expect_block 'kubectl config set-cluster my-cluster'
expect_block 'kubectl config set-credentials user'
expect_block 'kubectl config use-context my-ctx'
expect_block 'kubectl config delete-context my-ctx'
expect_block 'kubectl config delete-cluster my-cluster'
expect_block 'kubectl config delete-user user'
expect_block 'kubectl config rename-context old new'
expect_block 'kubectl config set key value'

section "kubectl: dangerous subcommands"
expect_block 'kubectl create deployment nginx --image=nginx'
expect_block 'kubectl apply -f manifest.yaml'
expect_block 'kubectl delete pod my-pod'
expect_block 'kubectl delete -f manifest.yaml'
expect_block 'kubectl patch deployment nginx -p "{}"'
expect_block 'kubectl replace -f manifest.yaml'
expect_block 'kubectl edit deployment nginx'
expect_block 'kubectl set image deployment/nginx nginx=nginx:1.2'
expect_block 'kubectl scale deployment nginx --replicas=3'
expect_block 'kubectl exec -it my-pod -- bash'
expect_block 'kubectl cp local.txt my-pod:/tmp/'
expect_block 'kubectl run nginx --image=nginx'
expect_block 'kubectl expose deployment nginx --port=80'
expect_block 'kubectl label pod my-pod app=v2'
expect_block 'kubectl annotate pod my-pod desc="test"'
expect_block 'kubectl cordon node1'
expect_block 'kubectl drain node1'
expect_block 'kubectl taint nodes node1 key=val:NoSchedule'
expect_block 'kubectl port-forward svc/nginx 8080:80'
expect_block 'kubectl proxy'
expect_block 'kubectl attach my-pod'
expect_block 'kubectl debug my-pod --image=busybox'
expect_block 'kubectl rollout restart deployment nginx'
expect_block 'kubectl' 'bare kubectl'

printf ' done'

# ===========================================================================
# gh (GitHub CLI) handler
# ===========================================================================
section "gh: safe read-only"
expect_allow 'gh search repos "topic:cli"'
expect_allow 'gh status'
expect_allow 'gh pr list'
expect_allow 'gh pr view 123'
expect_allow 'gh pr status'
expect_allow 'gh pr checks 123'
expect_allow 'gh pr diff 123'
expect_allow 'gh issue list'
expect_allow 'gh issue view 456'
expect_allow 'gh issue status'
expect_allow 'gh repo list'
expect_allow 'gh repo view'
expect_allow 'gh run list'
expect_allow 'gh run view 789'
expect_allow 'gh release list'
expect_allow 'gh release view v1.0'
expect_allow 'gh gist list'
expect_allow 'gh gist view abc123'
expect_allow 'gh cache list'
expect_allow 'gh workflow list'
expect_allow 'gh workflow view ci.yaml'
expect_allow 'gh ruleset list'
expect_allow 'gh ruleset view 1'
expect_allow 'gh ruleset check'
expect_allow 'gh label list'

section "gh api: safe (GET)"
expect_allow 'gh api repos/owner/repo'
expect_allow 'gh api /user'
expect_allow 'gh api repos/owner/repo/pulls'

section "gh api: write (ask)"
expect_ask 'gh api repos/owner/repo -X POST' 'gh api -X POST'
expect_ask 'gh api repos/owner/repo --method POST' 'gh api --method POST'
expect_ask 'gh api repos/owner/repo -X PUT' 'gh api -X PUT'
expect_ask 'gh api repos/owner/repo -X PATCH' 'gh api -X PATCH'
expect_ask 'gh api repos/owner/repo -X DELETE' 'gh api -X DELETE'
expect_ask 'gh api repos/owner/repo -f name=val' 'gh api -f (field)'
expect_ask 'gh api repos/owner/repo -F name=val' 'gh api -F (field)'
expect_ask 'gh api repos/owner/repo --field name=val' 'gh api --field'
expect_ask 'gh api repos/owner/repo --raw-field name=val' 'gh api --raw-field'
expect_ask 'gh api repos/owner/repo --input body.json' 'gh api --input'

section "gh: write commands (ask)"
expect_ask 'gh pr create'
expect_ask 'gh pr merge 123'
expect_ask 'gh pr close 123'
expect_ask 'gh pr comment 123 -b "text"'
expect_ask 'gh pr edit 123'
expect_ask 'gh issue create'
expect_ask 'gh issue close 456'
expect_ask 'gh issue comment 456'
expect_ask 'gh repo create'
expect_ask 'gh repo delete owner/repo'
expect_ask 'gh release create v1.0'
expect_ask 'gh gist create file.txt'
expect_ask 'gh auth login'

printf ' done'

# ===========================================================================
# Bug fix: flag bundling (\b word boundary bypass)
# ===========================================================================
section "Bug fix: flag bundling (dangerous flag not last)"
# These used to bypass due to \b word boundary bug
expect_block 'hostname -ba'         'hostname -b not last'
expect_block 'hostname -bfa'        'hostname -b mid-bundle'
expect_block 'git branch -dr origin/old' 'git branch -d not last'
expect_block 'git tag -dn v1.0'     'git tag -d not last'
expect_block 'dmesg -Ca'            'dmesg -C not last'
expect_block 'dmesg -nT'            'dmesg -n not last'
expect_block 'sort -on out.txt in.txt' 'sort -o not last'
expect_block 'yq -ia file.yaml'     'yq -i not last'
# Already-working cases should still work
expect_block 'hostname -ab'         'hostname -b last (still works)'
expect_block 'git branch -rd'       'git branch -d last (still works)'
expect_allow 'hostname -f'          'hostname safe flag unaffected'
expect_allow 'sort -n input.txt'    'sort safe flag unaffected'

printf ' done'

# ===========================================================================
# git branch: missing write flags (fix)
# ===========================================================================
section "git branch: missing write flags"
expect_block 'git branch -u origin/main'
expect_block 'git branch --set-upstream-to=origin/main'
expect_block 'git branch --unset-upstream'
expect_block 'git branch -f main HEAD'
expect_block 'git branch --force main HEAD'
expect_block 'git branch --edit-description'
expect_block 'git branch --delete feature'
expect_block 'git branch --move old new'
expect_block 'git branch --copy feature copy'
# Existing safe cases still work
expect_allow 'git branch'
expect_allow 'git branch -a'
expect_allow 'git branch -r -v'
expect_allow 'git branch --list'

printf ' done'

# ===========================================================================
# Security fixes from audit (round 2)
# ===========================================================================
section "git tag: long-form flags + bare creation"
expect_block 'git tag --delete v1.0'    'git tag --delete'
expect_block 'git tag --annotate v1.0'  'git tag --annotate'
expect_block 'git tag --sign v1.0'      'git tag --sign'
expect_block 'git tag --force v1.0'     'git tag --force'
expect_block 'git tag v1.0'             'git tag NAME (creates tag)'
expect_block 'git tag my-release abc123' 'git tag NAME COMMIT'
# Safe cases still work
expect_allow 'git tag'                  'bare git tag (lists)'
expect_allow 'git tag -l'
expect_allow 'git tag --list'
expect_allow 'git tag -n'
expect_allow 'git tag --verify v1.0'
expect_allow 'git tag --contains abc123'
expect_allow 'git tag --merged main'
expect_allow 'git tag --points-at HEAD'
expect_allow 'git tag --sort=-creatordate'

section "xxd: safe vs reverse mode"
expect_allow 'xxd file.bin'             'xxd (hex dump)'
expect_allow 'xxd -l 64 file.bin'       'xxd with length limit'
expect_allow 'xxd -p file.bin'          'xxd plain hex'
expect_block 'xxd -r hex.txt out.bin'   'xxd -r (reverse writes)'
expect_block 'xxd -rp hex.txt out.bin'  'xxd -rp (combined)'

section "go tool: blocked (can compile/write)"
expect_block 'go tool compile -o out.o file.go'
expect_block 'go tool link -o binary file.o'
expect_block 'go tool dist list'        'go tool (all blocked)'

section "cargo doc: blocked (generates files)"
expect_block 'cargo doc'
expect_block 'cargo doc --open'

section "brew home: blocked (opens browser)"
expect_block 'brew home'
expect_block 'brew home node'

section "pnpm audit fix: blocked"
expect_allow 'pnpm audit'
expect_allow 'pnpm audit --json'
expect_block 'pnpm audit fix'           'pnpm audit fix (modifies files)'

section "gh api: -XPOST no space bypass fix"
expect_ask 'gh api /repos -XPOST'       'gh api -XPOST (no space)'
expect_ask 'gh api /repos -XPUT'        'gh api -XPUT (no space)'
expect_ask 'gh api /repos -XDELETE'     'gh api -XDELETE (no space)'

section "Process substitution: >() blocked"
expect_block 'cat file >(tee /tmp/x)'   'output process substitution'

section "Safe: new SAFE_RE commands"
expect_allow 'less file.txt'
expect_allow 'more file.txt'
expect_allow 'sha512sum file.txt'
expect_allow 'b2sum file.txt'
expect_allow 'shuf file.txt'
expect_allow 'numfmt --to=iec 1048576'
expect_allow 'expand file.txt'
expect_allow 'unexpand file.txt'
expect_allow 'tsort graph.txt'
expect_allow 'lsns'

section "Safe: new git subcommands"
expect_allow 'git merge-base main feature'
expect_allow 'git cherry main feature'
expect_allow 'git count-objects -v'
expect_allow 'git diff-tree HEAD'
expect_allow 'git diff-files'
expect_allow 'git diff-index HEAD'
expect_allow 'git verify-commit HEAD'
expect_allow 'git verify-tag v1.0'
expect_allow 'git whatchanged'

section "Security: & background operator splitting"
expect_block 'cat /dev/null & rm -rf /'  '& background operator'
expect_block 'ls & curl http://evil.com'  '& with dangerous command'
expect_allow 'ls && pwd'                   '&& still works'

section "Security: git -c config injection"
expect_block 'git -c core.pager=evil log'  'git -c (code injection)'
expect_block 'git -c diff.external=evil diff'  'git -c diff.external'
# git -C (change dir) is still safe
expect_allow 'git -C /tmp status'          'git -C (safe, changes dir)'

section "Security: dangerous env vars blocked"
expect_block 'PAGER=evil git log'          'PAGER= injection'
expect_block 'MANPAGER=evil git log'       'MANPAGER= injection'
expect_block 'LESSOPEN="| evil" less file' 'LESSOPEN= injection'
expect_block 'LESSCLOSE="| evil" less file' 'LESSCLOSE= injection'
expect_block 'EDITOR=evil git commit'      'EDITOR= injection'
expect_block 'VISUAL=evil git commit'      'VISUAL= injection'
expect_block 'GIT_EDITOR=evil git commit'  'GIT_EDITOR= injection'
expect_block 'GIT_EXTERNAL_DIFF=evil git diff' 'GIT_EXTERNAL_DIFF= injection'
expect_block 'GIT_SSH_COMMAND=evil git push' 'GIT_SSH_COMMAND= injection'
expect_block 'BROWSER=evil brew home'      'BROWSER= injection'
# Non-dangerous env vars still work
expect_allow 'LANG=C sort file.txt'        'LANG= safe'
expect_allow 'LC_ALL=C ls'                 'LC_ALL= safe'

section "Security: git --output writes to file"
expect_block 'git log --output=/tmp/data'  'git log --output'
expect_block 'git diff --output=diff.txt'  'git diff --output'
expect_block 'git show --output=file.txt'  'git show --output'
# Without --output, still safe
expect_allow 'git log --oneline'
expect_allow 'git diff HEAD'

section "Security: bash path spoofing"
expect_block 'bash /tmp/evil/bash-guard.sh'  'bash-guard.sh in wrong dir'
# Guard's own scripts still allowed
expect_allow 'bash bash-guard.sh'
expect_allow 'bash bash-guard-test.sh'

section "Security: gh api equals-form flags"
expect_ask 'gh api /repos --method=DELETE'    'gh api --method=DELETE (equals)'
expect_ask 'gh api /repos -X=POST'            'gh api -X=POST (equals)'

section "Security: missing negative tests"
expect_block 'docker container rm abc123'     'docker container rm'
expect_block 'podman pod rm pod1'             'podman pod rm'
expect_block 'podman pod create'              'podman pod create'
expect_block 'command -p ls'                  'command -p (executes)'

section "Security: LD_PRELOAD / BASH_ENV injection"
expect_block 'LD_PRELOAD=/tmp/evil.so cat /etc/passwd'   'LD_PRELOAD injection'
expect_block 'LD_LIBRARY_PATH=/tmp/evil ls'              'LD_LIBRARY_PATH injection'
expect_block 'BASH_ENV=/tmp/evil.sh ls'                  'BASH_ENV injection'

section "Security: env var prefix bypass (non-first position)"
expect_block 'LANG=C PAGER=/tmp/evil git log'            'PAGER after safe prefix'
expect_block 'LANG=C GIT_SSH_COMMAND=evil git ls-remote' 'GIT_SSH_COMMAND after prefix'
expect_block 'LANG=C LD_PRELOAD=evil.so cat file'        'LD_PRELOAD after prefix'

section "Security: less -o/-O writes to file"
expect_allow 'less file.txt'
expect_allow 'less -N file.txt'
expect_block 'less -o /tmp/log file.txt'      'less -o (log-file)'
expect_block 'less -O /tmp/log file.txt'      'less -O (LOG-FILE)'
expect_block 'less --log-file=/tmp/x file'    'less --log-file'

section "Security: shuf -o writes to file"
expect_allow 'shuf file.txt'
expect_allow 'shuf -n 5 file.txt'
expect_block 'shuf -o /tmp/out file.txt'      'shuf -o (output file)'
expect_block 'shuf --output=/tmp/out file'    'shuf --output'

section "Security: uniq with output file"
expect_allow 'uniq'
expect_allow 'uniq -c'
expect_allow 'uniq file.txt'                  'uniq with input only'
expect_allow 'uniq -c file.txt'               'uniq -c with input'
expect_block 'uniq file.txt output.txt'       'uniq with output file'
expect_block 'uniq -c file.txt output.txt'    'uniq -c with output file'

section "Security: go env -w and go vet -vettool"
expect_allow 'go env'
expect_allow 'go env GOPATH'
expect_block 'go env -w CC=/tmp/evil'         'go env -w (writes config)'
expect_block 'go env -u GOPATH'               'go env -u (unsets config)'
expect_allow 'go vet ./...'
expect_block 'go vet -vettool=/tmp/evil .'    'go vet -vettool (executes)'

section "Security: kubectl auth reconcile"
expect_allow 'kubectl auth can-i create pods'
expect_allow 'kubectl auth whoami'
expect_block 'kubectl auth reconcile -f rbac.yaml' 'kubectl auth reconcile'

printf ' done'

# ===========================================================================
# Safe: binary inspection and kernel info (new SAFE_RE entries)
# ===========================================================================
section "Safe: binary inspection"
expect_allow 'nm a.out'
expect_allow 'nm -C --demangle lib.so'
expect_allow 'objdump -d binary'
expect_allow 'objdump -t -h program'
expect_allow 'readelf -h binary'
expect_allow 'readelf -S -s lib.so'

section "Safe: kernel info"
expect_allow 'lsmod'
expect_allow 'modinfo ext4'
expect_allow 'modinfo -p nvidia'

printf ' done'

# ===========================================================================
# go handler
# ===========================================================================
section "go: safe subcommands"
expect_allow 'go version'
expect_allow 'go env'
expect_allow 'go env GOPATH'
expect_allow 'go doc fmt.Println'
expect_allow 'go list ./...'
expect_allow 'go vet ./...'

section "go: dangerous subcommands"
expect_block 'go run main.go'
expect_block 'go build ./...'
expect_block 'go install ./...'
expect_block 'go get github.com/pkg/errors'
expect_block 'go generate ./...'
expect_block 'go clean'
expect_block 'go mod tidy'
expect_block 'go test ./...'

printf ' done'

# ===========================================================================
# cargo handler
# ===========================================================================
section "cargo: safe subcommands"
expect_allow 'cargo tree'
expect_allow 'cargo metadata'
expect_allow 'cargo search serde'
expect_allow 'cargo version'
expect_allow 'cargo --version'
expect_allow 'cargo verify-project'
expect_allow 'cargo read-manifest'

section "cargo: dangerous subcommands"
expect_block 'cargo build'
expect_block 'cargo run'
expect_block 'cargo install ripgrep'
expect_block 'cargo test'
expect_block 'cargo bench'
expect_block 'cargo publish'
expect_block 'cargo clean'
expect_block 'cargo fix'
expect_block 'cargo add serde'

printf ' done'

# ===========================================================================
# yarn handler
# ===========================================================================
section "yarn: safe subcommands"
expect_allow 'yarn list'
expect_allow 'yarn info lodash'
expect_allow 'yarn why webpack'
expect_allow 'yarn outdated'
expect_allow 'yarn --version'

section "yarn: dangerous subcommands"
expect_block 'yarn install'
expect_block 'yarn add lodash'
expect_block 'yarn remove lodash'
expect_block 'yarn run build'
expect_block 'yarn exec tsc'
expect_block 'yarn publish'
expect_block 'yarn upgrade'
expect_block 'yarn dlx create-react-app'

printf ' done'

# ===========================================================================
# pnpm handler
# ===========================================================================
section "pnpm: safe subcommands"
expect_allow 'pnpm list'
expect_allow 'pnpm ls'
expect_allow 'pnpm why webpack'
expect_allow 'pnpm outdated'
expect_allow 'pnpm audit'
expect_allow 'pnpm --version'

section "pnpm: dangerous subcommands"
expect_block 'pnpm install'
expect_block 'pnpm add lodash'
expect_block 'pnpm remove lodash'
expect_block 'pnpm run build'
expect_block 'pnpm exec tsc'
expect_block 'pnpm publish'
expect_block 'pnpm dlx create-react-app'

printf ' done'

# ===========================================================================
# brew handler
# ===========================================================================
section "brew: safe subcommands"
expect_allow 'brew list'
expect_allow 'brew info git'
expect_allow 'brew search node'
expect_allow 'brew deps git'
expect_allow 'brew uses --installed openssl'
expect_allow 'brew outdated'
expect_allow 'brew doctor'
expect_allow 'brew config'
expect_allow 'brew --version'

section "brew: dangerous subcommands"
expect_block 'brew install git'
expect_block 'brew uninstall git'
expect_block 'brew upgrade'
expect_block 'brew update'
expect_block 'brew tap user/repo'
expect_block 'brew cleanup'
expect_block 'brew link git'
expect_block 'brew services start nginx'

printf ' done'

# ===========================================================================
# apt handler
# ===========================================================================
section "apt: safe subcommands"
expect_allow 'apt list --installed'
expect_allow 'apt show nginx'
expect_allow 'apt search python'
expect_allow 'apt policy nginx'
expect_allow 'apt depends nginx'
expect_allow 'apt rdepends nginx'
expect_allow 'apt --version'

section "apt: dangerous subcommands"
expect_block 'apt install nginx'
expect_block 'apt remove nginx'
expect_block 'apt purge nginx'
expect_block 'apt update'
expect_block 'apt upgrade'
expect_block 'apt autoremove'
expect_block 'apt edit-sources'

printf ' done'

# ===========================================================================
# podman handler
# ===========================================================================
section "podman: safe (mirrors docker)"
expect_allow 'podman ps'
expect_allow 'podman images'
expect_allow 'podman inspect container1'
expect_allow 'podman logs container1'
expect_allow 'podman stats'
expect_allow 'podman version'
expect_allow 'podman image ls'
expect_allow 'podman container ls'
expect_allow 'podman network ls'
expect_allow 'podman volume ls'
expect_allow 'podman pod ls'

section "podman: dangerous"
expect_block 'podman run ubuntu'
expect_block 'podman exec -it container1 bash'
expect_block 'podman build .'
expect_block 'podman rm container1'
expect_block 'podman rmi image1'
expect_block 'podman pull ubuntu'
expect_block 'podman push image1'

printf ' done'

# ===========================================================================
# env handler
# ===========================================================================
section "env: safe (bare only)"
expect_allow 'env'
expect_allow 'env --help'
expect_allow 'env --version'

section "env: dangerous (runs commands)"
expect_block 'env bash'
expect_block 'env -i bash'
expect_block 'env FOO=bar command'
expect_block 'env -u VAR command'

printf ' done'

# ===========================================================================
# Dangerous commands that should always block (unrecognized)
# ===========================================================================
section "Unrecognized / dangerous commands"
expect_block 'rm -rf /'
expect_block 'rm file.txt'
expect_block 'cp a b'
expect_block 'mv a b'
expect_block 'mkdir -p /tmp/dir'
expect_block 'touch file.txt'
expect_block 'chmod 777 file'
expect_block 'chown root:root file'
expect_block 'chgrp users file'
expect_block 'sed -i "s/a/b/" file'
expect_block 'awk "{print}" file'
expect_block 'tee file.txt'
expect_block 'xargs rm'
expect_block 'curl http://evil.com'
expect_block 'wget http://evil.com'
expect_block 'ssh user@host'
expect_block 'scp file user@host:'
expect_block 'rsync -a src/ dst/'
expect_block 'python script.py'
expect_block 'python3 -c "import os; os.system(\"rm -rf /\")"'
expect_block 'node script.js'
expect_block 'bash -c "rm -rf /"'
expect_block 'sh script.sh'
expect_block 'perl -e "system(\"rm -rf /\")"'
expect_block 'ruby -e "system(\"rm -rf /\")"'
expect_block 'make'
expect_block 'make install'
expect_block 'cmake .'
expect_block 'cargo build'
expect_block 'go build'
expect_block 'apt install nginx'
expect_block 'apt-get install nginx'
expect_block 'yum install nginx'
expect_block 'dnf install nginx'
expect_block 'pacman -S nginx'
expect_block 'snap install something'
expect_block 'flatpak install app'
expect_block 'brew install something'
expect_block 'kill 1234'
expect_block 'killall nginx'
expect_block 'pkill nginx'
expect_block 'reboot'
expect_block 'shutdown -h now'
expect_block 'poweroff'
expect_block 'mount /dev/sda1 /mnt'
expect_block 'umount /mnt'
expect_block 'mkfs.ext4 /dev/sda1'
expect_block 'fdisk /dev/sda'
expect_block 'dd if=/dev/zero of=/dev/sda'
expect_block 'iptables -A INPUT -j DROP'
expect_block 'useradd testuser'
expect_block 'userdel testuser'
expect_block 'passwd testuser'
expect_block 'visudo'
expect_block 'cfdisk /dev/sda'
expect_block 'parted /dev/sda'
expect_block 'lvresize /dev/vg/lv'
expect_block 'systemd-run command'
expect_block 'nohup command &'
expect_block 'screen -S session'
expect_block 'tmux new -s session'

printf ' done'

# ===========================================================================
# Mixed / edge-case chains
# ===========================================================================
section "Mixed chains: all safe"
expect_allow 'ls -la | grep "^d" | wc -l'
expect_allow 'ps aux | grep nginx | grep -v grep'
expect_allow 'git status && git log --oneline -5'
expect_allow 'cat /etc/os-release | head -5'
expect_allow 'find . -name "*.py" -type f | wc -l'
expect_allow 'uname -a; hostname; uptime'
expect_allow 'docker ps -a | grep Exited | wc -l'
expect_allow 'kubectl get pods -o json | jq ".items[].metadata.name"'
expect_allow 'npm list --depth=0 | grep react'
expect_allow 'pip list | grep -i django'
expect_allow 'ss -tlnp | grep 8080'
expect_allow 'git log --oneline -5 | head -3'
expect_allow 'lsof -i :80 | grep LISTEN'
expect_allow 'dmesg | tail -20'
expect_allow 'journalctl -u nginx --no-pager | tail -50'

section "Mixed chains: one segment dangerous"
expect_block 'ls && rm file'
expect_block 'git status && git push'
expect_block 'ps aux | kill 1234'
expect_block 'docker ps; docker rm abc123'
expect_block 'kubectl get pods || kubectl delete pod foo'
expect_block 'npm list; npm install react'
expect_block 'pip list && pip install foo'

section "Safe command piped to safe command"
expect_allow 'git diff | cat'
expect_allow 'git log --oneline | head -20'
expect_allow 'find . -name "*.go" | sort'
expect_allow 'dpkg -l | grep nginx'
expect_allow 'gem list | grep rails'

printf ' done'

# ===========================================================================
# Edge cases: tricky patterns
# ===========================================================================
section "Edge: commands with dashes in names"
expect_allow 'apt-cache search foo'
expect_allow 'dpkg-query -l'

section "Edge: absolute paths to handled commands"
# NOTE: absolute paths for handler commands (git, docker, find, etc.) are a
# pre-existing limitation — handler seds like 's/^git\s+//' don't match the
# full path in CLEAN, so the subcommand extraction fails. These fall through
# to the unrecognized exit (block). Only trivially safe commands (SAFE_RE)
# work with absolute paths because BASE is extracted via basename before the
# regex check.
expect_block '/usr/bin/git status' '/usr/bin/git status (known limitation)'
expect_block '/usr/bin/docker ps' '/usr/bin/docker ps (known limitation)'
# find works with absolute paths because its handler uses grep on CLEAN
# (checks for dangerous flags) rather than sed-based subcommand extraction
expect_allow '/usr/bin/find . -name "*.txt"'
expect_block '/usr/bin/find . -delete'
expect_block '/usr/bin/git push'

section "Edge: env vars before handled commands"
expect_block 'GIT_PAGER=cat git log'  'GIT_PAGER blocked (code injection risk)'
expect_allow 'DOCKER_HOST=tcp://x docker ps'
expect_block 'GIT_PAGER=cat git push'
expect_block 'DOCKER_HOST=tcp://x docker run ubuntu'

section "Edge: single-char command 'w'"
expect_allow 'w'
expect_allow 'w -h'

section "Edge: repeated flags"
expect_allow 'ls -l -a -h'
expect_allow 'ps -e -f'
expect_allow 'git log --oneline --graph --all --decorate'

section "Edge: arguments that look like dangerous flag names"
# These test that flag-detection regexes don't match argument VALUES
expect_allow 'find . -name delete_me' 'find -name delete_me (not -delete)'
expect_allow 'find . -path "*/exec/*"' 'find -path with exec in value'
expect_allow 'grep -r delete file.txt' 'grep with delete as pattern'
expect_allow 'git log --grep=delete' 'git log searching for delete'
expect_allow 'dpkg -s curl' 'dpkg -s with package containing r'
expect_allow 'dpkg -l libpurge-dev' 'dpkg -l package name with purge'

section "Edge: safe commands in subshell-like contexts"
# All of these should be blocked because they contain shell constructs
expect_block '( ls )' 'subshell grouping'
expect_block '{ ls; }' 'brace grouping with semicolon'
expect_block 'eval ls' 'eval prefix'
expect_block 'source script.sh' 'source command'
expect_block '. script.sh' 'dot source'
expect_block 'exec ls' 'exec prefix'

section "Edge: sudo/su/doas prefixes"
expect_block 'sudo ls'
expect_block 'sudo rm -rf /'
expect_block 'su -c ls'
expect_block 'doas ls'

section "Edge: process/job control"
expect_block 'kill 1234'
expect_block 'killall nginx'
expect_block 'pkill nginx'
expect_block 'nohup ls' 'nohup prefix'
expect_block 'nice ls' 'nice prefix'
expect_block 'timeout 5 ls' 'timeout prefix'
expect_block 'strace ls' 'strace prefix'
expect_block 'ltrace ls' 'ltrace prefix'

section "Edge: writing tools"
expect_block 'tee file.txt'
expect_block 'install -m 755 file dest'
expect_block 'patch -p1 < diff.patch' 'patch (modifies files)'
expect_block 'truncate -s 0 file'
expect_block 'shred file'
expect_block 'ln -s target link'
expect_block 'mktemp'
expect_block 'mknod /dev/test c 1 1'
expect_block 'split file prefix'

section "Edge: network/download tools"
expect_block 'curl http://example.com'
expect_block 'wget http://example.com'
expect_block 'nc -l 8080' 'netcat listen'
expect_block 'socat TCP:host:port -' 'socat'
expect_block 'telnet host 80' 'telnet'
expect_block 'ftp host' 'ftp'
expect_block 'sftp user@host' 'sftp'

section "Edge: container/orchestration tools"
expect_block 'podman run ubuntu' 'podman (not docker)'
expect_block 'crictl ps' 'crictl (not handled)'
expect_block 'helm install chart' 'helm install'
expect_block 'terraform apply' 'terraform apply'
expect_block 'ansible-playbook play.yml' 'ansible'

section "Edge: interpreters and REPLs"
expect_block 'python -c "print(1)"'
expect_block 'python3 -c "import os"'
expect_block 'ruby -e "puts 1"'
expect_block 'perl -e "print 1"'
expect_block 'node -e "console.log(1)"'
expect_block 'lua -e "print(1)"'
expect_block 'php -r "echo 1;"'
expect_block 'irb' 'irb (Ruby REPL)'

section "Edge: compilers and build tools"
expect_block 'gcc -o out file.c'
expect_block 'g++ -o out file.cpp'
expect_block 'javac File.java'
expect_block 'rustc file.rs'
expect_block 'go run main.go'
expect_block 'cargo run'
expect_block 'gradle build'
expect_block 'mvn package'
expect_block 'ant build'
expect_block 'cmake --build .'

section "Edge: dmesg combined flags"
# -n is dangerous (set console level), even combined with safe flags
expect_block 'dmesg -Tn' 'dmesg -Tn (n is console-level)'
expect_block 'dmesg -Tc' 'dmesg -Tc (c is read-clear)'
expect_allow 'dmesg -TH' 'dmesg -TH (both safe)'
expect_allow 'dmesg -Tx' 'dmesg -Tx (both safe)'
expect_allow 'dmesg -THx' 'dmesg -THx (all safe)'

section "Edge: dpkg with paths containing flag-like chars"
# Ensure /usr/... paths don't trigger false positives for -i/-r/-P
expect_allow 'dpkg -S /usr/bin/install' 'dpkg -S with install in path'
expect_allow 'dpkg -L python3' 'dpkg -L with p in package name'
expect_allow 'dpkg --search /usr/sbin/repair' 'dpkg --search with repair in path'

section "Edge: npm edge cases"
expect_block 'npm i' 'npm i (alias for install)'
expect_block 'npm add react' 'npm add (alias for install)'
expect_block 'npm remove react' 'npm remove'
expect_block 'npm unlink pkg' 'npm unlink'
expect_block 'npm dedupe' 'npm dedupe (modifies node_modules)'
expect_block 'npm prune' 'npm prune (removes packages)'
expect_block 'npm rebuild' 'npm rebuild'
expect_block 'npm pkg set name=x' 'npm pkg set'
expect_allow 'npm view react versions' 'npm view with extra args'
expect_allow 'npm outdated --long' 'npm outdated with flags'

section "Edge: kubectl namespace and context flags"
# Flags like -n, --namespace, --context should not prevent safe subcommands
expect_allow 'kubectl get pods -n production'
expect_allow 'kubectl get pods --namespace=kube-system'
expect_allow 'kubectl get pods --context=staging'
expect_allow 'kubectl describe svc nginx -n default'
expect_allow 'kubectl logs -n monitoring prometheus-0'

printf ' done'

section "bash/sh: guard scripts allowed"
expect_allow 'bash bash-guard.sh'
expect_allow 'bash bash-guard-test.sh'
# Pipeline with guard script (the case that triggered this fix)
expect_allow 'echo test | bash bash-guard.sh'

section "bash/sh: everything else blocked"
expect_block 'bash' 'bare bash'
expect_block 'bash -c "rm -rf /"'
expect_block 'bash script.sh'
expect_block 'bash /tmp/evil.sh'
expect_block 'sh -c "whoami"'
expect_block 'sh script.sh'

printf ' done'

# ===========================================================================
# Print results
# ===========================================================================
printf '\n\n'
printf '=%.0s' {1..70}
printf '\n'

TOTAL=$((PASS + FAIL))
if [[ ${#ERRORS[@]} -gt 0 ]]; then
  printf '\n  FAILURES:\n\n'
  for err in "${ERRORS[@]}"; do
    printf '    %s\n' "$err"
  done
  printf '\n'
fi

printf '  Results: %d passed, %d failed, %d total\n' "$PASS" "$FAIL" "$TOTAL"
printf '=%.0s' {1..70}
printf '\n'

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
exit 0

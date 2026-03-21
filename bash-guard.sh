#!/usr/bin/env bash
# =============================================================================
# bash-guard.sh — Claude Code PreToolUse hook for Bash commands
# =============================================================================
#
# PURPOSE
#   Auto-allow verified read-only Bash commands. Everything else falls through
#   to the normal Claude Code permission system (user gets prompted).
#
# HOW IT WORKS
#   This script runs on every Bash tool invocation (via the PreToolUse hook).
#   Claude Code pipes JSON to stdin with the shape:
#     { "tool_input": { "command": "..." } }
#
#   The script outputs one of:
#     1. JSON with permissionDecision "allow"  → command runs without prompting
#     2. JSON with permissionDecision "ask"    → user sees prompt with reason
#     3. Nothing (silent exit 0)               → falls through to normal rules
#
# SECURITY MODEL
#   - Fail-safe: unknown commands produce NO output → user gets prompted
#   - Over-conservative: may prompt for safe commands, but NEVER auto-allows
#     a dangerous one
#   - Chaining-aware: splits on &&, ||, ;, |, & and checks EVERY segment
#   - Shell-construct-aware: bails on $(…), backticks, and output redirections
#
# OUT OF SCOPE
#   Environment variable injection (e.g., LD_PRELOAD=evil.so cat file,
#   PAGER=evil git log) is NOT handled here. These are niche attack vectors
#   that would require maintaining an ever-growing blocklist of dangerous
#   env var names. The guard focuses on command and flag classification.
#
# PHASES
#   Phase 1: Reject commands with dangerous shell constructs (redirects, subshells)
#   Phase 2: Split into segments, classify each by base command
#   Phase 3: Emit decision (allow if ALL segments safe, ask for gh writes)
#
# ADDING NEW COMMANDS
#   To allow a new read-only command, add it to the SAFE_RE regex (Phase 2).
#   For commands that are only safe with certain flags/subcommands, add a new
#   conditional block following the pattern of find/sort/git/docker/etc.
#   Always verify via man pages that no flags can write files, execute commands,
#   or modify system state.
#
# =============================================================================
set -euo pipefail

# Resolve the directory containing this script (for bash/sh allowlist)
GUARD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Read the JSON tool input from stdin
INPUT=$(cat)
CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')
[[ -z "$CMD" ]] && exit 0

# =============================================================================
# PHASE 1: Bail on dangerous shell constructs
# =============================================================================
# Before analyzing individual commands, check for shell features that could
# embed arbitrary operations. If found, exit silently (fall through to normal
# permission prompting). This is conservative: `echo "hello > world"` will
# trigger a prompt even though it's safe, because we can't perfectly parse
# shell quoting in bash.

# Strip quoted strings to reduce false positives on operators inside quotes.
# "hello && world" → "_" so the && check doesn't trigger.
# Imperfect (doesn't handle escaped quotes/heredocs), but imperfection is
# always over-conservative: may prompt unnecessarily, never auto-allows danger.
STRIPPED=$(printf '%s' "$CMD" | sed -E 's/"[^"]*"/"_"/g' | sed -E "s/'[^']*'/'_'/g")

# Bail on command substitution: $(...) or backticks can embed any command
if printf '%s' "$STRIPPED" | grep -qE '\$\(|`'; then
  exit 0
fi

# Bail on process substitution: <(...) and >(...) execute commands inside
if printf '%s' "$STRIPPED" | grep -qE '[<>]\('; then
  exit 0
fi

# Bail on output redirection: > or >> write to files
# First remove known-safe redirection patterns that don't write real files:
#   2>&1         — merges stderr into stdout
#   >/dev/null   — discards output
#   2>/dev/null  — discards stderr
#   &>/dev/null  — discards both
REDIR_CHECK=$(printf '%s' "$STRIPPED" | sed -E \
  -e 's/2>&1//g' \
  -e 's/&>\/dev\/null//g' \
  -e 's/[0-9]*>\/dev\/null//g')
if printf '%s' "$REDIR_CHECK" | grep -qE '>{1,2}'; then
  exit 0
fi

# =============================================================================
# PHASE 2: Split into segments and classify each
# =============================================================================
# Split the command on shell operators (&&, ||, ;, |, &) into individual segments.
# Each segment is classified independently. ALL must be read-only for the
# overall command to be auto-allowed.
#
# Note: naive splitting may incorrectly split quoted strings containing
# operators (though Phase 1 stripping mitigates most cases). This is always
# over-conservative: produces unrecognized segments → falls through to prompt.

# Remove safe &-containing redirections before splitting so they don't
# trigger the & separator. E.g., '2>&1', '&>/dev/null' are not background ops.
SPLIT_READY=$(printf '%s' "$STRIPPED" | sed -E \
  -e 's/2>&1//g' \
  -e 's/&>\/dev\/null//g' \
  -e 's/[0-9]*>\/dev\/null//g')

IFS=$'\n' read -r -d '' -a SEGMENTS < <(
  printf '%s' "$SPLIT_READY" | sed -E 's/(\|\||&&|[;&|])/\n/g' && printf '\0'
) || true

ALL_ALLOW=true       # Set to false if any segment triggers "ask"
GH_ASK_REASON=""     # Reason string for gh write commands

# ---------------------------------------------------------------------------
# Trivially safe commands: every flag for these is read-only (verified via
# man pages). None can write files, delete files, or execute other commands.
#
# Categories:
#   Text processing: cat head tail wc grep rg diff cut tr rev tac comm
#                    paste join fold nl column seq printf echo base64
#                    more numfmt expand unexpand tsort
#   File info:       ls file stat readlink du df basename dirname realpath
#   System info:     pwd whoami uname id groups tty uptime
#                    free nproc lscpu lsblk printenv locale
#   Process info:    ps pgrep pidof pstree lsof
#   Networking:      ss netstat
#   User info:       who w last
#   System stats:    vmstat iostat mpstat
#   Hardware info:   lspci lsusb
#   Filesystem info: findmnt lsns
#   Package query:   apt-cache dpkg-query
#   Lookup:          which type hash man whatis apropos getent
#   Crypto/encoding: sha256sum sha512sum sha1sum md5sum b2sum cksum
#                    hexdump od strings
#   DNS:             nslookup dig host
#   Shell builtins:  cd true false test [ tput clear
#   Structured data: jq
#   Binary inspection: nm objdump readelf
#   Kernel info:       lsmod modinfo
#
# Commands with flag-dependent safety that have their own handlers below:
#   hostname, date, command, yq, xxd, less, shuf, uniq, rg
# ---------------------------------------------------------------------------
SAFE_RE='^(ls|cat|head|tail|wc|file|stat|which|pwd|echo|printenv|realpath|basename|dirname|diff|cut|tr|cd|grep|true|false|test|\[|jq|whoami|uname|id|groups|tty|getent|sha256sum|sha512sum|sha1sum|md5sum|b2sum|cksum|hexdump|od|strings|readlink|du|df|free|uptime|nproc|lscpu|lsblk|column|seq|printf|type|hash|man|whatis|apropos|tput|clear|rev|tac|comm|paste|join|fold|nl|base64|nslookup|dig|host|ps|pgrep|pidof|pstree|lsof|ss|netstat|who|w|last|vmstat|iostat|mpstat|lspci|lsusb|locale|apt-cache|dpkg-query|findmnt|nm|objdump|readelf|lsmod|modinfo|more|numfmt|expand|unexpand|tsort|lsns)$'

for SEG in "${SEGMENTS[@]}"; do
  SEG=$(printf '%s' "$SEG" | sed 's/^[[:space:]]*//')
  [[ -z "$SEG" ]] && continue

  # Strip env var prefixes: FOO=bar BAR=baz command ... → command ...
  CLEAN=$(printf '%s' "$SEG" | sed -E 's/^([A-Za-z_][A-Za-z0-9_]*=[^ ]* +)*//')
  BASE=$(printf '%s' "$CLEAN" | awk '{print $1}')
  # Handle absolute/relative paths (e.g., /usr/bin/ls → ls)
  BASE=$(basename "$BASE" 2>/dev/null || printf '%s' "$BASE")

  # --- Any command with sole argument --version is read-only ---
  if printf '%s' "$CLEAN" | grep -qxE '[^ ]+\s+--version'; then
    continue
  fi

  # --- Trivially safe commands (no flag checks needed) ---
  if printf '%s' "$BASE" | grep -qxE "$SAFE_RE"; then
    continue
  fi

  # --- hostname: safe for display, dangerous when setting hostname ---
  # Safe: bare 'hostname', or with display flags (-f, -i, -d, -s, -A, -I, etc.)
  # Dangerous: 'hostname NAME' (sets hostname), -b (set if empty),
  #            -F/--file (set from file)
  if [[ "$BASE" == "hostname" ]]; then
    # Block -b (set if empty) and -F/--file (set from file)
    if printf '%s' "$CLEAN" | grep -qE '(\s)-[^-[:space:]]*[bF]|(\s)--file\b'; then exit 0; fi
    # Block if any non-flag word exists after 'hostname' (would set the hostname)
    HOSTNAME_ARGS=$(printf '%s' "$CLEAN" | sed -E 's/^hostname\s*//')
    if [[ -n "$HOSTNAME_ARGS" ]] && printf '%s' "$HOSTNAME_ARGS" | grep -qE '(^|\s)[^-]'; then
      exit 0
    fi
    continue
  fi

  # --- date: safe for display, dangerous when setting clock ---
  # Safe: all display/format flags (date, date -u, date +FORMAT, date -d STRING)
  # Dangerous: -s/--set (sets system clock)
  if [[ "$BASE" == "date" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '(\s)-[^-[:space:]]*s|(\s)--set\b'; then exit 0; fi
    continue
  fi

  # --- command: only allow lookup flags (-v/-V) ---
  # Safe: 'command -v name' / 'command -V name' (look up command location)
  # Dangerous: 'command name' (EXECUTES that command)
  if [[ "$BASE" == "command" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '(\s)-[vV]\b'; then continue; fi
    exit 0
  fi

  # --- yq: safe UNLESS -i/--inplace (modifies files in place) ---
  if [[ "$BASE" == "yq" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '(\s|^)(-[^-[:space:]]*i|--inplace\b)'; then exit 0; fi
    continue
  fi

  # --- xxd: safe UNLESS -r (reverse mode can write files) ---
  if [[ "$BASE" == "xxd" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '(\s|^)-[^-[:space:]]*r'; then exit 0; fi
    continue
  fi

  # --- rg: safe UNLESS --pre (executes arbitrary preprocessor command) ---
  if [[ "$BASE" == "rg" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '\s--pre\b'; then exit 0; fi
    continue
  fi

  # --- less: safe UNLESS -o/-O (log-file writes output to file) ---
  if [[ "$BASE" == "less" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '(\s|^)-[^-[:space:]]*[oO]|(\s|^)--(log-file|LOG-FILE)\b'; then exit 0; fi
    continue
  fi

  # --- shuf: safe UNLESS -o/--output (writes to file) ---
  if [[ "$BASE" == "shuf" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '(\s|^)-[^-[:space:]]*o|(\s|^)--output\b'; then exit 0; fi
    continue
  fi

  # --- uniq: safe UNLESS output file positional arg is given ---
  # Usage: uniq [OPTIONS] [INPUT [OUTPUT]]. Two positional args means the
  # second is an output file. We allow only zero or one non-flag arg.
  if [[ "$BASE" == "uniq" ]]; then
    UNIQ_ARGS=$(printf '%s' "$CLEAN" | sed -E 's/^uniq\s*//' | sed -E 's/-[^ ]+ *//g' | sed 's/^ *//')
    UNIQ_ARGC=$(printf '%s' "$UNIQ_ARGS" | awk '{print NF}')
    if [[ "$UNIQ_ARGC" -gt 1 ]]; then exit 0; fi
    continue
  fi

  # --- find: safe UNLESS dangerous action flags are present ---
  # Dangerous: -delete (removes files), -exec/-execdir/-ok/-okdir (runs commands),
  #            -fls/-fprint/-fprint0/-fprintf (writes results to files)
  # Safe: -name, -type, -size, -print, -print0, -printf, etc. (filtering/stdout)
  if [[ "$BASE" == "find" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '\s-(delete|exec|execdir|ok|okdir|fls|fprint0?|fprintf)\b'; then
      exit 0
    fi
    continue
  fi

  # --- sort: safe UNLESS -o/--output or --compress-program ---
  # Matches -o, -ro, -nro (combined short flags containing 'o'), --output
  # --compress-program executes an arbitrary command
  if [[ "$BASE" == "sort" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '(\s|^)(-[a-zA-Z]*o|--output\b|--compress-program\b)'; then
      exit 0
    fi
    continue
  fi

  # --- ip: safe UNLESS write action keywords are present ---
  # Safe actions: show, list (and bare 'ip addr' defaults to show)
  # Dangerous actions: add, del/delete, change, replace, flush, save, restore,
  #                    set (e.g., 'ip link set'), append
  # Uses word-boundary matching so 'address' doesn't match 'add'
  if [[ "$BASE" == "ip" ]]; then
    # -batch/-b reads commands from file (can contain any ip subcommand)
    if printf '%s' "$CLEAN" | grep -qE '(\s|^)(-b\b|-batch\b|--batch\b)'; then exit 0; fi
    if printf '%s' "$CLEAN" | grep -qE '\b(add|del|delete|change|replace|flush|save|restore|set|append|exec)\b'; then
      exit 0
    fi
    continue
  fi

  # --- git: subcommand-dependent classification ---
  if [[ "$BASE" == "git" ]]; then
    # Block git -c (config override) — can set keys like core.pager,
    # core.fsmonitor, diff.external that execute arbitrary commands
    if printf '%s' "$CLEAN" | grep -qE '(\s)-c(\s|[^-\s])'; then exit 0; fi

    # Extract git subcommand, skipping common flags that precede it
    # e.g., 'git --no-pager log' → 'log', 'git -C /path diff' → 'diff'
    GIT_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^git\s+//' | sed -E 's/^(--no-pager\s+|-C\s+[^ ]+\s+)*//' | awk '{print $1}')

    # Block --output flag (writes to file) — used by diff, log, show
    if printf '%s' "$CLEAN" | grep -qE '\s--output\b'; then exit 0; fi

    # Always-safe git subcommands (purely read-only, no flags can write)
    case "$GIT_SUB" in
      diff|log|show|status|rev-parse|describe|shortlog|blame|ls-files|ls-tree|cat-file|rev-list|name-rev|for-each-ref|show-ref|ls-remote|merge-base|cherry|count-objects|diff-tree|diff-files|diff-index|verify-commit|verify-tag|whatchanged)
        continue ;;
    esac

    # git stash: only 'list' (shows stashes) and 'show' (shows stash diff) are safe
    # Dangerous: push/pop/apply/drop/clear/create/store all modify state
    if [[ "$GIT_SUB" == "stash" ]]; then
      STASH_ACT=$(printf '%s' "$CLEAN" | sed -E 's/.*\bstash\s+//' | awk '{print $1}')
      case "$STASH_ACT" in list|show) continue ;; *) exit 0 ;; esac
    fi

    # git branch: safe for listing, dangerous with modification flags
    # -d/-D (delete), -m/-M (move/rename), -c/-C (copy), -u (set upstream),
    # -f (force) are write operations
    # Bare 'git branch' or with -r/-a/-v/--list just lists branches
    if [[ "$GIT_SUB" == "branch" ]]; then
      if printf '%s' "$CLEAN" | grep -qE '\s-[^-[:space:]]*[dDmMcCuf]'; then exit 0; fi
      if printf '%s' "$CLEAN" | grep -qE '\s--(delete|move|copy|set-upstream-to|unset-upstream|edit-description|force)\b'; then exit 0; fi
      continue
    fi

    # git tag: safe for listing/verifying, dangerous for creation/deletion
    # -a (annotate), -s (sign), -d (delete), -f (force) are write operations
    # 'git tag NAME' (no flags) creates a lightweight tag — also dangerous
    # Safe only with: bare 'git tag', -l/--list, -n, --verify, --contains,
    # --merged, --no-merged, --points-at, --sort
    if [[ "$GIT_SUB" == "tag" ]]; then
      if printf '%s' "$CLEAN" | grep -qE '\s-[^-[:space:]]*[asdf]'; then exit 0; fi
      if printf '%s' "$CLEAN" | grep -qE '\s--(delete|annotate|sign|force)\b'; then exit 0; fi
      if printf '%s' "$CLEAN" | grep -qE '\s(-[^-[:space:]]*[ln]|--list|--verify|--contains|--merged|--no-merged|--points-at|--sort)\b'; then continue; fi
      # Bare 'git tag' lists all tags
      TAG_REST=$(printf '%s' "$CLEAN" | sed -E 's/.*\btag(\s|$)//')
      if [[ -z "$TAG_REST" || "$TAG_REST" =~ ^[[:space:]]*$ ]]; then continue; fi
      # Anything else could be tag creation → block
      exit 0
    fi

    # git remote: safe for querying, dangerous for structural changes
    # Safe: bare 'git remote', -v, show, get-url (all just query info)
    # Dangerous: add, remove/rm, rename, set-url, set-head, set-branches, prune, update
    if [[ "$GIT_SUB" == "remote" ]]; then
      if printf '%s' "$CLEAN" | grep -qE '\b(add|remove|rm|rename|set-url|set-head|set-branches|prune|update)\b'; then
        exit 0
      fi
      continue
    fi

    # git config: safe with explicit read flags, dangerous otherwise
    # Read flags: --list, -l, --get, --get-all, --get-regexp, --show-origin, etc.
    # Write flags: --add, --unset, --edit, --replace-all, --rename-section, etc.
    # Bare 'git config key value' (no flags) is a WRITE (sets config value),
    # so we require explicit read flags to be present.
    if [[ "$GIT_SUB" == "config" ]]; then
      # Block if any write flag is present
      if printf '%s' "$CLEAN" | grep -qE '\s(--add|--unset|--unset-all|--edit|-e|--replace-all|--rename-section|--remove-section)\b'; then
        exit 0
      fi
      # Allow if an explicit read flag is present
      if printf '%s' "$CLEAN" | grep -qE '\s(--list|-l|--get\b|--get-all|--get-regexp|--get-urlmatch|--show-origin|--show-scope)'; then
        continue
      fi
      exit 0  # no read flag → could be 'git config key value' (write)
    fi

    # git reflog: bare/show/exists are safe, expire/delete are dangerous
    if [[ "$GIT_SUB" == "reflog" ]]; then
      REFLOG_ACT=$(printf '%s' "$CLEAN" | sed -E 's/.*\breflog\s+//' | awk '{print $1}')
      case "$REFLOG_ACT" in ""|show|exists) continue ;; *) exit 0 ;; esac
    fi

    # Unrecognized git subcommand (push, commit, add, reset, checkout, merge,
    # rebase, cherry-pick, revert, clean, rm, mv, etc.) → fall through
    exit 0
  fi

  # --- docker: subcommand-dependent classification ---
  if [[ "$BASE" == "docker" ]]; then
    DOCKER_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^docker\s+//' | awk '{print $1}')

    # Top-level read-only subcommands (all flags are display/filtering only)
    case "$DOCKER_SUB" in
      ps|images|inspect|logs|stats|top|port|version|info|diff|--version|--help)
        continue ;;
    esac

    # Nested subcommands: docker <object> <action>
    DOCKER_ACT=$(printf '%s' "$CLEAN" | sed -E 's/^docker\s+//' | awk '{print $2}')
    case "$DOCKER_SUB" in
      image)     [[ "$DOCKER_ACT" =~ ^(ls|list|inspect|history)$ ]] && continue ;;
      container) [[ "$DOCKER_ACT" =~ ^(ls|list|inspect|logs|stats|top|port|diff)$ ]] && continue ;;
      network)   [[ "$DOCKER_ACT" =~ ^(ls|list|inspect)$ ]] && continue ;;
      volume)    [[ "$DOCKER_ACT" =~ ^(ls|list|inspect)$ ]] && continue ;;
      # compose: ps/logs/ls/images are queries, config shows resolved config,
      # version shows version info. All read-only.
      compose)   [[ "$DOCKER_ACT" =~ ^(ps|logs|ls|images|config|version)$ ]] && continue ;;
    esac
    # Unrecognized (run, exec, build, rm, rmi, push, pull, stop, start, etc.)
    exit 0
  fi

  # --- systemctl: read-only query subcommands only ---
  # Safe: status, is-*, show, list-*, cat, help (all just query unit state)
  # Dangerous: start, stop, restart, enable, disable, mask, daemon-reload, etc.
  if [[ "$BASE" == "systemctl" ]]; then
    SYSD_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^systemctl\s+//' | awk '{print $1}')
    case "$SYSD_SUB" in
      status|is-active|is-enabled|is-failed|show|list-units|list-unit-files|list-sockets|list-timers|list-dependencies|cat|help)
        continue ;;
    esac
    exit 0
  fi

  # --- crontab: allow only -l (list) ---
  # Safe: -l (list crontab), optionally with -u user
  # Dangerous: -e (edit), -r (remove), -i (interactive), crontab <file> (install)
  if [[ "$BASE" == "crontab" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '\s-[^[:space:]]*[eri]'; then exit 0; fi
    if printf '%s' "$CLEAN" | grep -qE '\s-[^[:space:]]*l'; then continue; fi
    exit 0  # bare 'crontab' or 'crontab file' → dangerous
  fi

  # --- dmesg: block clear/write flags ---
  # Dangerous: -C/--clear, -c/--read-clear, -D/--console-off, -E/--console-on,
  #            -n/--console-level
  # Safe: everything else (display/filter flags)
  if [[ "$BASE" == "dmesg" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '(\s|^)(-[^-[:space:]]*[CcDEn]|--clear|--read-clear|--console-off|--console-on|--console-level)'; then
      exit 0
    fi
    continue
  fi

  # --- journalctl: block maintenance/write flags ---
  # Dangerous: --rotate, --vacuum-*, --flush, --sync, --relinquish-var,
  #            --smart-relinquish-var, --setup-keys, --update-catalog
  # Safe: everything else (filtering, display, query)
  if [[ "$BASE" == "journalctl" ]]; then
    if printf '%s' "$CLEAN" | grep -qE -- '--(rotate|vacuum-size|vacuum-time|vacuum-files|flush|sync|relinquish-var|smart-relinquish-var|setup-keys|update-catalog|cursor-file)\b'; then
      exit 0
    fi
    continue
  fi

  # --- tree: block file-writing flags ---
  # Dangerous: -o/--output (writes to file), -R (creates 00Tree.html files)
  # Safe: everything else (display/filter)
  if [[ "$BASE" == "tree" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '(\s|^)-[^-[:space:]]*[oR]|(\s|^)--output\b'; then
      exit 0
    fi
    continue
  fi

  # --- tar: allow only list mode (-t/--list) ---
  # Safe: -t/--list (list archive contents) with any display flags
  # Dangerous: -c (create), -x (extract), -r (append), -u (update),
  #            -A (catenate), --delete
  # Also handles GNU-style flags without leading dash: tar tf, tar tvf
  if [[ "$BASE" == "tar" ]]; then
    TAR_HAS_LIST=false
    TAR_HAS_DANGER=false
    # Check standard flags (-t, --list)
    if printf '%s' "$CLEAN" | grep -qE '(\s)-[a-zA-Z]*t|(\s)--list(\s|$)'; then TAR_HAS_LIST=true; fi
    if printf '%s' "$CLEAN" | grep -qE '(\s)-[a-zA-Z]*[cxruA]|(\s)--(create|extract|get|append|update|catenate|concatenate|delete)(\s|$)'; then TAR_HAS_DANGER=true; fi
    # Check GNU-style no-dash flags (first arg after 'tar')
    TAR_FIRST_ARG=$(printf '%s' "$CLEAN" | awk '{print $2}')
    if [[ "$TAR_FIRST_ARG" =~ ^[a-zA-Z]+$ ]]; then
      [[ "$TAR_FIRST_ARG" == *t* ]] && TAR_HAS_LIST=true
      [[ "$TAR_FIRST_ARG" == *[cxruA]* ]] && TAR_HAS_DANGER=true
    fi
    # These flags execute arbitrary commands even in list mode
    if printf '%s' "$CLEAN" | grep -qE '(\s)-[a-zA-Z]*[IF]|(\s)--(use-compress-program|checkpoint-action|info-script|new-volume-script)\b'; then exit 0; fi
    if [[ "$TAR_HAS_LIST" == true ]]; then
      if [[ "$TAR_HAS_DANGER" == true ]]; then exit 0; fi
      continue
    fi
    exit 0  # no list flag → not a read operation
  fi

  # --- dpkg: allow only query flags ---
  # Safe: -l/--list, -L/--listfiles, -s/--status, -S/--search, -p/--print-avail,
  #       --print-architecture, --print-foreign-architectures, --get-selections,
  #       --compare-versions, --validate-*, --assert-*, -C/--audit, -V/--verify
  # Dangerous: -i/--install, -r/--remove, -P/--purge, --unpack, --configure, etc.
  if [[ "$BASE" == "dpkg" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '(\s|^)(-[^-[:space:]]*[irP]\b|--install|--remove|--purge|--unpack|--configure|--triggers-only|--set-selections|--clear-selections|--clear-avail|--add-architecture|--remove-architecture|--update-avail|--merge-avail|--record-avail)'; then
      exit 0
    fi
    if printf '%s' "$CLEAN" | grep -qE '(\s|^)(-[lLsSpCV]\b|--list|--listfiles|--status|--search|--print-avail|--print-architecture|--print-foreign-architectures|--get-selections|--compare-versions|--validate|--assert|--audit|--verify)\b'; then
      continue
    fi
    exit 0  # unknown dpkg usage → fall through
  fi

  # --- npm: allow read-only subcommands ---
  # Safe: list, ls, view, info, show, outdated, explain, why, root, prefix,
  #       bin, fund, help, diff, find-dupes, audit (without fix), config list/get
  # Dangerous: install, run, exec, publish, cache, config set/edit, etc.
  if [[ "$BASE" == "npm" ]]; then
    NPM_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^npm\s+//' | awk '{print $1}')
    case "$NPM_SUB" in
      list|ls|view|info|show|outdated|explain|why|root|prefix|bin|fund|help|diff|find-dupes|--help|--version)
        continue ;;
      audit)
        if printf '%s' "$CLEAN" | grep -qE '\bfix\b'; then exit 0; fi
        continue ;;
      config)
        NPM_CFG_ACT=$(printf '%s' "$CLEAN" | sed -E 's/.*\bconfig\s+//' | awk '{print $1}')
        case "$NPM_CFG_ACT" in list|get|ls) continue ;; *) exit 0 ;; esac
        ;;
    esac
    exit 0
  fi

  # --- pip / pip3: allow read-only subcommands ---
  # Safe: list, show, freeze, check, index, help, inspect
  # Dangerous: install, download, uninstall, wheel, cache, config, hash
  if [[ "$BASE" == "pip" || "$BASE" == "pip3" ]]; then
    PIP_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^pip3?\s+//' | awk '{print $1}')
    case "$PIP_SUB" in
      list|show|freeze|check|index|help|inspect|--help|--version)
        continue ;;
    esac
    exit 0
  fi

  # --- gem: allow read-only subcommands ---
  # Safe: list, info, environment, help, specification, contents, search,
  #       which, outdated, dependency
  # Dangerous: install, uninstall, update, push, build, exec, etc.
  if [[ "$BASE" == "gem" ]]; then
    GEM_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^gem\s+//' | awk '{print $1}')
    case "$GEM_SUB" in
      list|info|environment|help|specification|contents|search|which|outdated|dependency|--help|--version)
        continue ;;
    esac
    exit 0
  fi

  # --- kubectl: allow read-only subcommands ---
  # Safe: get, describe, logs, version, api-resources, api-versions, explain,
  #       top, auth, events, diff, cluster-info
  # Safe config: view, current-context, get-contexts, get-clusters, get-users
  # Dangerous: create, apply, delete, patch, exec, run, scale, etc.
  if [[ "$BASE" == "kubectl" ]]; then
    KUBE_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^kubectl\s+//' | awk '{print $1}')
    case "$KUBE_SUB" in
      get|describe|logs|version|api-resources|api-versions|explain|top|events|diff|cluster-info|--help|--version)
        continue ;;
      auth)
        KUBE_AUTH_ACT=$(printf '%s' "$CLEAN" | sed -E 's/.*\bauth\s+//' | awk '{print $1}')
        case "$KUBE_AUTH_ACT" in can-i|whoami|"") continue ;; *) exit 0 ;; esac
        ;;
      config)
        KUBE_CFG_ACT=$(printf '%s' "$CLEAN" | sed -E 's/.*\bconfig\s+//' | awk '{print $1}')
        case "$KUBE_CFG_ACT" in view|current-context|get-contexts|get-clusters|get-users) continue ;; *) exit 0 ;; esac
        ;;
    esac
    exit 0
  fi

  # --- gh (GitHub CLI): read-only subcommands, ask for writes ---
  # Unlike other commands that silently fall through for writes, gh commands
  # get an explicit "ask" decision with a reason. This provides better UX
  # since gh is frequently used and the reason helps the user decide.
  if [[ "$BASE" == "gh" ]]; then
    # Read-only top-level subcommands (no further checks needed)
    if printf '%s' "$CLEAN" | grep -qE '^gh\s+(search|status)\b'; then continue; fi

    # Read-only sub-subcommands for resource types
    if printf '%s' "$CLEAN" | grep -qE '^gh\s+(pr|issue)\s+(list|ls|view|status|checks|diff)\b'; then continue; fi
    if printf '%s' "$CLEAN" | grep -qE '^gh\s+(repo|run|release)\s+(list|view)\b'; then continue; fi
    if printf '%s' "$CLEAN" | grep -qE '^gh\s+(gist)\s+(list|view)\b'; then continue; fi
    if printf '%s' "$CLEAN" | grep -qE '^gh\s+(cache|workflow)\s+(list|view)\b'; then continue; fi
    if printf '%s' "$CLEAN" | grep -qE '^gh\s+(ruleset)\s+(list|view|check)\b'; then continue; fi
    if printf '%s' "$CLEAN" | grep -qE '^gh\s+(label)\s+(list)\b'; then continue; fi

    # gh api: defaults to GET (safe), but certain flags indicate writes:
    #   -X/--method POST|PUT|PATCH|DELETE — explicit write method
    #   -f/--raw-field, -F/--field — auto-switches REST endpoints to POST
    #   --input — sends request body (implies write)
    if printf '%s' "$CLEAN" | grep -qE '^gh\s+api\b'; then
      if printf '%s' "$CLEAN" | grep -qE '(\s)(-X\s*|-X=|--method\s+|--method=)(POST|PUT|PATCH|DELETE)\b'; then
        ALL_ALLOW=false; GH_ASK_REASON="gh api with explicit write method"; continue
      fi
      if printf '%s' "$CLEAN" | grep -qE '(\s)(-[fF]\s|--field\s|--field=|--raw-field\s|--raw-field=|--input\s|--input=)'; then
        ALL_ALLOW=false; GH_ASK_REASON="gh api with body/field flags (implies POST)"; continue
      fi
      continue  # no write indicators → read-only GET request
    fi

    # All other gh commands (create, merge, comment, close, edit, delete,
    # auth, config, secret, variable, browse, etc.) → ask with reason
    ALL_ALLOW=false
    GH_ASK_REASON="potentially write gh command: $(printf '%s' "$CLEAN" | awk '{print $1, $2, $3}')"
    continue
  fi

  # --- bash/sh: allow running bash-guard scripts only ---
  # bash can execute arbitrary code, so it must block by default.
  # Exception: the guard's own scripts in GUARD_DIR are read-only
  # (stdin→stdout) and safe to auto-allow. Checks full resolved path
  # to prevent basename spoofing from other directories.
  if [[ "$BASE" == "bash" || "$BASE" == "sh" ]]; then
    SCRIPT_ARG=$(printf '%s' "$CLEAN" | awk '{print $2}')
    SCRIPT_BASE=$(basename "$SCRIPT_ARG" 2>/dev/null || true)
    case "$SCRIPT_BASE" in
      bash-guard.sh|bash-guard-test.sh)
        # Resolve to absolute path and verify it's in GUARD_DIR
        SCRIPT_REAL=$(realpath "$SCRIPT_ARG" 2>/dev/null || true)
        if [[ "$SCRIPT_REAL" == "$GUARD_DIR/bash-guard.sh" || "$SCRIPT_REAL" == "$GUARD_DIR/bash-guard-test.sh" ]]; then
          continue
        fi
        ;;
    esac
    exit 0
  fi

  # --- go: subcommand-dependent classification ---
  if [[ "$BASE" == "go" ]]; then
    GO_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^go\s+//' | awk '{print $1}')
    case "$GO_SUB" in
      version|doc|list|help|--help|--version) continue ;;
      env)
        # go env -w (write) and -u (unset) modify persistent config
        if printf '%s' "$CLEAN" | grep -qE '\s-[wu]'; then exit 0; fi
        continue ;;
      vet)
        # go vet -vettool=FILE executes an arbitrary binary
        if printf '%s' "$CLEAN" | grep -qE '\s-vettool\b'; then exit 0; fi
        continue ;;
    esac
    exit 0
  fi

  # --- cargo: subcommand-dependent classification ---
  if [[ "$BASE" == "cargo" ]]; then
    CARGO_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^cargo\s+//' | awk '{print $1}')
    case "$CARGO_SUB" in
      tree|metadata|search|version|verify-project|read-manifest|help|--help|--version) continue ;;
    esac
    exit 0
  fi

  # --- yarn: subcommand-dependent classification ---
  if [[ "$BASE" == "yarn" ]]; then
    YARN_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^yarn\s+//' | awk '{print $1}')
    case "$YARN_SUB" in
      list|info|why|licenses|outdated|help|--help|--version) continue ;;
    esac
    exit 0
  fi

  # --- pnpm: subcommand-dependent classification ---
  if [[ "$BASE" == "pnpm" ]]; then
    PNPM_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^pnpm\s+//' | awk '{print $1}')
    case "$PNPM_SUB" in
      list|ls|why|outdated|help|--help|--version) continue ;;
      audit)
        if printf '%s' "$CLEAN" | grep -qE '\bfix\b'; then exit 0; fi
        continue ;;
    esac
    exit 0
  fi

  # --- brew: subcommand-dependent classification ---
  if [[ "$BASE" == "brew" ]]; then
    BREW_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^brew\s+//' | awk '{print $1}')
    case "$BREW_SUB" in
      list|ls|info|search|deps|uses|outdated|doctor|config|desc|cat|log|help|--help|--version) continue ;;
    esac
    exit 0
  fi

  # --- apt: subcommand-dependent classification ---
  if [[ "$BASE" == "apt" ]]; then
    APT_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^apt\s+//' | awk '{print $1}')
    case "$APT_SUB" in
      list|show|search|policy|depends|rdepends|showsrc|changelog|help|--help|--version) continue ;;
    esac
    exit 0
  fi

  # --- podman: subcommand-dependent classification (mirrors docker) ---
  if [[ "$BASE" == "podman" ]]; then
    PODMAN_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^podman\s+//' | awk '{print $1}')
    case "$PODMAN_SUB" in
      ps|images|inspect|logs|stats|top|port|version|info|diff|--version|--help) continue ;;
    esac
    PODMAN_ACT=$(printf '%s' "$CLEAN" | sed -E 's/^podman\s+//' | awk '{print $2}')
    case "$PODMAN_SUB" in
      image)     [[ "$PODMAN_ACT" =~ ^(ls|list|inspect|history)$ ]] && continue ;;
      container) [[ "$PODMAN_ACT" =~ ^(ls|list|inspect|logs|stats|top|port|diff)$ ]] && continue ;;
      network)   [[ "$PODMAN_ACT" =~ ^(ls|list|inspect)$ ]] && continue ;;
      volume)    [[ "$PODMAN_ACT" =~ ^(ls|list|inspect)$ ]] && continue ;;
      compose)   [[ "$PODMAN_ACT" =~ ^(ps|logs|ls|images|config|version)$ ]] && continue ;;
      pod)       [[ "$PODMAN_ACT" =~ ^(ls|list|inspect|logs|stats|top)$ ]] && continue ;;
    esac
    exit 0
  fi

  # --- env: safe only when bare (prints environment) ---
  if [[ "$BASE" == "env" ]]; then
    ENV_ARGS=$(printf '%s' "$CLEAN" | sed -E 's/^env\s*//')
    if [[ -z "$ENV_ARGS" ]]; then continue; fi
    case "$ENV_ARGS" in --help|--version) continue ;; esac
    exit 0
  fi

  # --- Unrecognized command → fall through to normal permissions ---
  exit 0
done

# =============================================================================
# PHASE 3: Emit decision
# =============================================================================
# If we reach here, all segments were classified (none caused a bail-out).

if [[ "$ALL_ALLOW" == "true" ]]; then
  # Every segment was verified read-only → auto-allow
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"read-only command(s)"}}\n'
else
  # At least one segment was a known gh write → ask with reason
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"%s"}}\n' "$GH_ASK_REASON"
fi
exit 0

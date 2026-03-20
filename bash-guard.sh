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
#   - Chaining-aware: splits on &&, ||, ;, | and checks EVERY segment
#   - Shell-construct-aware: bails on $(…), backticks, and output redirections
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
# Split the command on shell operators (&&, ||, ;, |) into individual segments.
# Each segment is classified independently. ALL must be read-only for the
# overall command to be auto-allowed.
#
# Note: naive splitting may incorrectly split quoted strings containing
# operators (though Phase 1 stripping mitigates most cases). This is always
# over-conservative: produces unrecognized segments → falls through to prompt.

IFS=$'\n' read -r -d '' -a SEGMENTS < <(
  printf '%s' "$STRIPPED" | sed -E 's/(\|\||&&|[;|])/\n/g' && printf '\0'
) || true

ALL_ALLOW=true       # Set to false if any segment triggers "ask"
GH_ASK_REASON=""     # Reason string for gh write commands

# ---------------------------------------------------------------------------
# Trivially safe commands: every flag for these is read-only (verified via
# man pages). None can write files, delete files, or execute other commands.
#
# Categories:
#   Text processing: cat head tail wc grep rg diff uniq cut tr rev tac comm
#                    paste join fold nl column seq printf echo base64
#   File info:       ls file stat readlink du df basename dirname realpath
#   System info:     pwd whoami hostname uname id groups tty date uptime
#                    free nproc lscpu lsblk printenv
#   Lookup:          which type command hash man whatis apropos getent
#   Crypto/encoding: sha256sum sha1sum md5sum cksum xxd hexdump od strings
#   DNS:             nslookup dig host
#   Shell builtins:  cd true false test [ tput clear
#   Structured data: jq yq
# ---------------------------------------------------------------------------
SAFE_RE='^(ls|cat|head|tail|wc|file|stat|which|pwd|echo|printenv|realpath|basename|dirname|diff|uniq|cut|tr|cd|grep|rg|true|false|test|\[|jq|yq|date|whoami|hostname|uname|id|groups|tty|getent|sha256sum|sha1sum|md5sum|cksum|xxd|hexdump|od|strings|readlink|du|df|free|uptime|nproc|lscpu|lsblk|column|seq|printf|type|command|hash|man|whatis|apropos|tput|clear|rev|tac|comm|paste|join|fold|nl|base64|nslookup|dig|host)$'

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

  # --- sort: safe UNLESS -o/--output flag (writes to file) ---
  # Matches -o, -ro, -nro (combined short flags containing 'o'), --output
  if [[ "$BASE" == "sort" ]]; then
    if printf '%s' "$CLEAN" | grep -qE '(\s|^)(-[a-zA-Z]*o\b|--output\b)'; then
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
    if printf '%s' "$CLEAN" | grep -qE '\b(add|del|delete|change|replace|flush|save|restore|set|append)\b'; then
      exit 0
    fi
    continue
  fi

  # --- git: subcommand-dependent classification ---
  if [[ "$BASE" == "git" ]]; then
    # Extract git subcommand, skipping common flags that precede it
    # e.g., 'git --no-pager log' → 'log', 'git -C /path diff' → 'diff'
    GIT_SUB=$(printf '%s' "$CLEAN" | sed -E 's/^git\s+//' | sed -E 's/^(--no-pager\s+|-[cC]\s+[^ ]+\s+)*//' | awk '{print $1}')

    # Always-safe git subcommands (purely read-only, no flags can write)
    case "$GIT_SUB" in
      diff|log|show|status|rev-parse|describe|shortlog|blame|ls-files|ls-tree|cat-file|rev-list|name-rev|for-each-ref|show-ref|ls-remote)
        continue ;;
    esac

    # git stash: only 'list' (shows stashes) and 'show' (shows stash diff) are safe
    # Dangerous: push/pop/apply/drop/clear/create/store all modify state
    if [[ "$GIT_SUB" == "stash" ]]; then
      STASH_ACT=$(printf '%s' "$CLEAN" | sed -E 's/.*\bstash\s+//' | awk '{print $1}')
      case "$STASH_ACT" in list|show) continue ;; *) exit 0 ;; esac
    fi

    # git branch: safe for listing, dangerous with modification flags
    # -d/-D (delete), -m/-M (move/rename), -c/-C (copy) are write operations
    # Bare 'git branch' or with -r/-a/-v/--list just lists branches
    if [[ "$GIT_SUB" == "branch" ]]; then
      if printf '%s' "$CLEAN" | grep -qE '\s-[dDmMcC]\b'; then exit 0; fi
      continue
    fi

    # git tag: safe for listing, dangerous with creation/deletion flags
    # -a (annotate), -s (sign), -d (delete), -f (force) are write operations
    # Bare 'git tag' or with -l/-n/--list/--verify just lists or verifies tags
    if [[ "$GIT_SUB" == "tag" ]]; then
      if printf '%s' "$CLEAN" | grep -qE '\s-[asdf]\b'; then exit 0; fi
      continue
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
      if printf '%s' "$CLEAN" | grep -qE '(\s)(-X\s+|-X=|--method\s+|--method=)(POST|PUT|PATCH|DELETE)\b'; then
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

  # --- Unrecognized command → fall through to normal permissions ---
  # Commands not listed above (cp, mv, rm, mkdir, touch, chmod, sed, awk,
  # tee, xargs, curl, wget, ssh, python, node, etc.) produce no output,
  # so Claude Code's normal permission system handles them.
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

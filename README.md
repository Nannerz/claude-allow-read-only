# bash-guard.sh

A Claude Code `PreToolUse` hook that auto-allows verified read-only Bash commands. Everything else falls through to Claude Code's normal permission prompt.

## Why

Claude Code prompts before every Bash command. This is safe but slow for read-only operations like `ls`, `git status`, or `kubectl get pods`. This guard auto-allows commands it can verify are read-only, eliminating unnecessary prompts without compromising security.

## Security model

- **Fail-safe**: Unknown or unrecognized commands produce no output, which causes Claude Code to prompt the user. The guard can never auto-allow something it doesn't understand.
- **Over-conservative**: May prompt for actually-safe commands, but will never auto-allow a dangerous one. False negatives (unnecessary prompts) are acceptable; false positives (auto-allowing writes) are not.
- **Chaining-aware**: Splits on `&&`, `||`, `;`, `|`, `&` and classifies every segment independently. All segments must be safe for the command to be auto-allowed.
- **Shell-construct-aware**: Bails on `$(...)`, backticks, process substitution `<(...)`/`>(...)`, output redirection `>`/`>>`, and quoted flags before any classification.
- **Abbreviation-aware**: Dangerous long options are matched by prefix (e.g., `--compr` catches `--compress-program`) to prevent GNU long option abbreviation bypasses.

### Out of scope

Environment variable injection (e.g., `LD_PRELOAD=evil.so cat file`, `PAGER=evil git log`) is not handled. These are niche attack vectors that would require maintaining an ever-growing blocklist of dangerous env var names. The guard focuses on command and flag classification.

## Processing phases

### Phase 1: Shell construct rejection

Strips quoted strings, then checks for dangerous shell constructs. If any are found, exits silently (falls through to prompt):

- Quoted flags: `"-exec"`, `'-delete'` (hides flags from Phase 2 checks)
- Command substitution: `$(...)` or backticks
- Process substitution: `<(...)` or `>(...)`
- Output redirection: `>` or `>>` (after removing safe patterns like `2>&1`, `>/dev/null`)

### Phase 2: Segment classification

Splits the command on shell operators (`&&`, `||`, `;`, `|`, `&`) into segments. For each segment:

1. Strips env var prefixes (`FOO=bar cmd` -> `cmd`)
2. Extracts the base command name (handles absolute paths via `basename`)
3. Auto-allows any command with sole argument `--version`
4. Checks against the trivially-safe regex (commands where every flag is read-only)
5. Checks flag-aware handlers (commands safe only with certain flags/subcommands)
6. If unrecognized, exits silently (falls through to prompt)

### Phase 3: Decision

- If all segments were classified as safe: outputs JSON with `permissionDecision: "allow"`
- If any segment was a known `gh` write: outputs JSON with `permissionDecision: "ask"` and a reason
- If any segment was unrecognized: no output (falls through to prompt)

## Command reference

### Trivially safe (all flags read-only)

| Category | Commands |
|----------|----------|
| Text processing | `cat` `head` `tail` `wc` `grep` `diff` `cut` `tr` `rev` `tac` `comm` `paste` `join` `fold` `nl` `column` `seq` `printf` `echo` `base64` `more` `numfmt` `expand` `unexpand` `tsort` |
| File info | `ls` `file` `stat` `readlink` `du` `df` `basename` `dirname` `realpath` |
| System info | `pwd` `whoami` `uname` `id` `groups` `tty` `uptime` `free` `nproc` `lscpu` `lsblk` `printenv` `locale` |
| Process info | `ps` `pgrep` `pidof` `pstree` `lsof` |
| Networking | `ss` `netstat` |
| User info | `who` `w` `last` |
| System stats | `vmstat` `iostat` `mpstat` |
| Hardware info | `lspci` `lsusb` |
| Filesystem info | `findmnt` `lsns` |
| Package query | `apt-cache` `dpkg-query` |
| Lookup | `which` `type` `hash` `whatis` `apropos` `getent` |
| Crypto/encoding | `sha256sum` `sha512sum` `sha1sum` `md5sum` `b2sum` `cksum` `hexdump` `od` `strings` |
| DNS | `nslookup` `dig` `host` |
| Shell builtins | `cd` `true` `false` `test` `[` `tput` `clear` |
| Structured data | `jq` |
| Binary inspection | `readelf` |
| Kernel info | `lsmod` `modinfo` |

### Flag-aware handlers

These commands are safe with most flags but have specific flags that write files or execute programs. Dangerous long options are matched by prefix to catch GNU abbreviations.

| Command | Safe | Blocked |
|---------|------|---------|
| `hostname` | Bare, display flags (`-f`, `-i`, `-d`, `-s`, `-A`, `-I`) | `-b`, `-F`/`--file`, `hostname NAME` |
| `date` | All display/format flags | `-s`/`--set` |
| `command` | `-v`, `-V` (lookup) | `command NAME` (executes) |
| `yq` | All read flags | `-i`/`--inplace` |
| `xxd` | All display flags | `-r` (reverse mode writes files) |
| `rg` | All search flags | `--pre` (executes preprocessor) |
| `nm` `objdump` | All display flags | `--plugin` (loads arbitrary shared library) |
| `man` | All display flags | `-P`/`--pager`, `-H`/`--html` (execute arbitrary program) |
| `less` | All display flags | `-o`/`-O`/`--log-file`/`--LOG-FILE` (writes to file) |
| `shuf` | All display flags | `-o`/`--output` (writes to file) |
| `uniq` | Zero or one positional arg | Two positional args (second is output file) |
| `find` | All filter/print flags | `-delete`, `-exec`, `-execdir`, `-ok`, `-okdir`, `-fls`, `-fprint*` |
| `sort` | All display flags | `-o`/`--output`, `--compress-program` (executes program) |
| `ip` | `show`, `list`, bare queries | `add`, `del`, `set`, `flush`, `exec`, `-batch`/`-b` |
| `tree` | All display flags | `-o`/`--output`, `-R` |
| `crontab` | `-l` (list) | `-e`, `-r`, `crontab FILE` |
| `dmesg` | Display/filter flags | `-C`, `-c`, `-D`, `-E`, `-n` |
| `journalctl` | Filter/display flags | `--rotate`, `--vacuum-*`, `--flush`, `--sync`, `--cursor-file` |
| `tar` | `-t`/`--list` only | `-c`, `-x`, `-r`, `-u`, `--delete`, `-I`/`-F`, `--use-compress-program`, `--checkpoint-action`, `--info-script`, `--new-volume-script`, `--to-command`, `--index-file`, `--rsh-command`, `--rmt-command` |
| `dpkg` | `-l`, `-L`, `-s`, `-S`, `-p`, `-C`, `-V` | `-i`, `-r`, `-P`, `--unpack`, `--configure` |
| `env` | Bare `env` (prints environment) | `env COMMAND`, `env -i`, `env VAR=val CMD` |

### Subcommand-aware handlers

| Command | Safe subcommands | Blocked (everything else) |
|---------|-----------------|---------------------------|
| `git` | `diff` `log` `show` `status` `rev-parse` `describe` `shortlog` `blame` `ls-files` `ls-tree` `cat-file` `rev-list` `name-rev` `for-each-ref` `show-ref` `ls-remote` `merge-base` `cherry` `count-objects` `diff-tree` `diff-files` `diff-index` `verify-commit` `verify-tag` `whatchanged` `stash list/show` `branch` (list only) `tag` (list/verify only) `remote` (query) `config` (read) `reflog show/exists` | `push` `commit` `add` `reset` `checkout` `merge` `rebase` `branch NAME` (creation) `tag NAME` (creation) `git -c` (config injection) `--output` `--upload-pack` |
| `docker` | `ps` `images` `inspect` `logs` `stats` `top` `port` `version` `info` `diff` + nested read subcommands | `run` `exec` `build` `rm` `rmi` `push` `pull` `stop` `compose config` etc. |
| `podman` | Same as docker + `pod ls/list/inspect/logs/stats/top` | Same as docker |
| `systemctl` | `status` `is-*` `show` `list-*` `cat` `help` | `start` `stop` `restart` `enable` `disable` etc. |
| `npm` | `list` `view` `info` `show` `outdated` `explain` `why` `root` `prefix` `bin` `diff` `find-dupes` `fund` (no --browser) `help` (no --viewer) `audit` (no fix) `config list/get` | `install` `run` `exec` `publish` etc. |
| `pip`/`pip3` | `list` `show` `freeze` `check` `index` `help` `inspect` | `install` `uninstall` `download` etc. |
| `gem` | `list` `info` `environment` `help` `specification` `contents` `search` `which` `outdated` `dependency` | `install` `uninstall` `update` `push` `build` `exec` etc. |
| `kubectl` | `get` `describe` `logs` `version` `api-resources` `api-versions` `explain` `top` `events` `diff` `cluster-info` `auth can-i/whoami` `config view/current-context/get-*` | `create` `apply` `delete` `patch` `exec` `run` `scale` `auth reconcile` etc. |
| `gh` | `search` `status` `pr/issue list/view/status/checks/diff` `repo/run/release list/view` `api` (GET) | Write commands get `ask` decision with reason. HTTP method matching is case-insensitive. |
| `go` | `version` `env` (read only) `doc` `list` (no -toolexec) `vet` (no -toolexec/-vettool) `help` | `run` `build` `install` `get` `generate` `clean` `test` `env -w/-u` |
| `cargo` | `tree` `metadata` `search` `version` `verify-project` `read-manifest` `help` | `build` `run` `install` `test` `bench` `publish` `clean` `fix` `add` `doc` |
| `yarn` | `list` `info` `why` `licenses` `outdated` `help` | `install` `add` `remove` `run` `exec` `publish` `upgrade` `dlx` |
| `pnpm` | `list` `ls` `why` `outdated` `audit` (no fix) `help` | `install` `add` `remove` `run` `exec` `publish` `dlx` `audit fix` |
| `brew` | `list` `ls` `info` `search` `deps` `uses` `outdated` `doctor` `config` `desc` `cat` `log` `help` | `install` `uninstall` `upgrade` `update` `tap` `cleanup` `link` `services` `home` |
| `apt` | `list` `show` `search` `policy` `depends` `rdepends` `showsrc` `changelog` `help` | `install` `remove` `purge` `update` `upgrade` `autoremove` `edit-sources` |

### Special handling

- **`bash`/`sh`**: Only allows running the guard's own scripts (verified by full resolved path via `realpath`)
- **`--version`**: Any command with sole argument `--version` is auto-allowed
- **Env var prefixes**: Stripped before classification (`FOO=bar ls` -> `ls`)
- **`git -c`**: Blocked entirely, including `-ckey=value` form (can set config keys like `core.pager` that execute arbitrary commands)

## Testing

Run the test suite:

```bash
bash bash-guard-test.sh
```

### Test framework

The test file provides three assertion helpers:

- `expect_allow 'command' ['label']` -- command should be auto-allowed
- `expect_block 'command' ['label']` -- command should produce no output (fall through to prompt)
- `expect_ask 'command' ['label']` -- command should produce an "ask" decision

Tests are grouped with `section "name"` calls. The suite prints a summary with pass/fail counts and exits non-zero on any failure.

### Adding tests

Add new tests in the appropriate section of `bash-guard-test.sh`. Follow the pattern:

```bash
section "mycommand: safe subcommands"
expect_allow 'mycommand list'
expect_allow 'mycommand show thing'

section "mycommand: dangerous subcommands"
expect_block 'mycommand delete thing'
expect_block 'mycommand exec thing'
```

## Installation

### As a plugin (recommended)

```bash
# Add the marketplace
/plugin marketplace add Nannerz/claude-allow-read-only

# Install the plugin
/plugin install claude-allow-read-only@nannerz-plugins
```

The plugin auto-updates when new versions are pushed.

### Manual

Add to your Claude Code settings (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash /path/to/bash-guard.sh"
          }
        ]
      }
    ]
  }
}
```

# Security audit: `javorszky/envsecrets`

Scope: full repository at HEAD of `main` at audit time. Go binary (`cmd/`,
`internal/`), bash helpers (`bash/`), CI (`.github/`). macOS-only CLI that
stores secrets in a dedicated Keychain file and mirrors them to 1Password.

Findings are ordered by severity. No remote attack surface exists (no network
listener). The threat model is:

- (a) local multi-user exposure,
- (b) backup / cloud-sync leakage,
- (c) process-table disclosure,
- (d) file-system tampering / supply-chain.

---

## HIGH

### H1. Keychain master password written in plaintext to `~/Documents` (likely iCloud-synced)

`internal/keychain/keychain.go:358` (`writeAccessFile`) and
`bash/full_functions.sh:14` (`_es_write_kc_access_file`) both write a file
containing:

```
password: <64-hex keychain password>
```

to `~/Documents/envsecrets-<vault>-keychain-access.txt`.

- On default macOS installs, `~/Documents` is automatically synced to iCloud
  Drive when "Desktop & Documents Folders" is enabled. The keychain master
  password is therefore uploaded to Apple servers and pushed to every
  signed-in device.
- Third-party sync tools (Dropbox, Google Drive, OneDrive, Time Machine,
  corporate DLP agents) commonly watch `~/Documents` too.
- The README positions envsecrets's differentiator as "no network required …
  local-only" — this file silently defeats that property.
- Mode `0o600` is correct for the local filesystem but is ignored by
  iCloud / backup agents.

Recommendation: do not persist the password to disk. If a recovery copy is
desirable, write it to `~/Library/Application Support/envsecrets/` (not
iCloud-synced by default) and document the trade-off. Strongly reconsider
writing it at all.

### H2. Keychain auto-lock disabled

`internal/keychain/keychain.go:237-245` and `bash/full_functions.sh:160` call
`security set-keychain-settings <path>` with no flags, which clears both the
idle timeout and lock-on-sleep. Once unlocked, the vault stays unlocked until
reboot.

Effect: every subsequent process running as your user can read every secret
without any prompt — there is effectively no second factor between "screen
unlocked" and "all credentials." This is a downgrade from the login
keychain's default behaviour and from what the README implies.

Recommendation: leave the default lock behaviour, or at minimum pass explicit
`-l -u -t <timeout>` so lock-on-sleep and an idle timeout are preserved.
Document the tradeoff prominently.

### H3. Secrets and keychain passwords passed on the command line (argv exposure)

Every plaintext flows through `exec.CommandContext` argv:

- `internal/keychain/keychain.go:103` — `security add-generic-password … -w <value>` (user secret)
- `internal/keychain/keychain.go:228` — `security create-keychain -p <password>` (master)
- `internal/keychain/keychain.go:272` — `security unlock-keychain -p <password>`
- `internal/keychain/keychain.go:296` — `security add-generic-password … -w <password>` (master stored in login keychain)
- `internal/onepassword/onepassword.go:163,179` — `op item create/edit … "password=<value>"`
- `bash/full_functions.sh:189,194,196,224` — same pattern.

On macOS `ps` by default hides other users' argv, but: (1) running processes'
argv are still readable to the same user's other processes (including
background daemons, sandboxed helpers, crash reports, EndpointSecurity / MDM
tooling, `sysdiagnose` bundles); (2) crash reports and spindumps routinely
include argv. The `security` CLI accepts `-w` alone to prompt on stdin, and
`op` can read `password=` values via `--template -` / stdin, so this is
avoidable.

Recommendation: feed secret material over stdin (e.g. `security
add-generic-password … -w -` with the value on the pipe; `op item create
--template -`) for both user secrets and the master password.

### H4. `gen-env` output written with default (world-readable) permissions

`cmd/gen_env.go:53` uses `os.Create(outputPath)` which produces
`0o666 & ~umask` — commonly `0644`. The file is then populated with
decrypted secrets. On any machine with a non-restrictive umask, the `.env` is
readable by other local users, other apps on a shared CI runner, etc.

Recommendation: create the `.env` with
`os.OpenFile(path, O_WRONLY|O_CREATE|O_TRUNC, 0o600)` (and refuse to clobber a
pre-existing file with wider perms).

---

## MEDIUM

### M1. Silent login-keychain entry restoration from an attacker-writable location

`internal/keychain/keychain.go:314-343` (`readKeychainPassword`) and the bash
equivalent at `bash/full_functions.sh:89-103` silently:

1. read the password line out of
   `~/Documents/envsecrets-<vault>-keychain-access.txt`;
2. inject it into the login keychain as the new password for
   `envsecrets-keychain-<vault>`;
3. proceed to unlock the dedicated keychain file with it.

If an attacker can drop / replace that file (iCloud-shared device, shared
backup, supply-chain malware, another local user with loose perms), they can
cause envsecrets to rewrite the trusted login-keychain entry with an
attacker-chosen value, and/or — if the attacker also writes a matching
dedicated keychain file into `~/.local/share/envsecrets/` — unlock a
substituted vault containing attacker-controlled secrets, which then flow
into downstream env vars, `.env` files, and 1Password.

The file is treated as authoritative with no integrity check and no user
prompt.

Recommendation: do not auto-restore from the file. If the login-keychain
entry is missing, prompt the user. Emit a loud stderr warning at minimum
(currently silent). Best: don't write the "recovery" file at all (H1).

### M2. Path-traversal in `vault` name

`vault` flows from `--vault` / `$ENVSECRETS_VAULT` / config file into
`filepath.Join(home, ".local/share/envsecrets", vault+".keychain")`
(`internal/keychain/keychain.go:45-49`) and
`filepath.Join(home, "Documents", "envsecrets-"+vault+"-keychain-access.txt")`
(`:352`). Same pattern for `OpVault`.

Nothing rejects `../` or absolute paths. The primary risk is a malicious
config file (committed in a repo, dropped into `$HOME`) re-pointing the
vault to an attacker-controlled path or a symlinked-out location.

Recommendation: validate `vault` (e.g. `^[A-Za-z0-9._-]+$`) and reject any
value containing `/`, `\`, or leading `.`.

### M3. `security` / `op` flag collision on unusual key names

Keys are passed positionally to `security find-generic-password -s "$key"`,
`op item delete --vault … $key`, etc. A key beginning with `--` may be
interpreted as a flag by `op` (e.g. `--help`, `--debug`). Not remotely
exploitable, but a pathological key name could trigger unexpected behaviour
in the backend.

Recommendation: validate key names against a conservative character class, or
use `--` as a positional separator where the CLI supports it (e.g.
`op item delete --vault X -- KEY`).

### M4. Fragile error classification in keychain delete

`internal/keychain/keychain.go:441-449` maps any `*exec.ExitError` to
`ErrNotFound`. Real failures (locked keychain, permission error, disk full)
are silently reclassified. Because `Set` does `remove → add` (`:90-112`),
this can leave the vault in an inconsistent state (old value still present)
while reporting success.

Recommendation: inspect `security` exit codes / stderr explicitly (44 = item
not found, 25 = locked, …) instead of treating any non-zero exit as
`ErrNotFound`. Consider an upsert-style flow.

### M5. `.env` injection via newline in stored secret values

`cmd/gen_env.go:97` writes `%s=%s\n` directly. A secret containing a raw
newline bleeds into subsequent assignments:

```
API_KEY=abc
FAKE_VAR=injected
DATABASE_URL=...
```

Any downstream consumer that parses `.env` naively (`godotenv`, `dotenv`,
`export $(cat .env | xargs)`) will silently define `FAKE_VAR=injected`. A
user with write access to the upstream 1Password vault (e.g. a shared vault)
can inject arbitrary env vars into every consumer.

Recommendation: reject or quote-escape values containing `\n`, `\r`, or
unescaped `"`; prefer proper POSIX-shell quoting (`KEY="…"` with
backslash-escaped internal `"`).

---

## LOW / Informational

### L1. `fmt.Errorf(…: %w\n%s, err, out)` can surface secret material

Several sites wrap `cmd.CombinedOutput()` into errors (`keychain.go:108,
233, 244, 277, 300`; `onepassword.go:119, 168`). `security` / `op` don't
currently echo the password in error output, but a minor version upgrade
that adds a "usage:" banner would leak the raw value into stderr / error
aggregators. Trim or allow-list `out` before wrapping.

### L2. TOCTOU on keychain creation

`internal/keychain/keychain.go:206-211`: `os.Stat` then `create-keychain`.
Practically self-owned; prefer `O_CREATE|O_EXCL` semantics where feasible.

### L3. Regex-based 1P vault check in bash

`bash/full_functions.sh:113-114`:
`grep -qi "\"name\":\"${op_vault}\""`. `op_vault` is interpolated into both
a JSON match and a regex; `.` and other metacharacters match more broadly
than intended. Self-owned but error-prone.

### L4. `$USER` / `$LOGNAME` trusted

`keychain.go:463-470` uses `$USER` with a `$LOGNAME` fallback. If the env is
manipulated (cron, CI runners, `sudo -E`), secrets end up under a different
account namespace and silently diverge. Prefer `os/user.Current()`.

### L5. 1Password error classification by substring

`onepassword.go:194-210` matches English error strings. Localisation or a
minor `op` update silently turns real failures into `ErrNotFound`, which
`Delete` swallows. Use structured exit codes or `--format=json` errors where
available.

### L6. `root.go:33` prints raw `err.Error()` to stderr

Fine on its own, but combined with L1 it means any wrapped `CombinedOutput`
leakage surfaces to the user's terminal.

### L7. CI workflow

`.github/workflows/ci.yml` pins actions by major version only
(`actions/checkout@v6`, `actions/setup-go@v6`,
`golangci/golangci-lint-action@v9`). `permissions: contents: read` is good
and there are no writable secrets. Per OpenSSF Scorecard guidance, pin by
commit SHA. `govulncheck` is installed with `@latest` at runtime — pin a
version for reproducible CI.

### L8. `simple_functions.sh`

Uses the login keychain; `printf '%s' "$value"` is safe. These helpers still
inherit the argv-visibility concern of H3.

### L9. `os.UserHomeDir()` errors ignored

`keychain.go:44,351` and `onepassword.go:217` discard the error. If `HOME`
is unset, paths degrade to relative (`.local/share/…`), writing keychain
files into the current working directory. Surprising in daemon / CI
contexts. Prefer to surface the error.

### L10. `config init` TOCTOU

`cmd/config_init.go:60-64`: `os.Stat` then `os.WriteFile`. Not exploitable in
practice; prefer `O_CREATE|O_EXCL`.

---

## Summary and recommended priorities

1. Stop writing the keychain master password to `~/Documents` (H1). This
   alone undermines every other protection.
2. Stop disabling keychain auto-lock (H2).
3. Feed all secret material through stdin / pipes, never argv (H3).
4. Lock down `gen-env` output mode to `0o600` (H4).
5. Validate `vault`, `op_vault`, and key names (M2, M3).
6. Remove the silent login-keychain auto-restore from the access file (M1).
7. Tighten error classification and error-message leakage (M4, L1, L5).
8. Escape or reject newlines in `.env` output (M5).

The Go code itself is tidy: Cobra / Viper are used conventionally,
`crypto/rand` is used for password generation, `exec.CommandContext` avoids a
shell, and there is no network listener. The risk profile is almost entirely
driven by (a) design choices around on-disk plaintext recovery files and
(b) the habit of passing secrets on the command line.

# AgentLeaks

Find, redact and block the API keys sitting in plain text inside every AI coding tool's local history.

![AgentLeaks scan and fix on a throwaway fixture](assets/demo.gif)

The first scan of the laptop this was built on found a real GitHub token in four places across Claude Code's prompt history and a session transcript, and by the end of the build the transcripts of the build itself held 15 hits of 5 distinct values. 100 files, 47 MB, one second on an idle machine.[^1]

[![CI](https://github.com/Arthur031221/AgentLeaks/actions/workflows/ci.yml/badge.svg)](https://github.com/Arthur031221/AgentLeaks/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Arthur031221/agentleaks?include_prereleases)](https://github.com/Arthur031221/AgentLeaks/releases)


## Why

Coding agents read `.env` as a matter of course. Every secret they touch lands unencrypted in a transcript file that persists for months, gets synced by iCloud or Dropbox, and ends up in backups. Claude Code writes it to `~/.claude/projects/*.jsonl`. Codex writes it to `~/.codex/sessions`. Cursor writes it into a SQLite database. Cline, Roo, Gemini CLI, OpenCode, Aider and Copilot all keep their own copies. Anthropic closed the request to redact secrets from transcripts as not planned. Nothing cleans up what already leaked, and nothing stops the next agent from doing it again.

AgentLeaks does three things. `scan` finds the keys across every tool. `fix` redacts them in place without corrupting the JSONL records or SQLite rows the tools depend on. `guard` installs hooks so the agent is denied the next time it reaches for `.env` or `~/.aws/credentials`.

## Install

```sh
go install github.com/Arthur031221/agentleaks/cmd/agentleaks@latest
```

Static binaries for macOS (arm64, amd64), Linux and Windows are attached to each [release](https://github.com/Arthur031221/AgentLeaks/releases). The Homebrew formula and the `npx agentleaks` wrapper are prepared under `packaging/` and are published with the first tagged release. No runtime dependencies, no cgo, nothing leaves your machine unless you run `verify`.

## Quick start

```sh
agentleaks                  # scan every tool it can find, print a table
agentleaks fix              # show what would be redacted (dry run)
agentleaks fix --yes        # redact in place, originals go to ~/.agentleaks/backups
agentleaks guard            # install deny hooks for Claude Code, Codex, Cursor, Gemini CLI, Copilot CLI
```

The table shows the provider, which tool leaked it, the file, the line or database record, a masked preview, how old the file is, and how many times the same key appears in that file:

```
PROVIDER      TOOL         FILE                                          WHERE                         PREVIEW      AGE  HITS
Stripe        Aider        ~/Desktop/shop/.aider.chat.history.md         3:50                          sk_liv...WW  now  1
GitHub        Claude Code  ~/.claude/history.jsonl                       1:45                          ghp_CN...JE  now  1
OpenAI        Claude Code  ...ects/-Users-demo-shop/9c1d2e3f-demo.jsonl  3:125                         sk-pro...dt  now  1
Stripe        Claude Code  ...ects/-Users-demo-shop/9c1d2e3f-demo.jsonl  3:227                         sk_liv...WW  now  2
AWS           Claude Code  ...ects/-Users-demo-shop/9c1d2e3f-demo.jsonl  3:287                         AKIA80...GU  now  1
AWS           Claude Code  ...ects/-Users-demo-shop/9c1d2e3f-demo.jsonl  3:331                         0VFead...ZG  now  1
Anthropic     Codex        ...28/rollout-2026-09-28T10-01-00-demo.jsonl  2:144                         sk-ant...AA  now  1
Slack         Cursor       ~/.cursor/mcp.json                            3:115                         xoxb-5...xK  now  1
Hugging Face  Cursor       ...ort/Cursor/User/globalStorage/state.vscdb  cursorDiskKV/bubbleId:demo:1  hf_r6j...LF  now  1
Google        Gemini CLI   ...ni/tmp/demo/chats/session-2026-09-28.json  1:70                          AIza-T...Wz  now  1

11 secrets (9 distinct) in 7 files across 5 tools. Scanned 7 files (22.2 KB) from 5 tools in 1ms.
Next: `agentleaks fix` to redact (dry run), `agentleaks guard` to stop it happening again.
```

That output comes from the throwaway home that `demo/setup.sh` builds with random keys.

Exit code 1 means secrets were found, 0 means clean, 2 means an error. Use `--exit-zero` in scripts that only want the report.

## How it works

1. **Discovery.** A registry of every supported tool's on-disk layout (`agentleaks rules --tools` prints it). Paths that do not exist are skipped silently. Per-project files such as `.mcp.json`, `.cursor/mcp.json` and `.aider.chat.history.md` are found by walking common project folders under your home to a depth of four, skipping `node_modules`, `.git`, `Library` and the like.
2. **Detection.** 64 rules in [`internal/rules/rules.toml`](internal/rules/rules.toml), each with an id, provider, RE2 regex, keyword prefilter and optional entropy floor and allowlist. A single-pass Aho-Corasick automaton checks every line for rule keywords first, so regular expressions run only on candidate lines. Rules are ordered, and when two rules match overlapping bytes the more specific one wins, so `sk-ant-` is Anthropic, not OpenAI. Generic `API_KEY=` style assignments are last, with an entropy floor of 3.5 bits per byte and a placeholder allowlist.
3. **Streaming.** Files are read line by line through a 256 KiB buffer, never loaded whole. Lines longer than 32 MiB are scanned in overlapping chunks. Files are scanned in parallel, one worker per CPU. SQLite stores (Cursor's `state.vscdb`, Copilot's `session-store.db`) are opened read-only with a pure Go driver and every text cell is scanned.
4. **Redaction.** `fix` rewrites each line with the secret replaced by `[REDACTED:<rule-id>]`. The replacement contains no quote or backslash, so a JSON string stays a JSON string. Every JSONL record is re-validated after rewriting and left untouched if it would no longer parse. Whole JSON documents are validated the same way. SQLite rows are updated in a transaction by rowid, preserving blob versus text type. Private key blocks are blanked from `BEGIN` to `END`, and inside a JSON string the redaction stops at the closing quote. The original file is copied to `~/.agentleaks/backups/<timestamp>/` first, the rewrite is atomic (temp file plus rename), and the modification time is preserved so tools that sort sessions by mtime do not reshuffle.
5. **Guarding.** `guard` merges a hook entry into each tool's own config format. The hook command is `agentleaks hook <tool> <event>`. It reads the tool's JSON payload from stdin, checks every path and shell token against a list of secret file patterns, and answers in that tool's deny protocol. For Claude Code the deny is exit code 2 with the reason on stderr, which the hook docs describe as the form JSON cannot override. Claude Code also gets a PostToolUse hook that redacts secrets from tool output before they are written to the transcript.
6. **Verification** is off by default. `verify` prints a consent notice, then sends each distinct key to its own provider's read-only endpoint (for example `GET https://api.github.com/user`) and reports live, dead or unknown. Nothing is sent to any third party.

## Comparison

| | AgentLeaks | gitleaks | trufflehog | snyk/agent-scan | scrub-claude-sessions | claude-code-redaction-hooks | Sieve |
|---|---|---|---|---|---|---|---|
| Knows where 13 AI tools keep history | yes | no | no | no | Claude Code only | Claude Code only | closed source, unclear |
| Scans SQLite chat stores (Cursor, Copilot) | yes | no | no | no | no | no | unclear |
| Redacts in place, keeps JSONL and SQLite valid | yes | no | no | no | Claude Code JSONL | no | unclear |
| Installs deny hooks in the agent | 5 tools | no | no | no | no | Claude Code only | unclear |
| Scrubs tool output before it hits the transcript | Claude Code | no | no | no | no | yes | unclear |
| Liveness check | 14 providers | no | 800+ detectors | no | no | no | unclear |
| Scans MCP and agent config for secrets | yes | as files | as files | yes, plus prompt injection risks | no | no | unclear |
| Scans git history | no | yes | yes | no | no | no | no |
| Single static binary | yes | yes | yes | no (Node) | no (shell) | no (shell) | Mac App Store |
| License | MIT | MIT | AGPL | Apache 2.0 | MIT | MIT | paid, closed |

gitleaks and trufflehog are excellent at repositories and generic filesystems, and you can point them at `~/.claude` yourself, but they will not find Cursor's database, will not redact, and will not stop the next leak. snyk/agent-scan audits MCP configs and skills for risk, not transcripts. The two Claude Code projects are single-tool. Sieve is the only product that names the same problem, and it is closed.

## Commands

### `agentleaks scan [flags] [path ...]`

Scan every supported tool, or the given files and directories.

| Flag | Meaning |
|---|---|
| `--json` | JSON report on stdout |
| `--sarif` | SARIF 2.1.0 on stdout, for code scanning upload |
| `-o <file>` | write the report to a file |
| `--all` | one row per occurrence instead of per secret per file |
| `--tool <ids>` | comma separated tool ids, default all found |
| `--rule <ids>` | only these rule ids |
| `--min-severity high|medium|low` | default low |
| `--home <dir>` | scan another home directory (also `$AGENTLEAKS_HOME`) |
| `--repos <dirs>` | where to look for per-project files, default common folders under home |
| `--depth <n>` | project search depth, default 4 |
| `--workers <n>` | parallel files, default CPU count |
| `--include-credential-stores` | also report the tools' own auth files (`~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, and so on) |
| `--verify --yes` | liveness check, see `verify` |
| `--exit-zero` | exit 0 even with findings |
| `--quiet` | no progress line |

`agentleaks scan ~/Downloads/support-bundle` scans arbitrary paths. Files with NUL bytes in the first 8 KiB are treated as binary and skipped. Files ending in `.db`, `.sqlite`, `.sqlite3` or `.vscdb` are opened as SQLite.

### `agentleaks fix [flags] [path ...]`

Dry run by default. Prints one line per file with the number of secrets and the planned action.

| Flag | Meaning |
|---|---|
| `--yes` | apply |
| `--backup-dir <dir>` | default `~/.agentleaks/backups/<timestamp>` |
| `--no-backup` | do not keep originals |
| `--include-credential-stores` | rewrite the tools' own auth files too. This logs you out of that tool |
| `--json` | results as JSON |

The backup directory contains the originals with the secrets still in them. Delete it once you have confirmed the tools still open their history. If Cursor is running, its database is locked and `fix` reports the error instead of writing. Quit Cursor and run again.

### `agentleaks guard [flags]`

| Flag | Meaning |
|---|---|
| `--tool <ids>` | `claude-code`, `codex`, `cursor`, `gemini`, `copilot`, default all installed |
| `--uninstall` | remove only the entries AgentLeaks added |
| `--dry-run` | show what would change |
| `--force` | install even when the tool's config directory is missing |
| `--coverage` | print the coverage table below |
| `--binary <path>` | binary to reference in the hook, default this executable |

Coverage is limited by what each tool's hook system exposes. This table is generated from the code (`agentleaks guard --coverage`):

| Tool | Config written | Denies file reads | Denies shell reads | Scrubs output | Events |
|---|---|---|---|---|---|
| Claude Code | `~/.claude/settings.json` | yes | yes | yes | PreToolUse, PostToolUse |
| Codex | `~/.codex/hooks.json` | via shell | yes | no | PreToolUse |
| Cursor | `~/.cursor/hooks.json` | yes | yes | no | beforeShellExecution, beforeReadFile |
| Gemini CLI | `~/.gemini/settings.json` | yes | yes | no | BeforeTool |
| Copilot CLI | `~/.copilot/hooks/agentleaks.json` | yes | yes | no | preToolUse |

Known gaps: MCP tools that read files are not intercepted in any tool. Codex has no separate read tool, so reads through `apply_patch` are not covered. Copilot CLI does not document its tool names, so paths and commands are taken from `toolArgs` by key name. Hook timeouts fail open in every tool. `cp .env.example .env` is denied because `.env` appears as a token.

What counts as a secret path: `.env` and `.env.*` (not `.env.example`, `.env.sample`, `.env.template`), `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.aws/credentials`, `.config/gcloud`, `.kube/config`, `.ssh`, `.gnupg`, `terraform.tfvars`, `*.tfstate`, `secrets.yaml`, `credentials.json`, `service-account*.json`, and the AI tools' own credential and MCP files. Add your own globs, one per line, in `~/.agentleaks/guard-paths.txt`. Shell commands are tokenised and every token is checked, so `cat .env`, `grep KEY .env`, `source .env` and `export $(cat .env)` are all denied. Bare `env` and `printenv`, and `echo $ANY_KEY_OR_TOKEN`, are denied too.

Test a hook by hand:

```sh
echo '{"tool_name":"Read","tool_input":{"file_path":".env"}}' | agentleaks hook claude-code PreToolUse
echo $?   # 2
```

### `agentleaks verify [flags]`

Runs a scan, prints this notice, and asks for confirmation unless `--yes`:

> Verification sends each key to the provider that issued it, using a read-only endpoint. Nothing is sent anywhere else. The provider will see the request in its logs. A live key is still a live key after this check. Revoke it at the provider.

| Provider | Endpoint |
|---|---|
| Anthropic | `GET https://api.anthropic.com/v1/models` |
| GitHub | `GET https://api.github.com/user` |
| Groq | `GET https://api.groq.com/openai/v1/models` |
| Hugging Face | `GET https://huggingface.co/api/whoami-v2` |
| Mistral | `GET https://api.mistral.ai/v1/models` |
| npm | `GET https://registry.npmjs.org/-/whoami` |
| OpenAI | `GET https://api.openai.com/v1/models` |
| OpenRouter | `GET https://openrouter.ai/api/v1/auth/key` |
| Replicate | `GET https://api.replicate.com/v1/account` |
| SendGrid | `GET https://api.sendgrid.com/v3/scopes` |
| Slack | `POST https://slack.com/api/auth.test` |
| Stripe | `GET https://api.stripe.com/v1/balance` |
| Together | `GET https://api.together.xyz/v1/models` |
| Vercel | `GET https://api.vercel.com/v2/user` |

HTTP 200 is live, 401 or 403 is dead, anything else is unknown. Ten second timeout, redirects are not followed, the key never appears in any output.

### `agentleaks report --json | --sarif [-o file]`

Same as `scan` with a machine readable format. The JSON document has `summary`, `tools` (which tools were found and how many files each has), `findings` (rule, provider, severity, tool, path, line, column or record, masked preview, fingerprint, modified time) and `errors`. Findings never include the secret itself. The fingerprint is the first 12 hex characters of the SHA-256 of the secret, stable across runs, so you can diff reports.

### `agentleaks rules [--json] [--tools]`

Lists the 64 rules, or with `--tools` every path the scanner looks at.

### `agentleaks hook <tool> <event>`

The entry point the tools call. You do not run it yourself except to test.

## What is scanned

macOS paths are shown. On Linux, `~/Library/Application Support/<App>` becomes `~/.config/<App>` and `~/.local/share` is used for OpenCode. On Windows it becomes `%APPDATA%\<App>`. `<repo>` means any directory found under the project folders.

| Tool | Files |
|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl`, `~/.claude/history.jsonl`, `~/.claude.json`, `~/.claude/settings*.json`, `~/.claude/file-history/**`, `~/.claude/paste-cache/*.txt`, `~/.claude/shell-snapshots/*.sh`, `<repo>/.mcp.json`, `<repo>/.claude/settings*.json` |
| Codex | `~/.codex/sessions/**/*.jsonl`, `~/.codex/archived_sessions/**/*.jsonl`, `~/.codex/history.jsonl`, `~/.codex/config.toml`, `~/.codex/hooks.json`, `~/.codex/log/*.log`, `<repo>/.codex/config.toml` |
| Cursor | `~/Library/Application Support/Cursor/User/globalStorage/state.vscdb`, `.../workspaceStorage/*/state.vscdb`, `~/.cursor/mcp.json`, `~/.cursor/hooks.json`, `<repo>/.cursor/mcp.json` |
| Gemini CLI | `~/.gemini/tmp/*/chats/*.json`, `~/.gemini/tmp/*/checkpoints/**`, `~/.gemini/tmp/*/shell_history`, `~/.gemini/history/**`, `~/.gemini/settings.json`, `~/.gemini/.env`, `<repo>/.gemini/settings.json` |
| Cline | `<globalStorage>/saoudrizwan.claude-dev/tasks/*/api_conversation_history.json`, `ui_messages.json`, `context_history.json`, `settings/cline_mcp_settings.json`, `state/taskHistory.json` |
| Roo Code | `<globalStorage>/rooveterinaryinc.roo-cline/tasks/*/api_conversation_history.json`, `ui_messages.json`, `settings/mcp_settings.json` |
| OpenCode | `~/.local/share/opencode/storage/**/*.json`, `~/.local/share/opencode/*.db`, `~/.local/share/opencode/log/*.log`, `~/.config/opencode/opencode.json`, `<repo>/opencode.json` |
| Aider | `<repo>/.aider.chat.history.md`, `<repo>/.aider.input.history`, `<repo>/.aider.llm.history`, `~/.aider.chat.history.md`, `~/.aider.input.history`, `~/.aider.conf.yml`, `~/.aider/**` |
| GitHub Copilot CLI | `~/.copilot/session-state/**/*.jsonl`, `~/.copilot/session-state/**/*.json`, `~/.copilot/session-store.db`, `~/.copilot/command-history-state/**`, `~/.copilot/logs/*.log`, `~/.copilot/mcp-config.json`, `~/.copilot/settings.json`, `~/.copilot/providers.json` |
| VS Code Copilot Chat | `<globalStorage>/emptyWindowChatSessions/*.jsonl`, `<workspaceStorage>/*/chatSessions/*.jsonl`, `<globalStorage>/github.copilot-chat/session-store.db` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json`, `~/.config/devin/mcp_config.json` |
| Continue | `~/.continue/config.yaml`, `~/.continue/config.json`, `~/.continue/config.ts`, `~/.continue/.env`, `~/.continue/sessions/*.json`, `<repo>/.continue/config.yaml` |

`<globalStorage>` is checked for VS Code, VS Code Insiders, VSCodium, Cursor and Windsurf, since all of them host the Cline and Roo extensions.

The tools' own credential stores (`~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, `~/.copilot/config.json`, `~/.local/share/opencode/auth.json`, Cline's `secrets.json`) are scanned only with `--include-credential-stores`, because redacting them logs you out.

## Detection rules

Provider-specific: Anthropic (`sk-ant-`), OpenAI (`sk-proj-`, `sk-svcacct-`, `sk-admin-`, legacy `T3BlbkFJ` keys, generic `sk-`), DeepSeek, AWS (access key id and secret), GitHub (`ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_`, `ghr_`), GitLab (`glpat-`, `glrt-`, `gldt-`), Stripe (`sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`, `whsec_`), Slack (`xox*`, `xapp-`, webhook URLs), Google (`AIza`, `GOCSPX-`, `ya29.`, service account JSON), Hugging Face (`hf_`), Groq (`gsk_`), Mistral, OpenRouter (`sk-or-v1-`), Together, Replicate (`r8_`), Vercel, Supabase (`sbp_`, `sb_secret_`), Twilio, SendGrid (`SG.`), npm (`npm_`, `_authToken`), PyPI (`pypi-`), xAI (`xai-`), Perplexity (`pplx-`), Fireworks, DigitalOcean (`dop_v1_`), Tailscale (`tskey-`), Shopify (`shpat_`), Telegram, Cloudflare, Langfuse, Notion, Linear, Postman, Sentry, Doppler, Mailgun, Datadog, Heroku, Cohere.

Structural: private key blocks (RSA, EC, DSA, OpenSSH, PGP, age), JWTs, database connection strings with a password, URLs with credentials, `Authorization: Bearer` values, and generic `API_KEY=`, `TOKEN=`, `SECRET=`, `PASSWORD=` assignments with an entropy floor.

Providers whose keys have no distinctive prefix (Mistral, Together, Vercel, Twilio, Cloudflare) are matched only when the provider name appears in the variable or field name on the same line. This trades some recall for very few false positives.

Every rule has a positive and a negative test. The test suite fails if a rule is added without both. Test fixtures are assembled from fragments at run time, so the repository never contains a string that matches a rule.

## Limits and FAQ

**Does it phone home?** No. `verify` is the only command that makes network requests, it is off by default, and it talks only to the provider that issued each key.

**Will `fix` break my tools?** It has not in testing across Claude Code, Codex, Cursor and Gemini CLI fixtures, because the replacement text is a plain string and every record is validated after rewriting. If a record could not be redacted safely it is left alone and counted. Backups are kept until you delete them.

**Does redaction remove the secret from my provider?** No. A leaked key is a leaked key. Revoke it at the provider, then run `fix` so the old value stops spreading through backups and sync.

**Why did it miss my key?** Either the provider has no rule (open an issue with the documented format, never a real key), or the key has no prefix and the line did not name the provider. The `generic-api-key` rule needs an assignment shape and at least 3.5 bits per byte of entropy.

**Why is this false positive here?** Long random strings next to a word like `token` will match the generic rule. Use `--rule` to narrow a run, or `--min-severity high` to drop the generic and structural rules, which are medium.

**Can it stop MCP servers from reading secrets?** No. Hooks see the agent's built-in tools. A filesystem MCP server is a separate process with its own permissions.

**Does `guard` slow the agent down?** Each hook call is one process start and a few string comparisons, well under 10 ms.

**What about git history, Slack exports, or my Downloads folder?** `agentleaks scan <path>` works on any file or directory, but for git history use gitleaks or trufflehog, which are built for it.

**Windows?** The scanner and `fix` work on Windows and the paths are mapped to `%APPDATA%`. `guard` writes the same JSON config files, but the hook command paths have only been exercised on macOS and Linux.

**Why not import gitleaks as a library?** gitleaks v8.30 pulls in 204 Go modules and its config package alone depends on 271 packages including a WebAssembly RE2 shim. AgentLeaks has two direct dependencies: a TOML parser and a pure Go SQLite driver.

## Related projects

- [installwall](https://github.com/Arthur031221/installwall): Blocks a risky package install before an agent runs it. AgentLeaks cleans up a secret after it already leaked into a transcript. Different stage of the same problem.
- [cliffhanger](https://github.com/Arthur031221/cliffhanger): Keeps an unattended agent from stopping before the work is done. Worth pairing with AgentLeaks fix if it runs as part of a longer unattended job.
- [shiftgear](https://github.com/Arthur031221/shiftgear): Routes model and effort choices for the same coding agents whose history AgentLeaks scans.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: `go test ./...` must pass in under two minutes, `gofmt -l .` must print nothing, and no commit may contain a string that matches a rule.

## License

MIT, copyright 2026 Arthur.

[^1]: Method: AgentLeaks 0.1.0 with the 64 bundled rules, run on 2026-09-30 on a MacBook Air M5 (24 GB) with macOS 26, against the author's own home directory. Tools present: Claude Code, GitHub Copilot CLI and VS Code Copilot Chat. Codex, Cursor, Gemini CLI, Cline, Roo, OpenCode and Aider were not installed. First run, before this project's own sessions grew: 91 files, 36.6 MB, 0.97 s wall clock at load average 3, 8 hits, 3 distinct values. Final run: 100 files, 47.5 MB, 12 s wall clock at load average 62 with seven other builds running, 15 hits, 5 distinct values in 5 files. Reviewed by hand: one GitHub personal access token pasted into a Claude Code prompt (4 hits across `history.jsonl` and one transcript, the only real credential), one private key header in a transcript where the header regex was being discussed (3 hits, header only), and one AWS access key id plus two generic assignments that are this project's own test fixtures echoed into the build session's transcripts (8 hits). The GIF above uses a throwaway home built by `demo/setup.sh` with random keys, not this data.

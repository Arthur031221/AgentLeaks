# TODO

State on 2026-09-30: v0.1.0 is feature complete for the brief. Everything below is either an unverified assumption that needs a real install to confirm, a release step, or a hardening item. Each entry has the file to touch and what "done" means.

## Verified only against synthetic data

The scanner was exercised against real Claude Code, GitHub Copilot CLI and VS Code Copilot Chat data on the build machine. The other sources were verified against upstream source code and official docs, then tested with synthetic files. Confirm each on a real install:

1. Cursor `state.vscdb`. Files: `internal/sources/sources.go` (patterns), `internal/scan/sqlite.go`. Done when `agentleaks scan --tool cursor` on a machine with Cursor reports findings from `cursorDiskKV` rows keyed `bubbleId:*` and `composerData:*`, and `agentleaks fix --yes` on a copy leaves Cursor able to open the chat. Watch for `database is locked` while Cursor runs, which should be reported, not retried.
2. Codex sessions. Files: `internal/sources/sources.go`. The glob `.codex/sessions/**/*.jsonl` covers any date layout. Done when a real `~/.codex` scan lists `rollout-*.jsonl` and `history.jsonl` targets and `fix` keeps every line valid JSON. The `[hooks]` inline table form in `config.toml` is not written by `guard`, only `~/.codex/hooks.json`. Confirm Codex reads `hooks.json` (docs list both) or add TOML writing in `internal/guard/guard.go`.
3. Gemini CLI. Files: `internal/sources/sources.go`, `internal/guard/run.go`. Done when a real `~/.gemini/tmp/<hash>/chats/*.json` scan works and a `BeforeTool` hook installed by `guard` denies `read_file` on `.env` inside a real Gemini session (expect the reason to be shown to the model).
4. Cline and Roo Code task directories. Files: `internal/sources/sources.go`. Done when `<globalStorage>/saoudrizwan.claude-dev/tasks/*/api_conversation_history.json` from a real install is scanned and `fix` leaves the task openable in the extension.
5. OpenCode. Files: `internal/sources/sources.go`. The data dir `~/.local/share/opencode` comes from the docs, the `storage/session|message|part` layout from `packages/opencode/src/storage/storage.ts`. Done when a real install is scanned. If OpenCode has moved to `opencode.db`, the `*.db` pattern already covers it.
6. Aider, Continue, Windsurf, Claude Desktop. Files: `internal/sources/sources.go`. Paths come from docs. Done when each is confirmed on a real install. Windsurf now uses `~/.config/devin/mcp_config.json` per current docs, the legacy `~/.codeium/windsurf/mcp_config.json` is also listed.
7. Copilot CLI hooks. Files: `internal/guard/run.go`, `internal/guard/guard.go`. Tool names are undocumented, so `toolArgs` is inspected by key name. Done when a real Copilot CLI session with `~/.copilot/hooks/agentleaks.json` installed denies a shell `cat .env` and a file view of `.env`.
8. Claude Code PostToolUse scrubbing. Files: `internal/guard/run.go`. Implemented per the hooks reference (`hookSpecificOutput.updatedToolOutput`). Done when a real Claude Code session shows `[REDACTED:...]` in the transcript after the agent runs `cat .env` with the guard installed. If the field name differs in the shipped version, adjust `run.go` and the test in `internal/guard/guard_test.go`.

## Tests still to add

9. If `internal/fix/fix_test.go`, `internal/output/output_test.go` or `internal/cli/cli_test.go` are missing when you read this, write them following the plan in `CONTRIBUTING.md`: JSONL validity after redaction, backup mirroring, mtime preserved, SQLite blob type preserved, JSON and SARIF decode, CLI exit codes 0, 1 and 2. Build every fixture from fragments, never a literal that matches a rule. Done when `go test ./...` passes under two minutes with those packages covered.
10. Large file check. Files: `internal/scan/scan.go` (`ReadLines`). Generate a 1.2 GB JSONL with one secret near the end (do this outside the repo, do not commit it), run `agentleaks scan <file>` and confirm resident memory stays under 200 MB and the finding is reported. Done when noted in `CHANGELOG.md`.

## Release

11. Create the GitHub repository `Arthur031221/agentleaks`, push `main`, confirm the CI workflow in `.github/workflows/ci.yml` is green on ubuntu and macos.
12. Tag `v0.1.0`. `.github/workflows/release.yml` runs goreleaser and attaches archives for darwin, linux and windows on amd64 and arm64 plus `checksums.txt`.
13. Homebrew: create `Arthur031221/homebrew-tap`, copy `packaging/homebrew/agentleaks.rb` to `Formula/agentleaks.rb`, replace the four `REPLACE_WITH_SHA256_FROM_checksums.txt` values from the release, then un-comment the `brews:` block in `.goreleaser.yaml` and the tap token step in `release.yml` so future releases update it. Done when `brew install Arthur031221/tap/agentleaks && agentleaks version` works, then update the Install section of `README.md`.
14. npm: `packaging/npm` is a wrapper that downloads the release archive in `postinstall`. After the release exists, run `cd packaging/npm && npm install && node bin/agentleaks.js version`, then `npm publish`. Done when `npx agentleaks version` works, then update `README.md`.
15. Demo GIF. If `demo/demo.gif` is missing: `go build -o dist/agentleaks ./cmd/agentleaks && vhs demo/demo.tape` (vhs, ttyd and ffmpeg via Homebrew). The tape builds its own fixture home with `demo/setup.sh`, so no real history is recorded.

## Hardening

16. `verify` has only been tested against httptest servers. Run `agentleaks verify --yes` once with a revoked key per provider to confirm the dead path, and note any provider whose endpoint has changed. Files: `internal/verify/verify.go`.
17. Windows `guard`. Files: `internal/guard/guard.go`. The config paths map to `%USERPROFILE%`, but the hook command quoting for paths with spaces has only been checked on macOS. Done when `agentleaks guard` on Windows writes a hook that Claude Code executes.
18. Gemini `AfterTool` and Copilot `postToolUse` output scrubbing are not implemented because the docs do not describe an output rewrite field. Add them in `internal/guard/run.go` if a documented field appears.
19. MCP tool interception is out of scope for hooks in every tool. Document only, no code.
20. Rule review. `internal/rules/rules.toml` entries for Doppler, Notion, Linear, Sentry and Tailscale were written from remembered prefixes. Spot check each against the provider's current docs and adjust the regex plus the fixtures in `internal/rules/rules_test.go`.

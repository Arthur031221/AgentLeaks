# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Match Doppler token formats and recognize identity, SCIM and audit tokens.

## [0.1.0] - 2026-09-30

### Added

- `scan` across Claude Code, Codex, Cursor, Gemini CLI, Cline, Roo Code, OpenCode, Aider, GitHub Copilot CLI, VS Code Copilot Chat, Claude Desktop, Windsurf and Continue. Session transcripts, prompt history, MCP and settings files, edited file snapshots and SQLite chat stores are all covered. Arbitrary files and directories can be scanned with `scan <path>`.
- 64 detection rules covering OpenAI, Anthropic, AWS, GitHub, GitLab, Stripe, Slack, Google, Hugging Face, Groq, Mistral, OpenRouter, Together, Replicate, Vercel, Supabase, Twilio, SendGrid, npm, PyPI, private key blocks, JWTs, database connection strings and generic high entropy assignments. A keyword prefilter runs before any regular expression and an entropy floor cuts placeholder values.
- Streaming line reader that handles files over 1 GB without loading them fully, with parallel workers per file.
- `fix` redacts in place with `[REDACTED:<rule>]` markers. JSONL records, JSON documents and SQLite rows stay valid. Originals are copied to `~/.agentleaks/backups/<timestamp>` first. Dry run by default, `--yes` to apply.
- `guard` installs hooks for Claude Code, Codex, Cursor, Gemini CLI and GitHub Copilot CLI that deny reads of `.env` files, key files, cloud credentials and the tools' own config. Claude Code also gets a PostToolUse hook that redacts secrets from tool output before they reach the transcript. `guard --coverage` prints what each hook system can and cannot block.
- `verify` checks whether a found key is still live for 14 providers, using each provider's read-only endpoint only. Off by default and behind an explicit consent notice.
- `report --json` and `report --sarif` for machine readable output. Exit code 1 when secrets are found, for CI use.
- Static binaries without cgo for macOS (arm64 and amd64), Linux (arm64 and amd64) and Windows (arm64 and amd64), a Homebrew formula template and an npm wrapper package.

[0.1.0]: https://github.com/Arthur031221/agentleaks/releases/tag/v0.1.0

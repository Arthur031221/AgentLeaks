# Contributing

Thanks for taking the time. The project is small on purpose. Keep changes focused and tested.

## Build

You need Go 1.27 or newer. There is no cgo, so a plain build gives a static binary.

```sh
go build ./cmd/agentleaks
./agentleaks version
```

## Test and lint

```sh
go test ./...
gofmt -l .
go vet ./...
```

`gofmt -l .` must print nothing and `go vet` must be clean. CI runs both on every push and pull request. The whole test suite must finish in under two minutes, so keep new tests small and avoid network calls (use `httptest` where a server is needed).

## Never commit a real-looking secret

The repository is meant to pass GitHub push protection and its own scanner. Do not put a string that matches any rule in `internal/rules/rules.toml` into source, tests, docs or fixtures. Test fixtures are built at run time from fragments, for example `"ghp_" + strings.Repeat("a1", 18)`. If you need a sample in documentation, mask it.

## Adding a detection rule

1. Add a `[[rules]]` block to `internal/rules/rules.toml`. Each rule needs an `id`, `provider`, `description`, `regex` (RE2, no lookarounds) and at least one `keywords` entry. Use `group`, `entropy`, `allowlist`, `severity` and `verify` where they help.
2. Rule order matters. When two rules match overlapping bytes the earlier rule wins, so put provider-specific rules before generic ones.
3. Add a positive and a negative case to `internal/rules/rules_test.go`. The suite fails if any rule id lacks either one, and it checks that every keyword appears in a positive fixture.
4. If the provider has a safe read-only endpoint, add a prober in `internal/verify` and reference it in the rule's `verify` field.

## Adding a source

Sources live in the `Registry` in `internal/sources/sources.go`. A tool is a list of patterns, each with a base (`home`, `xdgconfig`, `xdgdata`, `appdata`, `vscode` or `repo`), a glob that may use `**`, a kind (`jsonl`, `json`, `text` or `sqlite`), a label and an optional `Credential` flag for the tool's own credential store. Verify the real on-disk layout from the tool's documentation or source before adding it, and add a discovery test with a synthetic home directory.

## Adding a hook adapter

Hook adapters live in `internal/guard`. Each tool needs the config file it reads, the event names it supports, the shape of the JSON it sends on stdin and the deny protocol it expects on stdout or via exit code. Implement only what the tool documents and describe the gaps in the `Coverage` notes. Add round-trip tests for install, uninstall and the deny and allow paths.

## Pull requests

- One change per pull request.
- Update `CHANGELOG.md` under an Unreleased heading.
- Plain engineer prose in docs and help text. Short sentences, no decoration.

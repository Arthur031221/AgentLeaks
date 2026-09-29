# agentleaks npm wrapper

This package is a thin wrapper. On install it downloads the matching agentleaks release binary from GitHub Releases, verifies its sha256 against the release checksums and places it in `bin/`.

It is not published to the npm registry yet. Publish it after the first GitHub release exists, since the postinstall step needs the release assets.

Set `AGENTLEAKS_BINARY` to use a binary you built yourself, or `AGENTLEAKS_SKIP_DOWNLOAD=1` to skip the download.

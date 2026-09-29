# Homebrew formula

`agentleaks.rb` is a template for a tap. It is not in Homebrew core.

After a GitHub release is published, download `checksums.txt` from the release and copy the sha256 for each archive into the matching `sha256` line. Bump `version` when releasing a new tag.

Create a repository named `homebrew-tap` under the `Arthur031221` account, put the formula at `Formula/agentleaks.rb` and push. Users then run `brew install Arthur031221/tap/agentleaks`.

#!/usr/bin/env bash
# Builds a throwaway home directory full of fake AI tool history for the demo.
# Every key is assembled from fragments and random bytes at run time, so this
# file never contains a string that matches a detection rule.
set -euo pipefail

home="$(mktemp -d "${TMPDIR:-/tmp}/agentleaks-demo.XXXXXX")"

rand() { # rand <n> <charset>
  # head closes the pipe early, which is fine here, so pipefail is off.
  ( set +o pipefail; LC_ALL=C tr -dc "$2" </dev/urandom | head -c "$1" )
}
alnum='A-Za-z0-9'

openai="sk-""proj-$(rand 74 "$alnum")"
anthropic="sk-""ant-api03-$(rand 93 "${alnum}_-")AA"
github="ghp_$(rand 36 "$alnum")"
aws_id="AKIA$(rand 16 'A-Z0-9')"
aws_secret="$(rand 40 "${alnum}/+")"
slack="xoxb-$(rand 12 '0-9')-$(rand 12 '0-9')-$(rand 24 "$alnum")"
stripe="sk_""live_$(rand 32 "$alnum")"
google="AIza$(rand 35 "${alnum}_-")"
hf="hf_$(rand 34 "$alnum")"

# Claude Code: a session transcript where the agent ran cat .env, and the
# prompt history where a token was pasted.
proj="$home/.claude/projects/-Users-demo-shop"
mkdir -p "$proj"
cat >"$proj/9c1d2e3f-demo.jsonl" <<EOF
{"type":"user","message":{"role":"user","content":"set up the payment webhook, the config is in .env"},"uuid":"u1","timestamp":"2026-09-28T09:12:01Z","cwd":"/Users/demo/shop","sessionId":"9c1d2e3f"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_01","name":"Bash","input":{"command":"cat .env"}}]},"uuid":"a1","timestamp":"2026-09-28T09:12:03Z","sessionId":"9c1d2e3f"}
{"type":"user","message":{"role":"user","content":[{"tool_use_id":"toolu_01","type":"tool_result","content":"OPENAI_API_KEY=$openai\nSTRIPE_SECRET_KEY=$stripe\nAWS_ACCESS_KEY_ID=$aws_id\nAWS_SECRET_ACCESS_KEY=$aws_secret\n"}]},"uuid":"u2","timestamp":"2026-09-28T09:12:03Z","sessionId":"9c1d2e3f"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"I have the Stripe key $stripe, wiring the webhook now."}]},"uuid":"a2","timestamp":"2026-09-28T09:12:09Z","sessionId":"9c1d2e3f"}
EOF
cat >"$home/.claude/history.jsonl" <<EOF
{"display":"use this token for the release: $github","pastedContents":{},"timestamp":1790000000000,"project":"/Users/demo/shop","sessionId":"9c1d2e3f"}
{"display":"run the tests","pastedContents":{},"timestamp":1790000100000,"project":"/Users/demo/shop","sessionId":"9c1d2e3f"}
EOF

# Codex: a rollout with an Anthropic key in a shell output.
codex="$home/.codex/sessions/2026/09/28"
mkdir -p "$codex"
cat >"$codex/rollout-2026-09-28T10-01-00-demo.jsonl" <<EOF
{"timestamp":"2026-09-28T10:01:00Z","type":"session_meta","payload":{"id":"demo","cwd":"/Users/demo/agent"}}
{"timestamp":"2026-09-28T10:01:05Z","type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"ANTHROPIC_API_KEY=$anthropic\n"}}
EOF

# Cursor: MCP config with a Slack token, plus a chat store if sqlite3 exists.
mkdir -p "$home/.cursor"
cat >"$home/.cursor/mcp.json" <<EOF
{
  "mcpServers": {
    "slack": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-slack"], "env": {"SLACK_BOT_TOKEN": "$slack"}}
  }
}
EOF
if command -v sqlite3 >/dev/null 2>&1; then
  gs="$home/Library/Application Support/Cursor/User/globalStorage"
  mkdir -p "$gs"
  sqlite3 "$gs/state.vscdb" "CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB); CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB);
INSERT INTO cursorDiskKV VALUES ('bubbleId:demo:1', '{\"type\":1,\"text\":\"here is the HF token: $hf\"}');
INSERT INTO cursorDiskKV VALUES ('bubbleId:demo:2', '{\"type\":2,\"text\":\"Got it, downloading the model.\"}');"
fi

# Gemini CLI: a saved chat with a Google API key.
gem="$home/.gemini/tmp/demo/chats"
mkdir -p "$gem"
cat >"$gem/session-2026-09-28.json" <<EOF
{"sessionId":"demo","messages":[{"role":"user","content":"the key is $google, add it to settings"}]}
EOF

# Aider: chat history in a project folder.
mkdir -p "$home/Desktop/shop"
cat >"$home/Desktop/shop/.aider.chat.history.md" <<EOF
# aider chat started at 2026-09-27 18:02:11

#### deploy with the same webhook, STRIPE key is $stripe
EOF

echo "$home"

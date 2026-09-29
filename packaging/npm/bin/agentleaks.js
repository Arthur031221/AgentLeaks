#!/usr/bin/env node
"use strict";

// Thin launcher: runs the platform binary downloaded by install.js.

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

function binaryPath() {
  if (process.env.AGENTLEAKS_BINARY) {
    return process.env.AGENTLEAKS_BINARY;
  }
  const osMap = { darwin: "darwin", linux: "linux", win32: "windows" };
  const archMap = { x64: "amd64", arm64: "arm64" };
  const goos = osMap[process.platform];
  const goarch = archMap[process.arch];
  if (!goos || !goarch) {
    return null;
  }
  const name = `agentleaks-${goos}-${goarch}${goos === "windows" ? ".exe" : ""}`;
  return path.join(__dirname, name);
}

const bin = binaryPath();
if (!bin || !fs.existsSync(bin)) {
  console.error(
    "agentleaks: binary not found. Run `npm rebuild agentleaks` or download it from " +
      "https://github.com/Arthur031221/agentleaks/releases"
  );
  process.exit(2);
}

const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
child.on("error", (err) => {
  console.error("agentleaks: failed to start binary: " + err.message);
  process.exit(2);
});
child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 2 : code);
});

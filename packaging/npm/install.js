#!/usr/bin/env node
"use strict";

// Downloads the agentleaks release binary for this platform into bin/.
// Runs as the npm postinstall step. Standard library only.

const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const { spawnSync } = require("child_process");

const pkg = require("./package.json");
const REPO = "Arthur031221/agentleaks";
const VERSION = pkg.version;
const BIN_DIR = path.join(__dirname, "bin");

function platformInfo() {
  const osMap = { darwin: "darwin", linux: "linux", win32: "windows" };
  const archMap = { x64: "amd64", arm64: "arm64" };
  const goos = osMap[process.platform];
  const goarch = archMap[process.arch];
  if (!goos || !goarch) {
    throw new Error(
      `agentleaks: no prebuilt binary for ${process.platform}/${process.arch}. ` +
        "Build from source with `go install github.com/Arthur031221/agentleaks/cmd/agentleaks@latest`."
    );
  }
  const ext = goos === "windows" ? "zip" : "tar.gz";
  const archive = `agentleaks_${VERSION}_${goos}_${goarch}.${ext}`;
  const binaryName = `agentleaks-${goos}-${goarch}${goos === "windows" ? ".exe" : ""}`;
  return { goos, goarch, ext, archive, binaryName };
}

function fetch(url, redirects) {
  redirects = redirects || 0;
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      { headers: { "User-Agent": "agentleaks-npm/" + VERSION } },
      (res) => {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400 && res.headers.location) {
          res.resume();
          if (redirects > 8) {
            reject(new Error("too many redirects for " + url));
            return;
          }
          const next = new URL(res.headers.location, url).toString();
          resolve(fetch(next, redirects + 1));
          return;
        }
        if (status === 404) {
          res.resume();
          reject(
            new Error(
              `release asset not found: ${url}\n` +
                `There is no published release v${VERSION} yet, or it lacks this platform. ` +
                "Check https://github.com/" + REPO + "/releases."
            )
          );
          return;
        }
        if (status !== 200) {
          res.resume();
          reject(new Error(`download failed with HTTP ${status}: ${url}`));
          return;
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      }
    );
    req.on("error", reject);
  });
}

function expectedSha(checksums, archive) {
  const lines = checksums.toString("utf8").split(/\r?\n/);
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 2 && parts[parts.length - 1].replace(/^\*/, "") === archive) {
      return parts[0].toLowerCase();
    }
  }
  return null;
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function extractTarGz(archivePath, outPath) {
  const tar = spawnSync("tar", ["--version"], { stdio: "ignore" });
  if (tar.error || tar.status !== 0) {
    throw new Error("`tar` is required to extract the release archive but was not found on PATH.");
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agentleaks-"));
  const res = spawnSync("tar", ["-xzf", archivePath, "-C", tmp, "agentleaks"], { stdio: "inherit" });
  if (res.status !== 0) {
    throw new Error("tar failed to extract " + archivePath);
  }
  fs.copyFileSync(path.join(tmp, "agentleaks"), outPath);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// Minimal zip reader: finds the entry named agentleaks.exe through the
// central directory and inflates it. Supports stored (0) and deflate (8).
function extractZipEntry(buf, wantName) {
  const EOCD = 0x06054b50;
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) {
    throw new Error("zip: end of central directory not found");
  }
  const entries = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < entries; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) {
      throw new Error("zip: bad central directory entry");
    }
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;
    if (path.posix.basename(name) !== wantName) {
      continue;
    }
    if (buf.readUInt32LE(localOff) !== 0x04034b50) {
      throw new Error("zip: bad local file header");
    }
    const lNameLen = buf.readUInt16LE(localOff + 26);
    const lExtraLen = buf.readUInt16LE(localOff + 28);
    const dataStart = localOff + 30 + lNameLen + lExtraLen;
    const data = buf.subarray(dataStart, dataStart + compSize);
    if (method === 0) {
      return Buffer.from(data);
    }
    if (method === 8) {
      return zlib.inflateRawSync(data);
    }
    throw new Error("zip: unsupported compression method " + method);
  }
  return null;
}

function extractZip(archivePath, outPath) {
  const buf = fs.readFileSync(archivePath);
  let data = null;
  try {
    data = extractZipEntry(buf, "agentleaks.exe");
  } catch (err) {
    data = null;
  }
  if (data) {
    fs.writeFileSync(outPath, data);
    return;
  }
  // Fall back to PowerShell when the archive uses a feature the small
  // reader above does not handle.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agentleaks-"));
  const res = spawnSync(
    "powershell",
    ["-NoProfile", "-Command", `Expand-Archive -LiteralPath '${archivePath}' -DestinationPath '${tmp}' -Force`],
    { stdio: "inherit" }
  );
  if (res.status !== 0) {
    throw new Error("could not extract " + archivePath);
  }
  fs.copyFileSync(path.join(tmp, "agentleaks.exe"), outPath);
  fs.rmSync(tmp, { recursive: true, force: true });
}

async function main() {
  if (process.env.AGENTLEAKS_SKIP_DOWNLOAD === "1") {
    console.log("agentleaks: AGENTLEAKS_SKIP_DOWNLOAD=1, not downloading a binary.");
    return;
  }
  if (process.env.AGENTLEAKS_BINARY) {
    console.log("agentleaks: using AGENTLEAKS_BINARY=" + process.env.AGENTLEAKS_BINARY);
    return;
  }
  const info = platformInfo();
  const outPath = path.join(BIN_DIR, info.binaryName);
  if (fs.existsSync(outPath)) {
    return;
  }
  const base = `https://github.com/${REPO}/releases/download/v${VERSION}/`;
  console.log(`agentleaks: downloading ${info.archive}`);
  const [archive, checksums] = await Promise.all([fetch(base + info.archive), fetch(base + "checksums.txt")]);
  const want = expectedSha(checksums, info.archive);
  if (!want) {
    throw new Error(`checksums.txt in release v${VERSION} has no entry for ${info.archive}`);
  }
  const got = sha256(archive);
  if (got !== want) {
    throw new Error(`sha256 mismatch for ${info.archive}: expected ${want}, got ${got}`);
  }
  fs.mkdirSync(BIN_DIR, { recursive: true });
  const archivePath = path.join(os.tmpdir(), info.archive);
  fs.writeFileSync(archivePath, archive);
  try {
    if (info.ext === "zip") {
      extractZip(archivePath, outPath);
    } else {
      extractTarGz(archivePath, outPath);
    }
  } finally {
    fs.rmSync(archivePath, { force: true });
  }
  fs.chmodSync(outPath, 0o755);
  console.log("agentleaks: installed " + outPath);
}

main().catch((err) => {
  console.error(err && err.message ? err.message : String(err));
  process.exit(1);
});

#!/usr/bin/env node
// Resolve the precompiled Rust binary for this platform and exec it,
// forwarding args + stdio. Falls back to cargo run in a source checkout.
const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const plat = process.platform; // darwin | linux | win32
const arch = process.arch;     // x64 | arm64
const ext = plat === "win32" ? ".exe" : "";
const name = `4ward-${plat}-${arch}${ext}`;

// Launch a candidate and exit with its exit status (a signal kill maps to a
// non-zero status). If the process could not be spawned at all (missing,
// EACCES, ENOEXEC, ...), return the error so the caller can try the next
// resolution step instead of silently exiting 0.
function launch(cmd, args, opts) {
  const r = spawnSync(cmd, args, { stdio: "inherit", ...opts });
  if (r.error) return r.error;
  process.exit(r.status ?? 1);
}

const candidates = [
  path.join(__dirname, "..", "binaries", name),
  path.join(__dirname, "..", "target", "release", `4ward${ext}`),
];

for (const c of candidates) {
  if (fs.existsSync(c)) launch(c, process.argv.slice(2));
}

// Source checkout without a built binary: try cargo run.
const err = launch(
  "cargo",
  ["run", "-q", "-p", "fourward-cli", "--", ...process.argv.slice(2)],
  { cwd: path.join(__dirname, "..") },
);
console.error(`4ward: no prebuilt binary (${name}) and the cargo fallback failed: ${err.message}`);
console.error("4ward: install Rust via https://rustup.rs and run 'cargo build --release -p fourward-cli', or retry once the GitHub release asset is published.");
process.exit(1);

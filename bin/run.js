#!/usr/bin/env node
// Resolve the precompiled Rust binary for this platform and exec it,
// forwarding args + stdio. Falls back to cargo run in a source checkout.
const { execFileSync, spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const plat = process.platform; // darwin | linux | win32
const arch = process.arch;     // x64 | arm64
const ext = plat === "win32" ? ".exe" : "";
const name = `4ward-${plat}-${arch}${ext}`;

const candidates = [
  path.join(__dirname, "..", "binaries", name),
  path.join(__dirname, "..", "target", "release", `4ward${ext}`),
  path.join(__dirname, "4ward"),
];

for (const c of candidates) {
  if (fs.existsSync(c)) {
    const r = spawnSync(c, process.argv.slice(2), { stdio: "inherit" });
    process.exit(r.status ?? 0);
  }
}

// Source checkout without a built binary: try cargo run.
try {
  const r = spawnSync("cargo", ["run", "-q", "-p", "fourward-cli", "--", ...process.argv.slice(2)], {
    stdio: "inherit",
    cwd: path.join(__dirname, ".."),
  });
  process.exit(r.status ?? 0);
} catch (e) {
  console.error(`4ward: no prebuilt binary (${name}) and cargo fallback failed: ${e.message}`);
  process.exit(1);
}

// postinstall: download the matching release binary from GitHub into ./binaries/.
const https = require("https");
const fs = require("fs");
const path = require("path");

const VERSION = require("../package.json").version;
const plat = process.platform;
const arch = process.arch;
const ext = plat === "win32" ? ".exe" : "";
const asset = `4ward-${plat}-${arch}${ext}`;
const url = `https://github.com/tljohnsilver/4ward/releases/download/v${VERSION}/${asset}`;
const dest = path.join(__dirname, "..", "binaries", asset);

if (fs.existsSync(dest)) process.exit(0);
if (process.env.FOURWARD_SKIP_DOWNLOAD) {
  console.log("4ward: skipping binary download (FOURWARD_SKIP_DOWNLOAD set)");
  process.exit(0);
}
fs.mkdirSync(path.dirname(dest), { recursive: true });
console.log(`4ward: downloading ${url}`);
https.get(url, (res) => {
  if (res.statusCode !== 200) {
    console.log(`4ward: no prebuilt binary yet (${res.statusCode}); use source via cargo. Skipping.`);
    res.resume();
    return;
  }
  const out = fs.createWriteStream(dest, { mode: 0o755 });
  res.pipe(out);
  out.on("finish", () => { fs.chmodSync(dest, 0o755); console.log("4ward: binary installed"); });
}).on("error", (e) => console.log(`4ward: download skipped: ${e.message}`));

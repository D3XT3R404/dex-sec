#!/usr/bin/env node
/**
 * DEX-SEC npm wrapper.
 *
 * The heavy lifting is done by the Python implementation of DEX-SEC. This
 * wrapper only makes sure the Python package is available and then forwards
 * every argument to it, so `dexsec scan --path .` behaves identically whether
 * it is started from a shell, an npm script, or a CI job.
 */

const { spawn, spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const PYTHON = process.platform === "win32" ? "python" : "python3";
const PROJECT_ROOT = path.resolve(__dirname, "..", "..");
const PACKAGE_DIR = path.join(PROJECT_ROOT, "dexsec");

function hasDexSec() {
  const probe = spawnSync(PYTHON, ["-c", "import dexsec"], { stdio: "ignore" });
  return probe.status === 0;
}

function installDexSec() {
  console.log("[dexsec] Installing the DEX-SEC python package...");
  const result = spawnSync(PYTHON, ["-m", "pip", "install", PROJECT_ROOT], { stdio: "inherit" });
  return result.status === 0;
}

function main() {
  const args = process.argv.slice(2);

  if (args[0] === "--check-python") {
    const version = spawnSync(PYTHON, ["--version"], { encoding: "utf8" });
    if (version.status !== 0) {
      console.error("[dexsec] Python 3.10+ is required but was not found on PATH.");
      process.exit(1);
    }
    console.log("[dexsec] " + (version.stdout || version.stderr).trim());
    process.exit(0);
  }

  if (!hasDexSec() && !installDexSec()) {
    console.error("[dexsec] Could not install the DEX-SEC python package.");
    console.error("[dexsec] Try manually: " + PYTHON + " -m pip install " + PROJECT_ROOT);
    process.exit(1);
  }

  const child = spawn(PYTHON, ["-m", "dexsec", ...args], {
    stdio: "inherit",
    env: { ...process.env, PYTHONPATH: [PACKAGE_DIR, process.env.PYTHONPATH].filter(Boolean).join(path.delimiter) },
  });
  child.on("exit", (code) => process.exit(code === null ? 1 : code));
}

main();

// End-to-end check that the build you launch is the build you get.
//
// An older copy is left running from what looks to it like a different folder, a
// newer one is launched with `--take-over`, and the newer one has to close the older
// one and come up in its place. Run it with `npm run e2e`; a virtual display is
// required on headless machines (`xvfb-run -a node test/e2e/takeover.mjs`).

import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";

const repository = path.resolve(import.meta.dirname, "..", "..");
const distribution = path.join(repository, "node_modules", "electron", "dist");
const electron = path.join(distribution, "electron");
// A second folder holding the same executable, which is exactly what extracting a
// new release beside an old one produces. Hard links make it free and keep the two
// genuinely distinct paths, so the check runs against the comparison that ships
// rather than against a stand-in for it.
const secondCopy = path.join(repository, "node_modules", ".e2e-second-copy");
const cleanups = [];

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.on("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

async function waitForWindow(port, what, timeout = 30000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`);
      const targets = await response.json();
      if (targets.some((target) => target.type === "page" && target.webSocketDebuggerUrl)) return true;
    } catch { /* nothing is listening yet */ }
    await delay(200);
  }
  throw new Error(`${what} never opened a window on port ${port}`);
}

// The process that took over is not a child of this test — it was started by the
// copy that exited — so it is found the way the application finds its own kind.
function processesUsing(marker) {
  const found = [];
  for (const entry of fs.readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const commandLine = fs.readFileSync(path.join("/proc", entry, "cmdline"), "utf8");
      if (commandLine.includes(marker)) found.push(Number(entry));
    } catch { /* gone, or another user's */ }
  }
  return found;
}

async function main() {
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-e2e-takeover-"));
  cleanups.push(() => fs.rmSync(userData, { recursive: true, force: true }));
  // Whatever is left holding the profile at the end is this test's to clean up.
  cleanups.push(() => {
    for (const pid of processesUsing(userData)) {
      try { process.kill(pid, "SIGKILL"); } catch { /* already gone */ }
    }
  });

  fs.rmSync(secondCopy, { recursive: true, force: true });
  cleanups.push(() => fs.rmSync(secondCopy, { recursive: true, force: true }));
  try {
    execFileSync("cp", ["-al", distribution, secondCopy]);
  } catch {
    fs.cpSync(distribution, secondCopy, { recursive: true });
  }

  const oldPort = await freePort();
  const newPort = await freePort();

  // The copy already running. Nothing marks it as old: what matters is that it runs
  // from a different folder, which is what an earlier release extracted to its own
  // folder is.
  const running = spawn(electron, [".", `--user-data-dir=${userData}`, `--remote-debugging-port=${oldPort}`], {
    cwd: repository,
    stdio: "ignore",
  });
  const runningExit = new Promise((resolve) => running.on("exit", (code, signal) => resolve({ code, signal })));
  await waitForWindow(oldPort, "the copy already running");
  console.log("• a copy is running and holds the profile");

  // The build the user just launched, from its own folder, told not to ask.
  const launched = spawn(path.join(secondCopy, "electron"), [
    ".", `--user-data-dir=${userData}`, `--remote-debugging-port=${newPort}`, "--take-over",
  ], {
    cwd: repository,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const output = [];
  launched.stdout.on("data", (chunk) => output.push(String(chunk)));
  launched.stderr.on("data", (chunk) => output.push(String(chunk)));
  const launchedExit = await Promise.race([
    new Promise((resolve) => launched.on("exit", (code) => resolve(code))),
    delay(30000).then(() => "still running"),
  ]);
  assert.equal(launchedExit, 0,
    `the launched copy should close the other and hand over to its relaunch (output: ${output.join("")})`);

  const closed = await Promise.race([runningExit, delay(20000).then(() => null)]);
  assert.ok(closed, "the copy that was running should have been closed");
  console.log(`• the copy that was running was closed (${closed.signal || `exit ${closed.code}`})`);

  // The relaunch carries the same arguments, so the build that took over answers on
  // the port the launch asked for. That is the whole point: the window now on screen
  // belongs to the copy that was launched.
  await waitForWindow(newPort, "the copy that took over");
  console.log("• the launched copy took its place and opened the window");

  // And it is alone: the profile is held by one process only.
  const response = await fetch(`http://127.0.0.1:${newPort}/json/list`);
  const targets = (await response.json()).filter((target) => target.type === "page");
  assert.equal(targets.length, 1, "the copy that took over should serve exactly one window");
  let servedByOld = true;
  try {
    await fetch(`http://127.0.0.1:${oldPort}/json/list`);
  } catch {
    servedByOld = false;
  }
  assert.equal(servedByOld, false, "the older copy's debugging port should be gone with it");
  console.log("• only the launched copy is left running");
}

main()
  .then(() => console.log("\ntakeover checks passed"))
  .catch((error) => {
    process.exitCode = 1;
    console.error(`\n${error?.stack || error}`);
  })
  .finally(async () => {
    for (const clean of cleanups.reverse()) {
      try { await clean(); } catch { /* nothing left to do about it */ }
    }
  });

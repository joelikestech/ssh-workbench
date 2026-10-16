// End-to-end check that the master password behaves as one vault across windows.
//
// One process holds the vault, so setting, unlocking and locking it in one window
// has to be the same in every other one. Two windows are opened before a master
// password exists; it is set in the first, which the second has to hear about (its
// Ctrl+Shift+L used to do nothing, as it still thought no master password was set).
// A saved connection chosen in the second window must put nothing secret in its
// form, and after a lock from either window, connecting from the other has to ask
// for the master password again rather than connect with what it was holding. Run
// it with `npm run e2e`; a virtual display is required on headless machines
// (`xvfb-run -a node test/e2e/vault-windows.mjs`).

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { startTestServer } = require("../helpers/ssh-test-server.js");
const { utils } = require("ssh2");

const repository = path.resolve(import.meta.dirname, "..", "..");
const MASTER = "master-password-for-e2e";
const cleanups = [];

function onCleanup(run) { cleanups.push(run); }

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

function fingerprint(publicKey) {
  const parsed = utils.parseKey(publicKey);
  return crypto.createHash("sha256").update(parsed.getPublicSSH()).digest("hex");
}

async function pageTargets(port) {
  const response = await fetch(`http://127.0.0.1:${port}/json/list`);
  return (await response.json()).filter((target) => target.type === "page" && target.webSocketDebuggerUrl);
}

async function openDevtools(port) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`);
      const targets = await response.json();
      const page = targets.find((target) => target.type === "page" && target.webSocketDebuggerUrl);
      if (page) return page.webSocketDebuggerUrl;
    } catch { /* the browser is still starting */ }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error("The application never exposed a DevTools page target");
}

async function connectDevtools(url) {
  const socket = new WebSocket(url);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("DevTools socket failed")), { once: true });
  });
  const pending = new Map();
  let nextId = 0;
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result);
    }
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  await send("Runtime.enable");
  onCleanup(() => socket.close());
  return { send };
}

async function evaluate(session, expression) {
  const result = await session.send("Runtime.evaluate", {
    expression: `(async () => { const $ = (id) => document.getElementById(id); ${expression} })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
  }
  return result.result.value;
}

async function state(session) {
  return evaluate(session, `
    return {
      view: $("connect-view").classList.contains("hidden") ? "workspace" : "connect",
      connectMessage: $("connect-message").textContent,
      tabs: document.querySelectorAll("#tabstrip .tab").length,
      label: $("connection-label").textContent,
      modal: !$("modal-backdrop").classList.contains("hidden"),
    };
  `);
}

async function waitFor(session, expression, label, timeout = 20000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    try {
      last = await evaluate(session, `return ${expression};`);
      if (last) return last;
    } catch { /* not built yet */ }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`Timed out waiting for ${label} (last: ${JSON.stringify(last)})\nstate: ${JSON.stringify(await state(session).catch(() => null))}`);
}

async function main() {
  const remoteRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-e2e-remote-"));
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-e2e-vault-"));
  onCleanup(() => fs.rmSync(remoteRoot, { recursive: true, force: true }));
  onCleanup(() => fs.rmSync(userData, { recursive: true, force: true }));
  fs.writeFileSync(path.join(remoteRoot, "readme.txt"), "hello\n");
  const server = await startTestServer({ root: remoteRoot, password: "staging-secret" });
  onCleanup(() => server.close());
  fs.writeFileSync(path.join(userData, "known-hosts.json"), JSON.stringify({
    version: 1,
    hosts: { [`${server.host}:${server.port}`]: { sha256: fingerprint(server.hostPublicKey) } },
  }));

  const debugPort = await freePort();
  const electron = spawn(
    path.join(repository, "node_modules", ".bin", "electron"),
    [".", `--remote-debugging-port=${debugPort}`, `--user-data-dir=${userData}`],
    { cwd: repository, stdio: ["ignore", "pipe", "pipe"] },
  );
  const output = [];
  electron.stdout.on("data", (chunk) => output.push(String(chunk)));
  electron.stderr.on("data", (chunk) => output.push(String(chunk)));
  onCleanup(() => { if (!electron.killed) electron.kill("SIGKILL"); });
  onCleanup(() => { if (process.exitCode) console.error(`\napplication output:\n${output.join("")}`); });

  const first = await connectDevtools(await openDevtools(debugPort));
  await waitFor(first, `$("credential-storage").textContent.length > 0`, "the first window to start");

  // The second window exists before any master password does.
  const known = new Set((await pageTargets(debugPort)).map((target) => target.id));
  await evaluate(first, `await window.sshWorkbench.windows.create(); return true;`);
  let target = null;
  for (let attempt = 0; attempt < 50 && !target; attempt += 1) {
    target = (await pageTargets(debugPort)).find((candidate) => !known.has(candidate.id));
    if (!target) await new Promise((resolve) => setTimeout(resolve, 200));
  }
  assert.ok(target, "a second window opened");
  const second = await connectDevtools(target.webSocketDebuggerUrl);
  await waitFor(second, `$("credential-storage").textContent.length > 0`, "the second window to start");

  // Set in the first window; the second hears of it without being asked.
  await evaluate(first, `
    await window.sshWorkbench.vault.set(${JSON.stringify(MASTER)}, { mode: "minutes", minutes: 15 });
    return true;
  `);
  await waitFor(second, `!$("master-lock").classList.contains("hidden")`, "the second window to learn a master password is set");
  console.log("• a master password set in one window is known to a window opened before it");

  // Saved through the form, with its password.
  await evaluate(first, `
    $("host").value = ${JSON.stringify(server.host)};
    $("port").value = "${server.port}";
    $("username").value = ${JSON.stringify(server.username)};
    $("auth-type").value = "password";
    $("auth-type").dispatchEvent(new Event("change"));
    $("password").value = ${JSON.stringify(server.password)};
    $("profile-name").value = "Staging box";
    $("save-credentials").checked = true;
    $("save-profile").click();
    return true;
  `);
  await waitFor(first, `$("connect-message").textContent.startsWith("Saved “Staging box” with encrypted")`, "the connection to be saved");

  // Ctrl+Shift+L in the second window -- the one opened before the password was set.
  await evaluate(second, `
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "L", code: "KeyL", ctrlKey: true, shiftKey: true, bubbles: true, cancelable: true }));
    return true;
  `);
  await waitFor(first, `$("master-lock").classList.contains("hidden")`, "the first window to show the lock from the second");
  assert.equal(await evaluate(first, `return (await window.sshWorkbench.vault.status()).unlocked;`), false);
  console.log("• Ctrl+Shift+L in that window locks the vault for every window");

  // Unlocked again from the first window. The second window's list is refreshed by
  // hearing of it, and the connection is chosen there.
  await evaluate(first, `await window.sshWorkbench.vault.unlock(${JSON.stringify(MASTER)}); return true;`);
  await waitFor(second, `!$("master-lock").classList.contains("hidden")`, "the second window to see the unlock");
  // Chosen in the second window while unlocked: nothing secret reaches the form.
  await waitFor(second, `$("saved-profile").options.length > 1`, "the second window's list");
  const chosen = await evaluate(second, `
    $("saved-profile").value = $("saved-profile").options[1].value;
    $("saved-profile").dispatchEvent(new Event("change"));
    await new Promise((resolve) => setTimeout(resolve, 500));
    return { password: $("password").value, host: $("host").value };
  `);
  assert.equal(chosen.host, server.host);
  assert.equal(chosen.password, "", "choosing a saved connection puts no secret in the form");
  console.log("• choosing a saved connection in another window leaves the password field empty");

  // Then locked with the first window's button: connecting from the second window has
  // to ask for the master password.
  await evaluate(second, `$("password").value = "typed-by-hand"; return true;`);
  await evaluate(first, `$("master-lock").click(); return true;`);
  await waitFor(second, `$("master-lock").classList.contains("hidden")`, "the second window to see the lock");
  assert.equal(await evaluate(second, `return $("password").value;`), "",
    "a lock from another window clears this window's form as a lock here would");
  await evaluate(second, `$("connect-form").requestSubmit(); return true;`);
  await waitFor(second, `!$("modal-backdrop").classList.contains("hidden") && document.querySelector("#modal input")`, "the master password prompt in the second window");
  assert.equal(await evaluate(second, `return document.querySelectorAll("#tabstrip .tab").length;`), 0,
    "nothing connected before the master password was given");
  await evaluate(second, `
    const input = document.querySelector("#modal input");
    input.value = ${JSON.stringify(MASTER)};
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    return true;
  `);
  await waitFor(second, `document.querySelectorAll("#tabstrip .tab").length === 1 && [...document.querySelectorAll("#file-rows tr")].some((row) => row.textContent.includes("readme.txt"))`, "the second window to connect");
  console.log("• after a lock in one window, connecting in another asks for the master password first");
}

main()
  .then(() => console.log("\nvault window checks passed"))
  .catch((error) => {
    process.exitCode = 1;
    console.error(`\n${error?.stack || error}`);
  })
  .finally(async () => {
    for (const clean of cleanups.reverse()) {
      try { await Promise.race([clean(), new Promise((resolve) => setTimeout(resolve, 2000))]); } catch { /* nothing left to do about it */ }
    }
    process.exit();
  });

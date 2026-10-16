// End-to-end check that Reconnect brings back the credentials a tab was opened with.
//
// Two servers with different passwords, each saved as a connection under a master
// password. A tab's link to its server is dropped and Reconnect is pressed with the
// password box left as it comes back -- empty -- which has to work, and has to use
// that tab's own saved password even while the list shows the other connection. Run
// it with `npm run e2e`; a virtual display is required on headless machines
// (`xvfb-run -a node test/e2e/reconnect.mjs`).

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

const fillForm = (server) => `
  $("saved-profile").value = "";
  $("saved-profile").dispatchEvent(new Event("change"));
  await new Promise((resolve) => setTimeout(resolve, 100));
  $("host").value = ${JSON.stringify(server.host)};
  $("port").value = "${server.port}";
  $("username").value = ${JSON.stringify(server.username)};
  $("auth-type").value = "password";
  $("auth-type").dispatchEvent(new Event("change"));
  $("password").value = ${JSON.stringify(server.password)};
`;

async function main() {
  const remoteRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-e2e-remote-"));
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-e2e-reconnect-"));
  onCleanup(() => fs.rmSync(remoteRoot, { recursive: true, force: true }));
  onCleanup(() => fs.rmSync(userData, { recursive: true, force: true }));
  fs.writeFileSync(path.join(remoteRoot, "readme.txt"), "hello\n");

  const alpha = await startTestServer({ root: remoteRoot, password: "alpha-secret" });
  const bravo = await startTestServer({ root: remoteRoot, password: "bravo-secret" });
  onCleanup(() => alpha.close());
  onCleanup(() => bravo.close());
  fs.writeFileSync(path.join(userData, "known-hosts.json"), JSON.stringify({
    version: 1,
    hosts: Object.fromEntries([alpha, bravo].map((server) =>
      [`${server.host}:${server.port}`, { sha256: fingerprint(server.hostPublicKey) }])),
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

  const session = await connectDevtools(await openDevtools(debugPort));
  await waitFor(session, `$("credential-storage").textContent.length > 0`, "the renderer to start");

  // A master password, so the saved credentials can be locked and unlocked at will.
  await evaluate(session, `
    await window.sshWorkbench.vault.set(${JSON.stringify(MASTER)}, { mode: "minutes", minutes: 15 });
    $("master-lock").click();
    await new Promise((resolve) => setTimeout(resolve, 200));
    await window.sshWorkbench.vault.unlock(${JSON.stringify(MASTER)});
    return true;
  `);

  // Both servers saved with their passwords, through the form as anyone would.
  const ids = {};
  for (const [name, server] of [["Alpha", alpha], ["Bravo", bravo]]) {
    await evaluate(session, `
      ${fillForm(server)}
      $("profile-name").value = ${JSON.stringify(name)};
      $("save-credentials").checked = true;
      $("save-profile").click();
      return true;
    `);
    await waitFor(session, `$("connect-message").textContent.startsWith("Saved “${name}” with encrypted")`, `${name} to be saved`);
    ids[name] = await evaluate(session, `return $("saved-profile").value;`);
  }
  assert.ok(ids.Alpha && ids.Bravo && ids.Alpha !== ids.Bravo);
  console.log("• two servers saved with different passwords under a master password");

  const select = (id) => evaluate(session, `
    $("saved-profile").value = ${JSON.stringify(id)};
    $("saved-profile").dispatchEvent(new Event("change"));
    await new Promise((resolve) => setTimeout(resolve, 300));
    return $("password").value;
  `);
  const submit = () => evaluate(session, `$("connect-form").requestSubmit(); return true;`);
  const connectedTabs = (count) => waitFor(session,
    `$("connect-view").classList.contains("hidden") && document.querySelectorAll("#tabstrip .tab").length === ${count} && !$("connection-label").textContent.includes("disconnected") && [...document.querySelectorAll("#file-rows tr")].some((row) => row.textContent.includes("readme.txt"))`,
    `${count} connected tab(s)`);
  const dropAndReconnect = async (server) => {
    server.dropClients();
    await waitFor(session, `!$("reconnect").classList.contains("hidden")`, "the tab to notice it was dropped");
    return evaluate(session, `
      $("reconnect").click();
      await new Promise((resolve) => setTimeout(resolve, 300));
      return {
        password: $("password").value,
        profile: $("saved-profile").value,
        host: $("host").value,
        port: $("port").value,
        message: $("connect-message").textContent,
      };
    `);
  };

  // 1. The reported case: unlocked, Alpha opened from the list, its link dropped.
  assert.equal(await select(ids.Alpha), "", "choosing a connection puts nothing secret in the form, even unlocked");
  await submit();
  await connectedTabs(1);
  let form = await dropAndReconnect(alpha);
  assert.equal(form.password, "", "Reconnect still keeps no password in the form");
  assert.equal(form.profile, ids.Alpha, "the form goes back to standing for the tab's own saved connection");
  assert.match(form.message, /saved with “Alpha”/);
  await submit();
  await connectedTabs(1);
  console.log("• a dropped tab reconnects with its saved password, nothing retyped");

  // 2. The list moves on to Bravo for a second tab; Alpha's link drops again. Its
  //    reconnect has to use Alpha's password, not the one now showing in the form.
  await evaluate(session, `$("new-session").click(); return true;`);
  assert.equal(await select(ids.Bravo), "");
  await submit();
  await connectedTabs(2);
  await evaluate(session, `document.querySelectorAll("#tabstrip .tab")[0].click(); return true;`);
  await waitFor(session, `$("connection-label").textContent.includes(":${alpha.port}")`, "Alpha's tab");
  form = await dropAndReconnect(alpha);
  assert.equal(form.port, String(alpha.port));
  assert.equal(form.profile, ids.Alpha, "Alpha's tab, not Bravo from the list");
  await submit();
  await connectedTabs(2);
  console.log("• with another connection loaded since, the tab reconnects with its own password");

  // 3. Locked: Reconnect asks for the master password, and then needs nothing else.
  await evaluate(session, `$("master-lock").click(); return true;`);
  await new Promise((resolve) => setTimeout(resolve, 300));
  form = await dropAndReconnect(alpha);
  assert.equal(form.password, "");
  await submit();
  await waitFor(session, `!$("modal-backdrop").classList.contains("hidden") && document.querySelector("#modal input")`, "the master password prompt");
  await evaluate(session, `
    const input = document.querySelector("#modal input");
    input.value = ${JSON.stringify(MASTER)};
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    return true;
  `);
  await connectedTabs(2);
  console.log("• locked, Reconnect asks for the master password and nothing more");

  // 4. A connection chosen while locked: the second tab opened from the same loaded
  //    entry must not come up with an empty password either.
  await evaluate(session, `$("master-lock").click(); return true;`);
  await new Promise((resolve) => setTimeout(resolve, 300));
  await evaluate(session, `$("new-session").click(); return true;`);
  assert.equal(await select(ids.Bravo), "", "a locked connection loads without its password");
  await submit();
  await waitFor(session, `document.querySelector("#modal input")`, "the master password prompt");
  await evaluate(session, `
    const input = document.querySelector("#modal input");
    input.value = ${JSON.stringify(MASTER)};
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    return true;
  `);
  await connectedTabs(3);
  await evaluate(session, `$("new-session").click(); return true;`);
  await waitFor(session, `!$("connect-view").classList.contains("hidden")`, "the connect view");
  assert.equal(await evaluate(session, `return $("saved-profile").value;`), ids.Bravo, "the form still shows Bravo");
  await submit();
  await connectedTabs(4);
  console.log("• a second tab from a connection loaded while locked connects without retyping");

  // 5. A tab from no saved connection has nothing to go back to, and is not handed
  //    whatever the list was showing.
  await evaluate(session, `$("new-session").click(); return true;`);
  await evaluate(session, `${fillForm(alpha)} $("connect-form").requestSubmit(); return true;`);
  await connectedTabs(5);
  await evaluate(session, `
    $("saved-profile").value = ${JSON.stringify(ids.Bravo)};
    $("saved-profile").dispatchEvent(new Event("change"));
    return true;
  `);
  form = await dropAndReconnect(alpha);
  assert.equal(form.profile, "", "an unsaved tab reconnects as an unsaved connection");
  assert.equal(form.password, "");
  console.log("• an unsaved tab is not linked to whatever the list shows");
}

main()
  .then(() => console.log("\nreconnect checks passed"))
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

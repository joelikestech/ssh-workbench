// End-to-end check of the packaged renderer against a real SSH/SFTP server.
//
// It launches the actual Electron application, drives the user interface over the
// Chrome DevTools Protocol, and asserts that several session tabs stay
// independent. Run it with `npm run e2e`. A virtual display is required on
// headless machines (`xvfb-run -a npm run e2e`).

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
  const targets = await response.json();
  return targets.filter((target) => target.type === "page" && target.webSocketDebuggerUrl);
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
  const problems = [];
  let nextId = 0;
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result);
      return;
    }
    if (message.method === "Runtime.exceptionThrown") {
      problems.push(message.params.exceptionDetails?.exception?.description || "uncaught exception");
    }
    if (message.method === "Runtime.consoleAPICalled" && message.params.type === "error") {
      problems.push(message.params.args.map((argument) => argument.value ?? argument.description).join(" "));
    }
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  await send("Runtime.enable");
  onCleanup(() => socket.close());
  return { send, problems };
}

async function evaluate(session, expression) {
  const result = await session.send("Runtime.evaluate", {
    expression: `(async () => { ${expression} })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
  }
  return result.result.value;
}

async function describeState(session) {
  return evaluate(session, `
    return {
      connectMessage: document.getElementById("connect-message").textContent,
      fileMessage: document.getElementById("file-message").textContent,
      tabs: document.querySelectorAll("#tabstrip .tab").length,
      rows: document.querySelectorAll("#file-rows tr").length,
      view: document.getElementById("connect-view").classList.contains("hidden") ? "workspace" : "connect",
    };
  `);
}

async function waitFor(session, expression, label, timeout = 20000) {
  const deadline = Date.now() + timeout;
  let last;
  let problem = null;
  while (Date.now() < deadline) {
    try {
      last = await evaluate(session, `return ${expression};`);
      problem = null;
      if (last) return last;
    } catch (error) {
      // A window still being built throws before it can answer -- reaching into a
      // document that has no such element yet is a "not yet", not a failure. A real
      // mistake in the expression keeps throwing and is reported when time runs out.
      problem = error.message;
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  const state = await describeState(session).catch(() => null);
  const why = problem ? `, last error: ${problem}` : "";
  throw new Error(`Timed out waiting for ${label} (last value: ${JSON.stringify(last)}${why})\nstate: ${JSON.stringify(state)}`);
}

const fillAndSubmit = (server) => `
  const $ = (id) => document.getElementById(id);
  $("host").value = ${JSON.stringify(server.host)};
  $("port").value = "${server.port}";
  $("username").value = ${JSON.stringify(server.username)};
  $("auth-type").value = "password";
  $("auth-type").dispatchEvent(new Event("change"));
  $("password").value = ${JSON.stringify(server.password)};
  $("start-path").value = "~";
  $("connect-form").requestSubmit();
  return true;
`;

async function main() {
  const remoteRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-e2e-remote-"));
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-e2e-profile-"));
  onCleanup(() => fs.rmSync(remoteRoot, { recursive: true, force: true }));
  onCleanup(() => fs.rmSync(userData, { recursive: true, force: true }));

  fs.mkdirSync(path.join(remoteRoot, "documents", "reports"), { recursive: true });
  fs.writeFileSync(path.join(remoteRoot, "readme.txt"), "hello from the test server\n");
  fs.writeFileSync(path.join(remoteRoot, "documents", "reports", "q1 results.txt"), "numbers\n");

  const server = await startTestServer({ root: remoteRoot });
  onCleanup(() => server.close());

  // Pre-trust the throwaway host key so no modal blocks the automated run.
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
  const applicationOutput = [];
  electron.stdout.on("data", (chunk) => applicationOutput.push(String(chunk)));
  electron.stderr.on("data", (chunk) => applicationOutput.push(String(chunk)));
  electron.on("exit", (code) => applicationOutput.push(`electron exited with ${code}`));
  onCleanup(() => { if (!electron.killed) electron.kill("SIGKILL"); });

  const firstTargetUrl = await openDevtools(debugPort);
  const firstTargetId = (await pageTargets(debugPort)).find((target) => target.webSocketDebuggerUrl === firstTargetUrl).id;
  const session = await connectDevtools(firstTargetUrl);
  onCleanup(() => {
    if (session.problems.length) console.error(`\nrenderer problems:\n${session.problems.join("\n")}`);
    if (process.exitCode) console.error(`\napplication output:\n${applicationOutput.join("")}`);
  });

  await waitFor(session, `!document.getElementById("connect-view").classList.contains("hidden")`, "the connect view");
  // The renderer bundle also has to have attached its handlers; the credential
  // notice is filled in only after its first round trip to the main process.
  await waitFor(session, `document.getElementById("credential-storage").textContent.length > 0`, "the renderer to start");
  const firstImpression = await evaluate(session, `
    const view = document.getElementById("connect-view");
    const card = document.querySelector(".connect-card");
    const submit = document.querySelector(".connect-button");
    return {
      scrolls: view.scrollHeight > view.clientHeight + 1,
      cardHeight: Math.round(card.getBoundingClientRect().height),
      windowHeight: innerHeight,
      submitVisible: submit.getBoundingClientRect().bottom <= innerHeight,
      authType: document.getElementById("auth-type").value,
      passwordShown: !document.getElementById("password-fields").classList.contains("hidden"),
      keyShown: !document.getElementById("key-fields").classList.contains("hidden"),
    };
  `);
  assert.equal(firstImpression.scrolls, false,
    `the connection form must fit without scrolling (card ${firstImpression.cardHeight}px in ${firstImpression.windowHeight}px)`);
  assert.equal(firstImpression.submitVisible, true, "including the Connect button");
  assert.equal(firstImpression.authType, "password", "a new connection starts on password authentication");
  assert.equal(firstImpression.passwordShown, true, "so the password field is the one on show");
  assert.equal(firstImpression.keyShown, false);
  console.log(`• connect view rendered, ${firstImpression.cardHeight}px tall and unscrolled, on password auth`);

  const identity = await evaluate(session, `
    const label = document.getElementById("app-version");
    const jump = [...document.getElementById("jump-auth-type").options].map((option) => option.value);
    const destination = [...document.getElementById("auth-type").options].map((option) => option.value);
    return {
      version: label.textContent,
      title: label.title,
      jump,
      destination,
      jumpValue: document.getElementById("jump-auth-type").value,
    };
  `);
  assert.match(identity.version, /^v\d+\.\d+\.\d+$/, `the build should be on screen, saw "${identity.version}"`);
  assert.match(identity.title, /SSH Workbench .* Electron /);
  assert.deepEqual(identity.jump, identity.destination,
    "the jump host offers the same authentication choices in the same order as the destination");
  assert.equal(identity.jumpValue, "agent", "a jump host still starts on the agent");
  console.log(`• the build is on screen (${identity.version}) and both authentication lists match`);

  // The default transfer setting says what it does in its own label; the two
  // deliberate choices carry a note.
  const protocolNotes = await evaluate(session, `
    const select = document.getElementById("protocol");
    const note = document.getElementById("protocol-note");
    const seen = {};
    for (const value of ["sftp-scp", "scp", "sftp"]) {
      select.value = value;
      select.dispatchEvent(new Event("change"));
      seen[value] = note.textContent;
    }
    select.value = "sftp-scp";
    select.dispatchEvent(new Event("change"));
    return seen;
  `);
  assert.equal(protocolNotes["sftp-scp"], "", "the default needs no note beyond its label");
  assert.match(protocolNotes.scp, /ls/, "choosing SCP explains what changes");
  assert.match(protocolNotes.sftp, /will not connect/, "and SFTP-only says what it refuses");
  console.log("• the transfer setting explains the two deliberate choices");

  await evaluate(session, fillAndSubmit(server));
  await waitFor(session, `document.querySelectorAll("#tabstrip .tab").length === 1`, "the first session tab");
  await waitFor(session, `document.querySelectorAll("#file-rows tr").length === 2`, "the first remote listing");
  const firstTab = await evaluate(session, `return document.querySelector("#tabstrip .tab .tab-name").textContent;`);
  assert.equal(firstTab, `${server.username}@${server.host}:${server.port}`);
  console.log(`• session 1 connected and listed ${server.host}`);

  await waitFor(session, `document.querySelector("#terminals .xterm-rows")?.textContent.includes("test-shell-ready")`,
    "the first remote shell banner");
  console.log("• session 1 shell is live");

  // The build has to be legible from a window that has been connected for days, not
  // only from the connection screen it was started on — and the session bar must not
  // repeat what the window title is already saying.
  const connectedIdentity = await evaluate(session, `
    return {
      windowTitle: document.title,
      card: document.getElementById("app-version").textContent,
      cardTitle: document.getElementById("app-version").title,
      barLabels: document.querySelectorAll(".appbar .app-version, .appbar .app-title").length,
      barText: document.querySelector(".appbar").textContent.trim(),
    };
  `);
  assert.match(connectedIdentity.windowTitle, /^SSH Workbench \d+\.\d+\.\d+$/,
    `the window title should name the build, saw "${connectedIdentity.windowTitle}"`);
  assert.equal(connectedIdentity.windowTitle, `SSH Workbench ${connectedIdentity.card.replace(/^v/, "")}`,
    "the title and the connection screen must name the same build");
  assert.equal(connectedIdentity.barLabels, 0, "the session bar repeats neither the name nor the build");
  assert.ok(!connectedIdentity.barText.includes("SSH Workbench"),
    `the session bar should not repeat the application's name (it read "${connectedIdentity.barText}")`);
  assert.match(connectedIdentity.cardTitle, /Electron/, "hovering the connection screen's label gives the fuller detail");
  console.log(`• the window title carries the build while connected ("${connectedIdentity.windowTitle}")`);

  // Connecting must leave no record of where: only innocuous interface state.
  const stored = await evaluate(session, `
    return Object.fromEntries(Object.keys(localStorage).map((key) => [key, localStorage.getItem(key)]));
  `);
  assert.equal(stored.connectionProfile, undefined, "the host and username are not remembered");
  const leaked = Object.entries(stored).filter(([, value]) =>
    String(value).includes("127.0.0.1") || String(value).includes("tester"));
  assert.deepEqual(leaked, [], `no stored value may contain the host or username (stored: ${JSON.stringify(stored)})`);
  console.log(`• nothing identifying is stored locally (keys: ${Object.keys(stored).sort().join(", ") || "none"})`);

  // Launching the application again must reach this process and open a window here,
  // rather than starting a second copy that would contend for the same profile.
  const relaunchStarted = Date.now();
  const relaunch = spawn(
    path.join(repository, "node_modules", ".bin", "electron"),
    [".", `--user-data-dir=${userData}`],
    { cwd: repository, stdio: "ignore" },
  );
  const relaunchExit = await new Promise((resolve) => relaunch.on("exit", (code) => resolve(code)));
  assert.equal(relaunchExit, 0, "the second copy exits instead of running alongside");
  const afterRelaunch = Date.now() + 20000;
  let windowCount = 1;
  while (windowCount < 2 && Date.now() < afterRelaunch) {
    windowCount = (await pageTargets(debugPort)).length;
    if (windowCount < 2) await new Promise((resolve) => setTimeout(resolve, 150));
  }
  assert.equal(windowCount, 2, "launching again opens a window in the running process");
  console.log(`• launching again opens a window here in ${Date.now() - relaunchStarted} ms`);

  // A copy from a different folder is a different build, and this one must not draw a
  // window on its behalf — that is what made an update look like it had changed
  // nothing. --no-take-over is how the test declines the offer that copy would
  // otherwise put to the user.
  const windowsBefore = (await pageTargets(debugPort)).length;
  const stranger = spawn(
    path.join(repository, "node_modules", ".bin", "electron"),
    [".", `--user-data-dir=${userData}`, "--no-take-over"],
    {
      cwd: repository,
      stdio: "ignore",
      env: { ...process.env, SSH_WORKBENCH_INSTALLATION: path.join(os.tmpdir(), "another-copy", "SSH Workbench") },
    },
  );
  const strangerExit = await new Promise((resolve) => stranger.on("exit", (code) => resolve(code)));
  assert.equal(strangerExit, 0, "a copy from another folder exits rather than running alongside");
  await new Promise((resolve) => setTimeout(resolve, 1500));
  assert.equal((await pageTargets(debugPort)).length, windowsBefore,
    "and is given no window by the copy holding the profile");
  console.log("• a copy from another folder is not served a window by this one");
  // Leave one window for the checks that follow.
  const extra = (await pageTargets(debugPort)).find((target) => target.id !== firstTargetId);
  await session.send("Target.closeTarget", { targetId: extra.id });
  await new Promise((resolve) => setTimeout(resolve, 1000));

  // A second window: its own tabs, its own sessions, and no wait for a profile that
  // another copy of the application would have been contending for.
  const windowStarted = Date.now();
  await evaluate(session, `document.getElementById("new-window").click(); return true;`);
  let secondTarget = null;
  const windowDeadline = Date.now() + 20000;
  while (!secondTarget && Date.now() < windowDeadline) {
    const targets = await pageTargets(debugPort);
    secondTarget = targets.find((target) => target.id !== firstTargetId) || null;
    if (!secondTarget) await new Promise((resolve) => setTimeout(resolve, 150));
  }
  assert.ok(secondTarget, "a second window should appear");
  const windowMilliseconds = Date.now() - windowStarted;
  const second = await connectDevtools(secondTarget.webSocketDebuggerUrl);
  await waitFor(second, `document.getElementById("credential-storage").textContent.length > 0`, "the second window to start");
  console.log(`• a second window opens in ${windowMilliseconds} ms`);

  // It starts empty, and knows nothing of the first window's session.
  assert.equal(await evaluate(second, `return document.querySelectorAll("#tabstrip .tab").length;`), 0,
    "a new window starts with no sessions");
  assert.equal(await evaluate(second, `return document.getElementById("connect-view").classList.contains("hidden");`),
    false, "and shows the connection form");
  const forged = await evaluate(second, `
    try {
      await window.sshWorkbench.files.list("00000000-0000-4000-8000-000000000000", "/");
      return "allowed";
    } catch (error) { return String(error.message || error); }
  `);
  assert.match(forged, /no longer open/, "a session id it does not own is refused");

  await evaluate(second, fillAndSubmit(server));
  await waitFor(second, `document.querySelectorAll("#file-rows tr").length === 2`, "the second window's listing");
  assert.equal(await evaluate(second, `return document.querySelectorAll("#tabstrip .tab").length;`), 1);
  assert.equal(await evaluate(session, `return document.querySelectorAll("#tabstrip .tab").length;`), 1,
    "the first window still has exactly its own session");
  console.log("• each window keeps its own sessions and tab strip");

  // Closing the second window must leave the first one working.
  await session.send("Target.closeTarget", { targetId: secondTarget.id });
  await new Promise((resolve) => setTimeout(resolve, 1500));
  await evaluate(session, `document.getElementById("refresh").click(); return true;`);
  await waitFor(session, `document.querySelectorAll("#file-rows tr").length === 2`,
    "the first window to keep working after the second closes");
  assert.equal((await pageTargets(debugPort)).length, 1, "only the first window remains");
  console.log("• closing one window leaves the other untouched");

  // A second tab to the same host must be an independent session.
  await evaluate(session, `document.getElementById("new-session").click(); return true;`);
  await waitFor(session, `!document.getElementById("connect-view").classList.contains("hidden")`, "the connect view again");
  assert.equal(await evaluate(session, `return document.getElementById("cancel-connect").classList.contains("hidden");`),
    false, "an existing session must offer a way back");
  await evaluate(session, fillAndSubmit(server));
  await waitFor(session, `document.querySelectorAll("#tabstrip .tab").length === 2`, "the second session tab");
  await waitFor(session, `document.querySelectorAll("#terminals > div").length === 2`, "a second terminal");
  console.log("• session 2 connected in its own tab");

  // Navigate only the second session and confirm the first keeps its folder.
  await waitFor(session,
    `[...document.querySelectorAll("#file-rows .name-link")].some((node) => node.textContent === "documents")`,
    "the second session listing");
  await evaluate(session, `
    const link = [...document.querySelectorAll("#file-rows .name-link")].find((node) => node.textContent === "documents");
    link.click();
    return true;
  `);
  await waitFor(session, `document.querySelectorAll("#file-rows tr").length === 1`, "the second session to enter documents");
  const secondPath = await evaluate(session, `return document.getElementById("path-input").value;`);
  assert.equal(path.posix.basename(secondPath), "documents");

  await evaluate(session, `document.querySelectorAll("#tabstrip .tab")[0].click(); return true;`);
  await waitFor(session, `document.querySelectorAll("#file-rows tr").length === 2`, "the first session listing to return");
  const firstPathAfter = await evaluate(session, `return document.getElementById("path-input").value;`);
  assert.notEqual(path.posix.basename(firstPathAfter), "documents", "each tab keeps its own remote folder");
  assert.equal(await evaluate(session, `return document.querySelectorAll("#terminals > div:not(.hidden)").length;`), 1,
    "exactly one terminal is visible at a time");
  console.log("• tabs keep independent folders, selections, and terminals");

  // Per-tab search state.
  await evaluate(session, `
    const search = document.getElementById("search");
    search.value = "readme";
    search.dispatchEvent(new Event("input"));
    return true;
  `);
  await waitFor(session, `document.getElementById("file-count").textContent.includes("match")`, "search results in tab 1");
  await evaluate(session, `document.querySelectorAll("#tabstrip .tab")[1].click(); return true;`);
  assert.equal(await evaluate(session, `return document.getElementById("search").value;`), "",
    "the second tab does not inherit the first tab's search text");
  console.log("• search text is per session");

  // Alt+2 / Alt+1 tab switching.
  await evaluate(session, `
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "1", altKey: true, bubbles: true }));
    return true;
  `);
  await waitFor(session, `document.querySelectorAll("#tabstrip .tab")[0].classList.contains("active")`,
    "Alt+1 to activate the first tab");
  console.log("• Alt+digit switches tabs");

  // Searching by path and by wildcard, and reporting the coverage honestly.
  const runSearch = async (text) => {
    await evaluate(session, `
      // Blank the status line first: the previous search's message would satisfy
      // the wait below before this search has run.
      document.getElementById("file-message").textContent = "";
      const search = document.getElementById("search");
      search.value = ${JSON.stringify(text)};
      search.dispatchEvent(new Event("input"));
      return true;
    `);
    await waitFor(session, `document.getElementById("file-message").textContent.includes("match")`,
      `search results for ${text}`);
    return evaluate(session, `return {
      names: [...document.querySelectorAll("#file-rows .name-link")].map((node) => node.textContent),
      locations: [...document.querySelectorAll("#file-rows .where")].map((node) => node.textContent),
      message: document.getElementById("file-message").textContent,
    };`);
  };

  const byPath = await runSearch("reports/q1");
  assert.deepEqual(byPath.names, ["q1 results.txt"],
    `a query with a slash matches the path (got ${JSON.stringify(byPath)})`);
  assert.deepEqual(byPath.locations, ["documents/reports"]);
  assert.match(byPath.message, /by relative path/);
  assert.match(byPath.message, /searched \d+ folders/, "the status line says how much was covered");

  const byWildcard = await runSearch("*.txt");
  assert.deepEqual(byWildcard.names.sort(), ["q1 results.txt", "readme.txt"]);
  console.log(`• path and wildcard search work ("${byPath.message}")`);

  assert.equal(await evaluate(session, `
    return [...document.querySelectorAll("#terminals > div")]
      .filter((node) => node.textContent.includes("test-shell-ready")).length;
  `), 2, "each session keeps its own shell output");
  console.log("• both sessions hold their own terminal scrollback");

  // Windows-console copy and paste behaviour, driven with real input events so
  // xterm's own selection and Chromium's own paste both take part.
  const terminalBox = await evaluate(session, `
    const box = document.querySelector("#terminals > div:not(.hidden)").getBoundingClientRect();
    return { left: Math.round(box.left), top: Math.round(box.top) };
  `);
  const mouse = (type, x, y, extra = {}) => session.send("Input.dispatchMouseEvent",
    { type, x, y, button: "left", buttons: type === "mouseMoved" ? 1 : 0, clickCount: 1, ...extra });
  const dragAcrossFirstLine = async (modifiers) => {
    const y = terminalBox.top + 14;
    await mouse("mousePressed", terminalBox.left + 10, y, { modifiers });
    await mouse("mouseMoved", terminalBox.left + 120, y, { modifiers });
    await mouse("mouseReleased", terminalBox.left + 120, y, { modifiers });
    await new Promise((resolve) => setTimeout(resolve, 250));
  };
  const clipboard = () => evaluate(session, `return window.sshWorkbench.clipboard.read();`);
  const setClipboard = (text) => evaluate(session, `return window.sshWorkbench.clipboard.write(${JSON.stringify(text)});`);

  // Nothing has been selected in this window yet, which is the case that matters:
  // xterm reads Shift+mousedown as "extend the selection", and with none to extend
  // the drag would select nothing at all.
  await setClipboard("untouched");
  await dragAcrossFirstLine(8); // 8 = Shift
  const shiftCopied = await clipboard();
  assert.match(shiftCopied, /test/,
    `the first Shift+drag must copy, with nothing selected before it (clipboard held ${JSON.stringify(shiftCopied)})`);
  console.log(`• the first Shift+drag copies ("${shiftCopied.trim()}") with nothing selected before it`);

  await setClipboard("untouched");
  await dragAcrossFirstLine(0);
  assert.equal(await clipboard(), "untouched", "a plain drag selects without touching the clipboard");
  console.log("• a plain drag selects and leaves the clipboard alone");

  // A drag with the middle button -- the scroll wheel held down -- copies like
  // Shift+drag. On Linux the middle button's release would also paste the primary
  // selection, which xterm has just filled with the dragged text; none of that may
  // reach the shell.
  const middleDragAcrossFirstLine = async () => {
    const y = terminalBox.top + 14;
    await mouse("mousePressed", terminalBox.left + 10, y, { button: "middle" });
    for (const step of [1, 2, 3]) {
      await mouse("mouseMoved", terminalBox.left + 10 + (110 * step) / 3, y, { button: "middle", buttons: 4 });
      await new Promise((resolve) => setTimeout(resolve, 40));
    }
    await mouse("mouseReleased", terminalBox.left + 120, y, { button: "middle" });
    await new Promise((resolve) => setTimeout(resolve, 300));
  };
  await setClipboard("untouched");
  const inputBeforeMiddle = server.received().length;
  await middleDragAcrossFirstLine();
  const middleCopied = await clipboard();
  assert.match(middleCopied, /test/, `a middle-drag copies (clipboard held ${JSON.stringify(middleCopied)})`);
  assert.equal(server.received().slice(inputBeforeMiddle), "", "a middle-drag sends nothing to the shell");
  console.log(`• a middle-drag copies ("${middleCopied.trim()}") and pastes nothing`);

  // Indented output, copied the way it actually arrives: a YAML fragment printed
  // inside a tool's own indentation, which is unusable in a file unless the shared
  // depth comes off on the way to the clipboard.
  const printed = ["    hooks:", "      PreToolUse:", "        - matcher: Bash"];
  server.shells[0].write(`\r\n${printed.join("\r\n")}\r\n`);
  await waitFor(session,
    `document.querySelector("#terminals > div:not(.hidden) .xterm-rows").textContent.includes("- matcher: Bash")`,
    "the indented block to be printed");
  const blockBox = await evaluate(session, `
    const rows = [...document.querySelectorAll("#terminals > div:not(.hidden) .xterm-rows > div")];
    const first = rows.find((row) => row.textContent.includes("hooks:"));
    const last = rows.find((row) => row.textContent.includes("- matcher: Bash"));
    const top = first.getBoundingClientRect();
    const bottom = last.getBoundingClientRect();
    return {
      startX: Math.round(top.left + 1), startY: Math.round(top.top + top.height / 2),
      cellWidth: (() => {
        const measure = document.querySelector("#terminals > div:not(.hidden) .xterm-char-measure-element");
        return measure.getBoundingClientRect().width / measure.textContent.length;
      })(),
      endX: Math.round(bottom.right - 4), endY: Math.round(bottom.top + bottom.height / 2),
    };
  `);
  // The movement is spread over several events: xterm follows a drag from its own
  // frame loop, and a press and release in one task select a single cell.
  const dragBlock = async (modifiers, startX = blockBox.startX) => {
    await mouse("mousePressed", startX, blockBox.startY, { modifiers });
    for (const step of [1, 2, 3, 4]) {
      await mouse("mouseMoved",
        Math.round(startX + ((blockBox.endX - startX) * step) / 4),
        Math.round(blockBox.startY + ((blockBox.endY - blockBox.startY) * step) / 4), { modifiers });
      await new Promise((resolve) => setTimeout(resolve, 60));
    }
    await mouse("mouseReleased", blockBox.endX, blockBox.endY, { modifiers });
    await new Promise((resolve) => setTimeout(resolve, 300));
  };

  const copyWith = async (modifiers) => {
    for (const type of ["rawKeyDown", "keyUp"]) {
      await session.send("Input.dispatchKeyEvent",
        { type, modifiers, key: modifiers & 8 ? "C" : "c", code: "KeyC", windowsVirtualKeyCode: 67 });
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  };

  // Ctrl+C removes the indentation the block shares and keeps what is inside it.
  await setClipboard("untouched");
  await dragBlock(0);
  await copyWith(2); // 2 = Ctrl
  const copiedBlock = (await clipboard()).replace(/\r/g, "").split("\n")
    .map((line) => line.trimEnd()).filter((line) => line.length);
  assert.deepEqual(copiedBlock, ["hooks:", "  PreToolUse:", "    - matcher: Bash"],
    `Ctrl+C must drop the shared indentation and keep the structure (clipboard held ${JSON.stringify(await clipboard())})`);
  console.log("• Ctrl+C drops the indentation the block shared, keeping what is inside it");

  await setClipboard("untouched");
  await dragBlock(8); // 8 = Shift
  const shiftBlock = (await clipboard()).replace(/\r/g, "").split("\n")
    .map((line) => line.trimEnd()).filter((line) => line.length);
  assert.deepEqual(shiftBlock, ["hooks:", "  PreToolUse:", "    - matcher: Bash"],
    `Shift+drag must drop the shared indentation and keep the structure (clipboard held ${JSON.stringify(await clipboard())})`);
  console.log("• Shift+drag drops the indentation the block shared, keeping what is inside it");

  // The drag people actually make: from the first letter, not from the space
  // before it. The first line arrives bare, and the rest must still lose the margin.
  await setClipboard("untouched");
  await dragBlock(8, Math.round(blockBox.startX - 1 + blockBox.cellWidth * 4.3));
  const fromLetter = (await clipboard()).replace(/\r/g, "").split("\n")
    .map((line) => line.trimEnd()).filter((line) => line.length);
  assert.deepEqual(fromLetter, ["hooks:", "  PreToolUse:", "    - matcher: Bash"],
    `a drag begun on the first letter must still drop the margin (clipboard held ${JSON.stringify(await clipboard())})`);
  console.log("• a drag begun on the first letter still drops the margin");

  // The one way to copy exactly what is on screen, for when the whitespace is the point.

  await setClipboard("untouched");
  await dragBlock(0);
  await copyWith(10); // 10 = Ctrl+Shift
  const verbatim = await clipboard();
  assert.match(verbatim, /^ {4}hooks:/, `Ctrl+Shift+C must copy it verbatim (clipboard held ${JSON.stringify(verbatim)})`);
  console.log("• Ctrl+Shift+C still copies exactly what is on screen");

  await setClipboard("untouched");
  await dragAcrossFirstLine(0);
  await evaluate(session, `
    document.querySelector("#terminals > div:not(.hidden)")
      .dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true }));
    return true;
  `);
  await new Promise((resolve) => setTimeout(resolve, 250));
  assert.match(await clipboard(), /test/, "right-click copies an existing selection");
  assert.equal(await evaluate(session, `
    return document.querySelector("#terminals > div:not(.hidden)").textContent.includes("PASTE-MARK");
  `), false);
  console.log("• right-click copies the selection");

  // With nothing selected, the right button pastes instead; the echo server sends
  // whatever it receives straight back, so a double paste would be visible.
  await setClipboard("PASTE-MARK-RIGHT");
  await evaluate(session, `
    document.querySelector("#terminals > div:not(.hidden)")
      .dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true }));
    return true;
  `);
  await waitFor(session,
    `document.querySelector("#terminals > div:not(.hidden)").textContent.includes("PASTE-MARK-RIGHT")`,
    "the right-click paste to reach the shell");
  console.log("• right-click pastes when nothing is selected");

  await setClipboard("PASTE-MARK-CTRLV");
  for (const type of ["rawKeyDown", "keyUp"]) {
    await session.send("Input.dispatchKeyEvent", { type, modifiers: 2, key: "v", code: "KeyV", windowsVirtualKeyCode: 86 });
  }
  await waitFor(session,
    `document.querySelector("#terminals > div:not(.hidden)").textContent.includes("PASTE-MARK-CTRLV")`,
    "the Ctrl+V paste to reach the shell");
  const ctrlVCount = await evaluate(session, `
    return document.querySelector("#terminals > div:not(.hidden)").textContent.split("PASTE-MARK-CTRLV").length - 1;
  `);
  assert.equal(ctrlVCount, 1, "Ctrl+V must paste once, not once per handler");
  console.log("• Ctrl+V pastes exactly once");

  await setClipboard("untouched");
  await dragAcrossFirstLine(0);
  for (const type of ["rawKeyDown", "keyUp"]) {
    await session.send("Input.dispatchKeyEvent", { type, key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  }
  await new Promise((resolve) => setTimeout(resolve, 250));
  assert.match(await clipboard(), /test/, "Enter copies a mouse selection, as the Windows console does");
  console.log("• Enter finishes a mouse selection by copying it");

  await setClipboard("PASTE-MARK-SHIFTINS");
  for (const type of ["rawKeyDown", "keyUp"]) {
    await session.send("Input.dispatchKeyEvent", { type, modifiers: 8, key: "Insert", code: "Insert", windowsVirtualKeyCode: 45 });
  }
  await waitFor(session,
    `document.querySelector("#terminals > div:not(.hidden)").textContent.includes("PASTE-MARK-SHIFTINS")`,
    "the Shift+Insert paste to reach the shell");
  console.log("• Shift+Insert pastes");

  // The refresh button turns once while the listing reloads.
  const refreshFeedback = await evaluate(session, `
    const button = document.getElementById("refresh");
    button.click();
    const during = button.classList.contains("refreshing");
    await new Promise((resolve) => setTimeout(resolve, 900));
    return { during, after: button.classList.contains("refreshing") };
  `);
  assert.equal(refreshFeedback.during, true, "pressing refresh marks the button straight away");
  assert.equal(refreshFeedback.after, false, "and the mark is cleared once the turn finishes");
  console.log("• the refresh button shows a single turn while reloading");

  // Saving a connection, then opening it straight from the list.
  const quickConnect = await evaluate(session, `
    document.getElementById("profile-name").value = "Test target";
    document.getElementById("save-credentials").checked = false;
    document.getElementById("save-profile").click();
    await new Promise((resolve) => setTimeout(resolve, 600));
    const select = document.getElementById("saved-profile");
    return {
      saved: [...select.options].map((option) => option.textContent),
      value: select.value,
      connectEnabled: !document.getElementById("quick-connect").disabled,
      message: document.getElementById("connect-message").textContent,
    };
  `);
  assert.ok(quickConnect.saved.some((name) => name.startsWith("Test target")),
    `the connection should be saved (options: ${JSON.stringify(quickConnect.saved)}, message: ${quickConnect.message})`);
  assert.equal(quickConnect.connectEnabled, true, "Connect is enabled once a saved connection is selected");

  // Enter means connect, wherever the focus is on this screen — which is the screen
  // the saved-connection list lives on, so the checks below start by opening it.
  await evaluate(session, `
    document.getElementById("new-session").click();
    await new Promise((resolve) => setTimeout(resolve, 300));
    return true;
  `);
  await waitFor(session, `!document.getElementById("connect-view").classList.contains("hidden")`,
    "the connect view for the Enter checks");

  // From the list: no trip through the form at all.
  const viaEnter = await evaluate(session, `
    const select = document.getElementById("saved-profile");
    const option = [...select.options].find((candidate) => candidate.textContent.startsWith("Test target"));
    select.value = option.value;
    select.dispatchEvent(new Event("change"));
    await new Promise((resolve) => setTimeout(resolve, 400));
    select.focus();
    document.getElementById("connect-message").textContent = "";
    select.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 900));
    return document.getElementById("connect-message").textContent;
  `);
  assert.notEqual(viaEnter, "", "Enter on a saved connection starts a connection attempt");
  console.log(`• saved connections open from the list with Enter ("${viaEnter}")`);

  // From a select in the form: the case browsers do not submit from on their own. An
  // unused port makes the attempt fail at once rather than opening a session this run
  // would then have to clean up.
  const deadPort = await freePort();
  const tabsBefore = await evaluate(session, `return document.querySelectorAll("#tabstrip .tab").length;`);
  await evaluate(session, `
    const $ = (id) => document.getElementById(id);
    $("saved-profile").value = "";
    $("saved-profile").dispatchEvent(new Event("change"));
    await new Promise((resolve) => setTimeout(resolve, 200));
    $("host").value = ${JSON.stringify(server.host)};
    $("port").value = "${deadPort}";
    $("username").value = ${JSON.stringify(server.username)};
    $("auth-type").value = "password";
    $("auth-type").dispatchEvent(new Event("change"));
    $("password").value = ${JSON.stringify(server.password)};
    $("connect-message").textContent = "";
    const target = $("protocol");
    target.focus();
    target.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
    return true;
  `);
  const viaSelect = await waitFor(session,
    `(() => { const text = document.getElementById("connect-message").textContent; return text && text !== "Connecting…" ? text : false; })()`,
    "Enter in a select to start a connection attempt");
  assert.match(viaSelect, /ECONNREFUSED|closed|refused|failed|Destination/i,
    `Enter should have attempted a connection: ${viaSelect}`);
  assert.equal(await evaluate(session, `return document.querySelectorAll("#tabstrip .tab").length;`), tabsBefore,
    "a failed attempt leaves no tab behind");
  console.log(`• Enter connects from anywhere on the form, selects included ("${viaSelect.slice(0, 40)}…")`);

  // Back to the session the rest of the run works with.
  await evaluate(session, `
    document.getElementById("cancel-connect").click();
    await new Promise((resolve) => setTimeout(resolve, 400));
    return true;
  `);
  await waitFor(session, `document.getElementById("connect-view").classList.contains("hidden")`,
    "the workspace to come back");

  // Mouse tracking: a remote program really can take the mouse over SSH, and Shift
  // has to be able to take it back. This asks for DECSET 1000, the mode vim, tmux,
  // and less use, then watches what the terminal forwards.
  const reportsBefore = server.mouseReports();
  server.setMouseReporting(true);
  await new Promise((resolve) => setTimeout(resolve, 400));
  await setClipboard("untouched");
  await dragAcrossFirstLine(0);
  const grabbedReports = server.mouseReports() - reportsBefore;
  const grabbedSelection = await evaluate(session, `
    return document.querySelector("#terminals > div:not(.hidden) .xterm-selection div") !== null;
  `);
  assert.ok(grabbedReports > 0, "a plain drag must reach the remote program once it asks for the mouse");
  assert.equal(grabbedSelection, false, "and it must not select locally at the same time");
  assert.equal(await clipboard(), "untouched");

  const beforeShift = server.mouseReports();
  await dragAcrossFirstLine(8);
  assert.equal(server.mouseReports() - beforeShift, 0, "Shift must keep the drag away from the remote program");
  assert.match(await clipboard(), /test/, "Shift+drag still selects and copies while the mouse is grabbed");
  console.log(`• a remote program can grab the mouse (${grabbedReports} reports forwarded); Shift overrides it`);

  await setClipboard("untouched");
  const beforeMiddle = server.mouseReports();
  await middleDragAcrossFirstLine();
  assert.equal(server.mouseReports() - beforeMiddle, 0, "a middle-drag must stay away from the remote program");
  assert.match(await clipboard(), /test/, "a middle-drag still copies while the mouse is grabbed");
  console.log("• a middle-drag copies while the mouse is grabbed, and the program sees none of it");

  // A plain middle click is not a drag, so the program gets it after all: a press of
  // the middle button and a release, nothing selected and nothing copied. A wheel
  // pressed with a little wobble is still a click.
  {
    await setClipboard("untouched");
    const y = terminalBox.top + 14;
    const reportsBeforeClick = server.mouseReports();
    await mouse("mousePressed", terminalBox.left + 40, y, { button: "middle" });
    await mouse("mouseMoved", terminalBox.left + 42, y + 1, { button: "middle", buttons: 4 });
    await mouse("mouseReleased", terminalBox.left + 42, y + 1, { button: "middle" });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const reports = server.received().split("\u001b[M").slice(-(server.mouseReports() - reportsBeforeClick));
    assert.equal(reports.length, 2, `the program saw one press and one release (${reports.length} reports)`);
    assert.equal(reports[0][0], "!", "the press is reported as the middle button");
    assert.equal(reports[1][0], "#", "and then the button coming up");
    assert.equal(await clipboard(), "untouched", "a middle click copies nothing");
    console.log("• a middle click still reaches the program as a middle press and release");
  }

  // Shift pressed only after the drag has begun -- the press has already gone to the
  // program. The drag is taken back: the program is told the button came up, and the
  // text from the original press to the pointer is selected and copied.
  {
    await setClipboard("untouched");
    const y = terminalBox.top + 14;
    const reportsBeforeLate = server.mouseReports();
    await mouse("mousePressed", terminalBox.left + 10, y);
    await mouse("mouseMoved", terminalBox.left + 60, y);
    await new Promise((resolve) => setTimeout(resolve, 60));
    await session.send("Input.dispatchKeyEvent",
      { type: "rawKeyDown", modifiers: 8, key: "Shift", code: "ShiftLeft", windowsVirtualKeyCode: 16 });
    await mouse("mouseMoved", terminalBox.left + 120, y, { modifiers: 8 });
    await new Promise((resolve) => setTimeout(resolve, 60));
    await mouse("mouseReleased", terminalBox.left + 120, y, { modifiers: 8 });
    await session.send("Input.dispatchKeyEvent",
      { type: "keyUp", modifiers: 0, key: "Shift", code: "ShiftLeft", windowsVirtualKeyCode: 16 });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const reports = server.received().split("\u001b[M").slice(-(server.mouseReports() - reportsBeforeLate));
    assert.ok(reports.length >= 2, `the program saw the press and a release (${reports.length} reports)`);
    assert.equal(reports[reports.length - 1][0], "#", "the last thing the program saw is the button coming up");
    assert.match(await clipboard(), /test/, "Shift pressed mid-drag still copies the text dragged across");
    console.log(`• Shift pressed after the drag began takes it back from the program and copies (${reports.length} reports, ending in a release)`);
  }
  server.setMouseReporting(false);
  await new Promise((resolve) => setTimeout(resolve, 300));

  // A synthetic drop cannot carry a real local path, so the pane must still light
  // up and the failure must name the count instead of a vague refusal.
  const dropDiagnostic = await evaluate(session, `
    const pane = document.getElementById("files-pane");
    const transfer = new DataTransfer();
    transfer.items.add(new File(["synthetic"], "synthetic.txt", { type: "text/plain" }));
    pane.dispatchEvent(new DragEvent("dragenter", { dataTransfer: transfer, bubbles: true, cancelable: true }));
    const highlighted = pane.classList.contains("drop-target");
    pane.dispatchEvent(new DragEvent("drop", { dataTransfer: transfer, bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 400));
    return { highlighted, cleared: !pane.classList.contains("drop-target"), message: document.getElementById("file-message").textContent };
  `);
  assert.equal(dropDiagnostic.highlighted, true, "a file drag must highlight the pane");
  assert.equal(dropDiagnostic.cleared, true, "the overlay must clear after the drop");
  assert.match(dropDiagnostic.message, /1 dropped item/, "the failure names how many items had no local path");
  console.log(`• drop overlay and path diagnostics work ("${dropDiagnostic.message}")`);

  // A real inbound drop: Chromium builds native File objects from these paths, so
  // this exercises the same path-extraction the desktop file manager triggers.
  const localDrop = path.join(userData, "dropped upload.txt");
  fs.writeFileSync(localDrop, "dropped from the desktop\n");
  const paneCentre = await evaluate(session, `
    const box = document.getElementById("files-pane").getBoundingClientRect();
    return { x: Math.round(box.left + box.width / 2), y: Math.round(box.top + box.height / 2) };
  `);
  await evaluate(session, `
    window.__drops = [];
    window.addEventListener("drop", (event) => window.__drops.push(event.dataTransfer.files.length), true);
    return true;
  `);
  const nativeDrop = async (files) => {
    const data = { items: [], files, dragOperationsMask: 1 };
    for (const type of ["dragEnter", "dragOver", "drop"]) {
      await session.send("Input.dispatchDragEvent", { type, x: paneCentre.x, y: paneCentre.y, data });
    }
  };
  const waitForFile = async (target) => {
    const deadline = Date.now() + 15000;
    while (!fs.existsSync(target) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    assert.equal(fs.existsSync(target), true,
      `${target} should have been uploaded; last status: ${(await describeState(session)).fileMessage}; ` +
      `remote root holds ${JSON.stringify(fs.readdirSync(remoteRoot))}; ` +
      `drop events saw ${JSON.stringify(await evaluate(session, "return window.__drops;"))} files`);
  };

  // An uploaded file appears before its bytes do, so content is polled for rather
  // than read the moment the path exists.
  const waitForContent = async (target, expected) => {
    await waitForFile(target);
    const deadline = Date.now() + 15000;
    let seen = "";
    while (Date.now() < deadline) {
      seen = fs.readFileSync(target, "utf8");
      if (seen === expected) return;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    assert.equal(seen, expected, `${target} should hold its uploaded contents`);
  };

  let nativeDropSupported = true;
  try {
    await nativeDrop([localDrop]);
  } catch (error) {
    nativeDropSupported = false;
    console.log(`• native drop dispatch unavailable in this build: ${error.message}`);
  }
  if (nativeDropSupported) {
    await waitForContent(path.join(remoteRoot, "dropped upload.txt"), "dropped from the desktop\n");
    console.log("• a real dropped file uploaded into the shown remote folder");

    // Several items at once, including a nested folder with a space in its name.
    const folder = path.join(userData, "dropped folder");
    fs.mkdirSync(path.join(folder, "inner"), { recursive: true });
    fs.writeFileSync(path.join(folder, "inner", "leaf.txt"), "leaf\n");
    const second = path.join(userData, "second.txt");
    fs.writeFileSync(second, "second\n");
    await nativeDrop([second, folder]);
    await waitForContent(path.join(remoteRoot, "second.txt"), "second\n");
    await waitForContent(path.join(remoteRoot, "dropped folder", "inner", "leaf.txt"), "leaf\n");
    console.log("• a multi-item drop with a nested folder uploaded its whole tree");

    // Dropping a name that is already there must stop and ask. Each answer is
    // driven through the real dialog, and the remote folder is checked after every
    // one: the point of the dialog is that nothing moves until it is answered.
    const conflictRows = async () => evaluate(session, `
      const rows = [...document.querySelectorAll(".conflict-row")];
      return rows.map((row) => ({
        name: row.querySelector(".conflict-name").textContent,
        detail: row.querySelector(".conflict-detail").textContent,
        choice: row.querySelector("select").value,
        note: row.querySelector(".conflict-note")?.textContent || "",
        options: [...row.querySelectorAll("select option")].map((option) => option.value),
      }));
    `);
    const applyToAllOptions = async () => evaluate(session, `
      const select = document.querySelector(".conflict-all select");
      return select ? [...select.options].map((option) => option.value).filter(Boolean) : null;
    `);
    const answerConflicts = async (choice) => {
      await evaluate(session, `
        for (const row of document.querySelectorAll(".conflict-row")) {
          const select = row.querySelector("select");
          select.value = ${JSON.stringify(choice)};
          select.dispatchEvent(new Event("change"));
        }
        document.querySelector("#modal .modal-footer button:last-child").click();
        return true;
      `);
    };
    const remoteText = (...names) => fs.readFileSync(path.join(remoteRoot, ...names), "utf8");
    const uploadTarget = path.join(remoteRoot, "dropped upload.txt");
    const awaitDialog = () => waitFor(session,
      `document.querySelectorAll(".conflict-row").length`, "the upload collision dialog");

    fs.writeFileSync(localDrop, "a second attempt\n");
    await nativeDrop([localDrop]);
    await awaitDialog();
    const asked = await conflictRows();
    assert.equal(asked.length, 1, "one dropped name was already taken");
    assert.equal(asked[0].name, "dropped upload.txt");
    assert.equal(asked[0].choice, "overwrite", "a file collision offers to overwrite first");
    assert.deepEqual(asked[0].options, ["overwrite", "keep-both", "skip"]);
    assert.match(asked[0].detail, /On the host:.*Being uploaded:/);
    assert.equal(remoteText("dropped upload.txt"), "dropped from the desktop\n",
      "nothing may be written while the question is still on screen");
    console.log(`• a colliding drop asks before writing ("${asked[0].detail}")`);

    await answerConflicts("keep-both");
    await waitForContent(path.join(remoteRoot, "dropped upload_2.txt"), "a second attempt\n");
    assert.equal(remoteText("dropped upload.txt"), "dropped from the desktop\n",
      "keeping both must leave the original alone");
    console.log("• Keep both landed the drop beside the file already there");

    fs.writeFileSync(localDrop, "a third attempt\n");
    await nativeDrop([localDrop]);
    await awaitDialog();
    await answerConflicts("skip");
    await waitFor(session, `/Skipped/.test(document.getElementById("file-message").textContent)`,
      "the status line to report the skip");
    assert.equal(remoteText("dropped upload.txt"), "dropped from the desktop\n",
      "a skipped name is not touched");
    console.log("• Skip left the remote file exactly as it was");

    await nativeDrop([localDrop]);
    await awaitDialog();
    // Cancelling is a refusal, not a deferral: the drop is discarded unwritten.
    await evaluate(session, `document.querySelector("#modal .modal-footer button").click(); return true;`);
    await waitFor(session, `/cancelled/.test(document.getElementById("file-message").textContent)`,
      "the status line to report the cancellation");
    assert.equal(remoteText("dropped upload.txt"), "dropped from the desktop\n",
      "a cancelled drop writes nothing at all");
    console.log("• Cancel discarded the drop without writing");

    await nativeDrop([localDrop]);
    await awaitDialog();
    await answerConflicts("overwrite");
    await waitForContent(uploadTarget, "a third attempt\n");
    console.log("• Overwrite replaced the remote file once it was chosen");

    // A folder that is already there is one question about the folder, and merging
    // is what answering "overwrite" means.
    fs.writeFileSync(path.join(userData, "dropped folder", "inner", "leaf.txt"), "regrown leaf\n");
    fs.writeFileSync(path.join(userData, "dropped folder", "added.txt"), "added later\n");
    await nativeDrop([path.join(userData, "dropped folder")]);
    await awaitDialog();
    const folderAsked = await conflictRows();
    assert.equal(folderAsked.length, 1, "a folder collision is one question, not one per file inside");
    assert.match(folderAsked[0].detail, /folder/);
    await answerConflicts("overwrite");
    await waitForContent(path.join(remoteRoot, "dropped folder", "added.txt"), "added later\n");
    await waitForContent(path.join(remoteRoot, "dropped folder", "inner", "leaf.txt"), "regrown leaf\n");
    console.log("• a colliding folder asked once and merged when told to");

    // Two dropped items that clash with each other rather than with the host: a drag
    // out of a search results window gathers files from several folders, and two of
    // them can share a name. Nothing is in the way of the first write, so this is the
    // case probing the host alone would never see.
    const twinA = path.join(userData, "twin-a", "twin.txt");
    const twinB = path.join(userData, "twin-b", "twin.txt");
    fs.mkdirSync(path.dirname(twinA), { recursive: true });
    fs.mkdirSync(path.dirname(twinB), { recursive: true });
    fs.writeFileSync(twinA, "from the first folder\n");
    fs.writeFileSync(twinB, "from the second folder\n");
    await nativeDrop([twinA, twinB]);
    await awaitDialog();
    const twins = await conflictRows();
    assert.equal(twins.length, 1, "the shared name is one question, not one per copy");
    assert.equal(twins[0].name, "twin.txt");
    assert.match(twins[0].detail, /2 of the dropped items are named this/);
    assert.deepEqual(twins[0].options, ["keep-both", "overwrite", "skip"]);
    assert.equal(twins[0].choice, "keep-both", "a clash between two dropped items keeps both by default");
    await answerConflicts("keep-both");
    await waitForContent(path.join(remoteRoot, "twin.txt"), "from the first folder\n");
    await waitForContent(path.join(remoteRoot, "twin_2.txt"), "from the second folder\n");
    await waitFor(session, `/Kept both copies of twin\.txt/.test(document.getElementById("file-message").textContent)`,
      "the shared-name upload to report");
    console.log("• two dropped files sharing a name were asked about and both kept");

    // The same clash, between two dropped items that are not the same kind. Neither
    // can replace the other, so overwriting must not be among the answers -- the
    // same rule that applies to a kind clash with the host.
    const oddFile = path.join(userData, "odd-a", "mixed");
    const oddFolder = path.join(userData, "odd-b", "mixed");
    fs.mkdirSync(path.dirname(oddFile), { recursive: true });
    fs.mkdirSync(oddFolder, { recursive: true });
    fs.writeFileSync(oddFile, "i am a file\n");
    fs.writeFileSync(path.join(oddFolder, "inside.txt"), "i am inside\n");
    await nativeDrop([oddFile, oddFolder]);
    await awaitDialog();
    const mixed = await conflictRows();
    assert.equal(mixed.length, 1, "the shared name is still one question");
    assert.equal(mixed[0].name, "mixed");
    assert.deepEqual(mixed[0].options, ["keep-both", "skip"], "overwriting is not on offer");
    assert.match(mixed[0].note, /not all the same kind/);
    await answerConflicts("keep-both");
    await waitForContent(path.join(remoteRoot, "mixed"), "i am a file\n");
    await waitForContent(path.join(remoteRoot, "mixed_2", "inside.txt"), "i am inside\n");
    await waitFor(session, `/Kept both copies of mixed/.test(document.getElementById("file-message").textContent)`,
      "the mixed-kind upload to report");
    console.log("• a file and a folder dropped under one name were not offered overwriting");

    // Two of them brings out the "Apply to all" control, which must not offer an
    // answer that no row below it can take -- a whole column refusing it in silence
    // is the same broken promise as one row.
    const pairs = [["odd-c", "twinned"], ["odd-d", "twinned"], ["odd-e", "paired"], ["odd-f", "paired"]];
    const mixedPair = [];
    for (const [folder, name] of pairs) {
      const holder = path.join(userData, folder);
      fs.mkdirSync(holder, { recursive: true });
      const target = path.join(holder, name);
      if (folder === "odd-c" || folder === "odd-e") fs.writeFileSync(target, `${name} as a file\n`);
      else { fs.mkdirSync(target, { recursive: true }); fs.writeFileSync(path.join(target, "inside.txt"), `${name} inside\n`); }
      mixedPair.push(target);
    }
    await nativeDrop(mixedPair);
    await awaitDialog();
    const twoMixed = await conflictRows();
    assert.equal(twoMixed.length, 2, "two shared names, two questions");
    assert.deepEqual(await applyToAllOptions(), ["keep-both", "skip"],
      "Apply to all offers only what every row can take");
    await answerConflicts("keep-both");
    await waitForContent(path.join(remoteRoot, "twinned"), "twinned as a file\n");
    await waitForContent(path.join(remoteRoot, "twinned_2", "inside.txt"), "twinned inside\n");
    await waitFor(session, `/Kept both copies of/.test(document.getElementById("file-message").textContent)`,
      "the two-name mixed-kind upload to report");
    console.log("• Apply to all offered nothing the rows below it would refuse");

    // The path bar is a field at all times: the path is there to be selected and
    // copied, and a path can be typed or pasted straight over it.
    const pathState = async () => evaluate(session, `
      const input = document.getElementById("path-input");
      return {
        value: input.value,
        focused: document.activeElement === input,
        selected: [...document.querySelectorAll("#file-rows tr.selected .name-link")].map((a) => a.textContent),
        menu: [...document.querySelectorAll("#row-menu button")].map((b) => b.textContent),
        message: document.getElementById("file-message").textContent,
      };
    `);
    const typePath = async (value) => evaluate(session, `
      const input = document.getElementById("path-input");
      input.value = ${JSON.stringify(value)};
      input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
      return true;
    `);
    const pressCtrlL = async () => evaluate(session, `
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "l", ctrlKey: true, bubbles: true }));
      return true;
    `);
    const rightClickRow = async (name) => evaluate(session, `
      const row = [...document.querySelectorAll("#file-rows tr")]
        .find((tr) => tr.querySelector(".name-link")?.textContent === ${JSON.stringify(name)});
      if (!row) throw new Error("no row named " + ${JSON.stringify(name)});
      const box = row.getBoundingClientRect();
      row.dispatchEvent(new MouseEvent("contextmenu", {
        bubbles: true, cancelable: true,
        clientX: Math.round(box.left + 40), clientY: Math.round(box.top + 8),
      }));
      return true;
    `);
    const clickRow = async (name) => evaluate(session, `
      const row = [...document.querySelectorAll("#file-rows tr")]
        .find((tr) => tr.querySelector(".name-link")?.textContent === ${JSON.stringify(name)});
      if (!row) throw new Error("no row named " + ${JSON.stringify(name)});
      row.click();
      return true;
    `);

    await evaluate(session, `document.getElementById("home").click(); return true;`);
    await waitFor(session, `document.getElementById("file-message").textContent === "Ready"`, "the home listing");

    // No asking for an editor first: the path is sitting in a field, selectable.
    const resting = await pathState();
    assert.equal(resting.value, remoteRoot, "the field holds the folder shown, with no click needed");
    await pressCtrlL();
    const focused = await evaluate(session, `
      const input = document.getElementById("path-input");
      return { focused: document.activeElement === input, all: input.selectionStart === 0 && input.selectionEnd === input.value.length };
    `);
    assert.deepEqual(focused, { focused: true, all: true }, "Ctrl+L selects the whole path, ready to copy");
    console.log(`• the path sits in a field and Ctrl+L selects it ("${resting.value}")`);

    // And it reaches the path box from the search box, the way Ctrl+F reaches the
    // search box from here. Being in one field is no reason not to ask for the other.
    await evaluate(session, `
      const search = document.getElementById("search");
      search.focus();
      search.dispatchEvent(new KeyboardEvent("keydown", { key: "l", ctrlKey: true, bubbles: true }));
      return true;
    `);
    assert.equal((await pathState()).focused, true, "Ctrl+L reaches the path box from the search box");
    console.log("• Ctrl+L reaches the path box from the search box as well");

    // Typing a path over it and pressing Enter goes there. Explorer's quotes and a
    // trailing newline are what a pasted path actually arrives with.
    await typePath(`"${path.posix.join(remoteRoot, "documents")}"\n`);
    // Exact, not endsWith: a loose predicate here would match the text just typed and
    // let the next step run before the listing had landed.
    await waitFor(session, `document.getElementById("path-input").value === ${JSON.stringify(path.posix.join(remoteRoot, "documents"))}`,
      "the pasted folder to open");
    console.log("• a quoted path with a trailing newline pasted over it and opened");

    // A path naming a file opens the folder holding it and selects the file.
    await typePath(path.posix.join(remoteRoot, "documents", "reports", "q1 results.txt"));
    await waitFor(session, `/Opened the folder holding/.test(document.getElementById("file-message").textContent)`,
      "the folder holding the pasted file");
    const landed = await pathState();
    assert.equal(landed.value, path.posix.join(remoteRoot, "documents", "reports"));
    assert.deepEqual(landed.selected, ["q1 results.txt"], "the file named by the path is selected");
    console.log("• a pasted file path opened its folder and selected it");

    await typePath("~");
    await waitFor(session, `document.getElementById("path-input").value === ${JSON.stringify(remoteRoot)}`, "the home folder");
    await typePath("documents/reports");
    await waitFor(session, `document.getElementById("path-input").value === ${JSON.stringify(path.posix.join(remoteRoot, "documents", "reports"))}`,
      "the relative path to open");
    console.log("• ~ and a relative path both resolved");

    await typePath("C:\\Users\\exampleuser\\notes.txt");
    await waitFor(session, `/not on the host/.test(document.getElementById("file-message").textContent)`,
      "the local-path refusal");
    const refused = await pathState();
    assert.equal(refused.value, path.posix.join(remoteRoot, "documents", "reports"),
      "a refused path leaves the field showing where you actually are");
    console.log(`• a Windows path was refused by name ("${refused.message}")`);

    // Escape puts back the folder actually being shown, rather than leaving the field
    // claiming somewhere you are not.
    await evaluate(session, `
      const input = document.getElementById("path-input");
      input.focus();
      input.value = "/somewhere/else";
      input.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
      return true;
    `);
    assert.equal((await pathState()).value, path.posix.join(remoteRoot, "documents", "reports"),
      "Escape restores the shown folder");
    // So does moving on without entering it -- but the window losing focus must not,
    // since fetching a path from another application is half the reason to type here.
    await evaluate(session, `
      const input = document.getElementById("path-input");
      input.focus();
      input.value = "/half-typed";
      const real = document.hasFocus.bind(document);
      document.hasFocus = () => false;
      try { input.dispatchEvent(new FocusEvent("blur")); } finally { document.hasFocus = real; }
      return true;
    `);
    assert.equal((await pathState()).value, "/half-typed", "the window losing focus keeps what was typed");
    // A real focus move, which is the gesture this is about.
    await evaluate(session, `
      document.getElementById("path-input").focus();
      document.getElementById("path-input").value = "/half-typed";
      document.getElementById("search").focus();
      return true;
    `);
    assert.equal((await pathState()).value, path.posix.join(remoteRoot, "documents", "reports"),
      "moving on inside the window puts the shown folder back");
    console.log("• Escape and moving away restored the shown folder; a window switch did not");

    // Ctrl+L belongs to the shell while the terminal has it. Taking it there would
    // cost the one binding every shell uses for clearing the screen.
    await evaluate(session, `
      const textarea = document.querySelector(".terminal .xterm-helper-textarea");
      textarea.focus();
      textarea.dispatchEvent(new KeyboardEvent("keydown", { key: "l", ctrlKey: true, bubbles: true }));
      return true;
    `);
    assert.equal((await pathState()).focused, false, "the terminal keeps Ctrl+L for itself");
    console.log("• Ctrl+L in the terminal stayed with the shell");

    // Copy as path, on the row itself.
    await evaluate(session, `document.getElementById("home").click(); return true;`);
    await waitFor(session, `document.getElementById("file-message").textContent === "Ready"`, "the home listing");
    await setClipboard("untouched");
    await rightClickRow("readme.txt");
    assert.deepEqual((await pathState()).menu, ["Copy as path"], "right-clicking a row offers Copy as path");
    await evaluate(session, `document.querySelector("#row-menu button").click(); return true;`);
    await waitFor(session, `window.sshWorkbench.clipboard.read().then((text) => text !== "untouched")`,
      "the row's path to reach the clipboard");
    assert.equal(await clipboard(), path.posix.join(remoteRoot, "readme.txt"));
    assert.deepEqual((await pathState()).menu, [], "the menu closes once it has been used");
    console.log("• right-click Copy as path put one row's full path on the clipboard");

    // A whole selection at once, and a name that a shell would misread is quoted.
    await clickRow("readme.txt");
    await clickRow("dropped upload.txt");
    await rightClickRow("readme.txt");
    assert.deepEqual((await pathState()).menu, ["Copy 2 paths"], "the menu says how many it will copy");
    await evaluate(session, `document.querySelector("#row-menu button").click(); return true;`);
    await waitFor(session, `window.sshWorkbench.clipboard.read().then((text) => text.includes("readme.txt") && text.includes("dropped upload.txt"))`,
      "both paths to reach the clipboard");
    assert.deepEqual((await clipboard()).split("\n").sort(), [
      `'${path.posix.join(remoteRoot, "dropped upload.txt")}'`,
      path.posix.join(remoteRoot, "readme.txt"),
    ].sort(), "a name with a space is quoted for a shell; a plain one is left bare");
    console.log("• a selection copied one path per line, quoting the one that needed it");

    // Escape closes the menu without copying anything.
    await setClipboard("untouched");
    await rightClickRow("readme.txt");
    await evaluate(session, `document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true })); return true;`);
    assert.deepEqual((await pathState()).menu, [], "Escape closes the menu");
    assert.equal(await clipboard(), "untouched", "and copies nothing");
    console.log("• Escape closed the row menu without copying");

    // The checks that follow paste into the folder the session started in.
    await evaluate(session, `document.getElementById("home").click(); return true;`);
    await waitFor(session, `document.getElementById("path-input").value === ${JSON.stringify(remoteRoot)} && document.getElementById("file-message").textContent === "Ready"`,
      "the session back at its home folder");
  }

  // Pasting a screenshot: the clipboard image has no local path, only bytes, which
  // is exactly what a snipping tool leaves behind.
  const pasted = await evaluate(session, `
    // A one-pixel PNG, built here so the bytes are known.
    const base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==";
    const bytes = Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
    const transfer = new DataTransfer();
    transfer.items.add(new File([bytes], "image.png", { type: "image/png" }));
    document.body.focus();
    document.body.dispatchEvent(new ClipboardEvent("paste", { clipboardData: transfer, bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 1500));
    return { message: document.getElementById("file-message").textContent, expected: bytes.length };
  `);
  const pastedFiles = fs.readdirSync(remoteRoot).filter((name) => name.startsWith("pasted-"));
  assert.equal(pastedFiles.length, 1, `a pasted image should land as a file; status: ${pasted.message}`);
  assert.match(pastedFiles[0], /^pasted-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}\.png$/);
  assert.equal(fs.statSync(path.join(remoteRoot, pastedFiles[0])).size, pasted.expected,
    "the image arrives byte for byte");
  assert.match(pasted.message, /Pasted pasted-/);
  console.log(`• a pasted screenshot uploads as ${pastedFiles[0]} (${pasted.expected} bytes)`);

  // The same paste aimed at the terminal must still reach the folder: a clipboard
  // image has only one possible destination, so focus must not decide.
  const pastedFromTerminal = await evaluate(session, `
    const base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==";
    const bytes = Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
    const transfer = new DataTransfer();
    transfer.items.add(new File([bytes], "image.png", { type: "image/png" }));
    const textarea = document.querySelector("#terminals > div:not(.hidden) .xterm-helper-textarea");
    textarea.focus();
    textarea.dispatchEvent(new ClipboardEvent("paste", { clipboardData: transfer, bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 1500));
    return {
      message: document.getElementById("file-message").textContent,
      focused: document.activeElement === textarea,
      shell: document.querySelector("#terminals > div:not(.hidden) .xterm-rows").textContent,
    };
  `);
  assert.equal(pastedFromTerminal.focused, true, "the terminal really had focus");
  assert.equal(fs.readdirSync(remoteRoot).filter((name) => name.startsWith("pasted-")).length, 2,
    `pasting with the terminal focused must still upload; status: ${pastedFromTerminal.message}`);
  assert.doesNotMatch(pastedFromTerminal.shell, /PNG|IHDR/, "and no image bytes were typed into the shell");
  console.log("• a screenshot pasted with the terminal focused still uploads");

  // A right-click pastes text only: a screenshot on the real system clipboard is not
  // uploaded from it, and nothing reaches the shell. Shift+Insert then uploads the
  // same image, which shows it really was on the clipboard.
  {
    // The page may not write an image to the clipboard, so a second Electron process
    // puts one there, as a snipping tool would, and holds it until it is killed: on
    // X11 a clipboard empties when the program that owns it exits.
    const helperDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-e2e-clipboard-"));
    fs.writeFileSync(path.join(helperDirectory, "main.cjs"), `
      const { app, clipboard, nativeImage } = require("electron");
      app.whenReady().then(() => {
        // A real 4x4 PNG: the one-pixel one above is only ever sent as bytes and does not decode.
        const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAIAAAAmkwkpAAAAEElEQVR4nGP4z8AARwzEcQCukw/x0F8jngAAAABJRU5ErkJggg==", "base64");
        clipboard.writeImage(nativeImage.createFromBuffer(png));
        console.log("image-on-clipboard");
      });
    `);
    const holder = spawn(path.join(repository, "node_modules", ".bin", "electron"),
      [path.join(helperDirectory, "main.cjs"), `--user-data-dir=${path.join(helperDirectory, "profile")}`],
      { stdio: ["ignore", "pipe", "pipe"] });
    onCleanup(() => { if (!holder.killed) holder.kill("SIGKILL"); });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("the clipboard helper never put its image up")), 20000);
      holder.stdout.on("data", (chunk) => { if (String(chunk).includes("image-on-clipboard")) { clearTimeout(timer); resolve(); } });
    });
    await waitFor(session, `(await window.sshWorkbench.clipboard.read()) === ""`,
      "the application to see the clipboard holding no text, only the image");
    await evaluate(session, `document.querySelector("#terminals > div:not(.hidden) .xterm-helper-textarea").focus(); return true;`);
    const pastedCount = () => fs.readdirSync(remoteRoot).filter((name) => name.startsWith("pasted-")).length;
    const before = pastedCount();
    const inputBefore = server.received().length;
    await evaluate(session, `
      document.querySelector("#terminals > div:not(.hidden)")
        .dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true }));
      return true;
    `);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    assert.equal(pastedCount(), before, "a right-click must not upload the clipboard image");
    assert.equal(server.received().slice(inputBefore), "", "and must send nothing to the shell");
    assert.match(await evaluate(session, `return document.getElementById("file-message").textContent;`), /Right-click pastes text only/, "the status line says why nothing happened");

    for (const type of ["rawKeyDown", "keyUp"]) {
      await session.send("Input.dispatchKeyEvent",
        { type, modifiers: 8, key: "Insert", code: "Insert", windowsVirtualKeyCode: 45 });
    }
    await waitFor(session, `document.getElementById("file-message").textContent.startsWith("Pasted pasted-")`,
      "Shift+Insert to upload the image");
    assert.equal(pastedCount(), before + 1, "Shift+Insert still uploads it");
    holder.kill("SIGKILL");
    console.log("• a right-click leaves a clipboard screenshot alone; Shift+Insert still uploads it");
  }

  // A paste carrying a real local path uploads by path instead of by bytes.
  const pastedPath = path.join(userData, "pasted by path.txt");
  fs.writeFileSync(pastedPath, "from the clipboard\n");
  const pastedByPath = await evaluate(session, `
    const transfer = new DataTransfer();
    transfer.items.add(new File(["ignored"], "pasted by path.txt", { type: "text/plain" }));
    document.body.dispatchEvent(new ClipboardEvent("paste", { clipboardData: transfer, bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 800));
    return document.getElementById("file-message").textContent;
  `);
  assert.match(pastedByPath, /clipboard holds nothing that can be pasted|Pasted/,
    "a synthetic text file has neither a path nor image bytes, and that is reported");
  console.log(`• a pasteable-but-pathless text file is reported ("${pastedByPath}")`);

  // A connection that vanishes must mark its tab instead of pretending to work.
  server.dropClients();
  await waitFor(session, `document.querySelectorAll("#tabstrip .tab.offline").length === 2`, "both tabs to go offline");
  assert.equal(await evaluate(session, `return document.getElementById("reconnect").classList.contains("hidden");`),
    false, "a disconnected session offers Reconnect");
  assert.equal(await evaluate(session, `return document.getElementById("upload-files").disabled;`), true,
    "remote actions are disabled while disconnected");
  console.log("• a dropped connection marks its tab and disables remote actions");

  await evaluate(session, `document.getElementById("reconnect").click(); return true;`);
  await waitFor(session, `!document.getElementById("connect-view").classList.contains("hidden")`, "the reconnect form");
  await evaluate(session, fillAndSubmit(server));
  await waitFor(session, `document.querySelectorAll("#tabstrip .tab.offline").length === 1`, "one tab back online");
  await waitFor(session, `document.querySelectorAll("#file-rows tr").length > 0`, "the reconnected listing");
  assert.equal(await evaluate(session, `return document.querySelectorAll("#tabstrip .tab").length;`), 2,
    "reconnecting reuses the same tab");
  console.log("• Reconnect revives the same tab without adding another");

  // Closing one tab leaves the other running.
  await evaluate(session, `document.querySelectorAll("#tabstrip .tab")[0].querySelector(".tab-close").click(); return true;`);
  await waitFor(session, `document.querySelectorAll("#tabstrip .tab").length === 1`, "one tab after closing");
  await waitFor(session, `document.querySelectorAll("#terminals > div").length === 1`, "one terminal after closing");
  assert.equal(await evaluate(session, `return document.getElementById("workspace").classList.contains("hidden");`), false,
    "the surviving session stays open");
  console.log("• closing a tab keeps the remaining session");

  // Closing the last tab returns to the connect view.
  await evaluate(session, `document.getElementById("disconnect").click(); return true;`);
  await waitFor(session, `!document.getElementById("connect-view").classList.contains("hidden")`,
    "the connect view after the last session closes");
  assert.equal(await evaluate(session, `return document.querySelectorAll("#tabstrip .tab").length;`), 0);
  console.log("• the last close returns to the connect view");

  // A master password over the saved credentials: set it, lock it, and check that
  // opening a saved connection is what asks for it. Each step waits for the modal to
  // settle rather than guessing at how long deriving a key takes.
  const modalSettled = async (label) => {
    try {
      return await waitFor(session, `(() => {
        const backdrop = document.getElementById("modal-backdrop");
        if (backdrop.classList.contains("hidden")) return "closed";
        const error = document.querySelector("#modal .form-message")?.textContent || "";
        return error ? "error: " + error : false;
      })()`, label);
    } catch (failure) {
      const diagnostic = await evaluate(session, `
        return {
          title: document.querySelector("#modal .modal-header h2")?.textContent || null,
          buttons: [...document.querySelectorAll("#modal .modal-footer button")].map((button) => button.textContent),
          fields: [...document.querySelectorAll("#modal .password-form input[type=password]")].map((input) => input.value.length),
          vault: await window.sshWorkbench.vault.status(),
        };
      `).catch((error) => ({ unavailable: String(error.message) }));
      throw new Error(`${failure.message}\nmodal: ${JSON.stringify(diagnostic)}`);
    }
  };

  const masterFields = await evaluate(session, `
    document.getElementById("master-manage").click();
    await new Promise((resolve) => setTimeout(resolve, 200));
    return {
      fields: document.querySelectorAll("#modal .password-form input[type=password]").length,
      title: document.querySelector("#modal .modal-header h2")?.textContent || "",
    };
  `);
  assert.equal(masterFields.title, "Set a master password");
  assert.equal(masterFields.fields, 2, "a new master password is typed twice");

  const mismatch = await evaluate(session, `
    const fields = [...document.querySelectorAll("#modal .password-form input[type=password]")];
    fields[0].value = "an e2e master password";
    fields[1].value = "a different password";
    document.querySelector("#modal .modal-footer button.primary").click();
    return true;
  `);
  assert.ok(mismatch);
  assert.match(await modalSettled("the mismatched passwords to be refused"), /^error: Those two passwords are not the same/);

  await evaluate(session, `
    const fields = [...document.querySelectorAll("#modal .password-form input[type=password]")];
    fields[0].value = "an e2e master password";
    fields[1].value = "an e2e master password";
    const radios = [...document.querySelectorAll("#modal .policy-control input[type=radio]")];
    radios[1].checked = true;
    document.querySelector("#modal .policy-minutes").value = "30";
    document.querySelector("#modal .modal-footer button.primary").click();
    return true;
  `);
  assert.equal(await modalSettled("the master password to be set"), "closed");
  const masterSet = await evaluate(session, `
    return {
      state: document.getElementById("master-state").textContent,
      canSaveCredentials: !document.getElementById("save-credentials").disabled,
      lockOffered: !document.getElementById("master-lock").classList.contains("hidden"),
    };
  `);
  assert.match(masterSet.state, /unlocked for 30 more minutes/);
  assert.equal(masterSet.canSaveCredentials, true, "a master password makes saving credentials possible");
  assert.equal(masterSet.lockOffered, true, "an unlocked vault offers Lock now");
  console.log(`• a master password can be set ("${masterSet.state}")`);

  // Save the connection again, this time with its password, then lock. It is chosen
  // in the list first: a fresh form saved under a name already taken is refused
  // rather than quietly replacing the connection of that name.
  const savedWithCredentials = await evaluate(session, `
    const $ = (id) => document.getElementById(id);
    const existing = [...$("saved-profile").options].find((option) => option.textContent.startsWith("Test target"));
    if (existing) {
      $("saved-profile").value = existing.value;
      $("saved-profile").dispatchEvent(new Event("change"));
      await new Promise((resolve) => setTimeout(resolve, 400));
    }
    $("host").value = ${JSON.stringify(server.host)};
    $("port").value = "${server.port}";
    $("username").value = ${JSON.stringify(server.username)};
    $("auth-type").value = "password";
    $("auth-type").dispatchEvent(new Event("change"));
    $("password").value = ${JSON.stringify(server.password)};
    $("profile-name").value = "Test target";
    $("save-credentials").checked = true;
    $("save-profile").click();
    await new Promise((resolve) => setTimeout(resolve, 1200));
    // Read the save result before locking, which posts a message of its own.
    const message = $("connect-message").textContent;
    $("master-lock").click();
    await new Promise((resolve) => setTimeout(resolve, 400));
    return {
      message,
      state: $("master-state").textContent,
      // Locking the key in the other process is only half of it: a password already
      // sitting in this field would still open a connection with nothing asked.
      secretsLeftInTheForm: [$("password").value, $("passphrase").value,
        $("jump-password").value, $("jump-passphrase").value].filter(Boolean),
    };
  `);
  assert.match(savedWithCredentials.message, /encrypted credentials/,
    `credentials should be saved: ${savedWithCredentials.message}`);
  assert.match(savedWithCredentials.state, /locked/i, "Lock now locks the saved credentials");
  assert.deepEqual(savedWithCredentials.secretsLeftInTheForm, [],
    "Lock now takes back the decrypted copy the window was holding, not just the key");
  console.log("• credentials save under the master password, and Lock now clears the form too");

  // Choosing a saved connection reads nothing secret, so it must ask for nothing —
  // including when it is chosen for you at startup because it was the last one used.
  const onSelect = await evaluate(session, `
    const select = document.getElementById("saved-profile");
    const option = [...select.options].find((candidate) => candidate.textContent.startsWith("Test target"));
    document.getElementById("password").value = "";
    select.value = option.value;
    select.dispatchEvent(new Event("change"));
    await new Promise((resolve) => setTimeout(resolve, 900));
    return {
      prompted: !document.getElementById("modal-backdrop").classList.contains("hidden"),
      message: document.getElementById("connect-message").textContent,
      host: document.getElementById("host").value,
      passwordField: document.getElementById("password").value,
    };
  `);
  assert.equal(onSelect.prompted, false, "choosing a saved connection does not ask for the master password");
  assert.equal(onSelect.host, server.host, "its details are loaded all the same");
  assert.equal(onSelect.passwordField, "", "and no saved credential has been handed over yet");
  assert.match(onSelect.message, /asked for when you connect/);
  console.log("• choosing a locked saved connection loads it without asking for anything");

  // Pressing Connect is the moment the credential is used, so that is when it asks.
  await evaluate(session, `
    document.getElementById("quick-connect").click();
    return true;
  `);
  await waitFor(session, `!document.getElementById("modal-backdrop").classList.contains("hidden")`,
    "the unlock prompt to appear on connecting");
  const promptTitle = await evaluate(session, `return document.querySelector("#modal .modal-header h2")?.textContent || "";`);
  assert.equal(promptTitle, "Unlock saved credentials");

  await evaluate(session, `
    document.querySelector("#modal .password-form input[type=password]").value = "not the master password";
    document.querySelector("#modal .modal-footer button.primary").click();
    return true;
  `);
  assert.match(await modalSettled("the wrong master password to be refused"), /^error: .*not correct/);

  await evaluate(session, `
    document.querySelector("#modal .password-form input[type=password]").value = "an e2e master password";
    document.querySelector("#modal .modal-footer button.primary").click();
    return true;
  `);
  assert.equal(await modalSettled("the right master password to be accepted"), "closed");
  // The credential goes to the connection rather than back into the form, so what
  // proves it arrived is that the session opens.
  await waitFor(session, `document.querySelectorAll("#tabstrip .tab").length > 0`,
    "the session the saved credential opened");
  console.log("• Connect is what asks, and the right master password opens the session");

  await evaluate(session, `
    document.getElementById("disconnect").click();
    await new Promise((resolve) => setTimeout(resolve, 600));
    return true;
  `);
  await waitFor(session, `!document.getElementById("connect-view").classList.contains("hidden")`,
    "the connect view after closing that session");

  // Put it back as it was. Where the machine has no secure keyring — a headless
  // Linux build host, for one — removing the master password means forgetting the
  // credentials it was protecting, and the button says as much.
  const keyring = await evaluate(session, `return (await window.sshWorkbench.profiles.security()).available;`);
  const removeLabel = await evaluate(session, `
    document.getElementById("master-manage").click();
    await new Promise((resolve) => setTimeout(resolve, 200));
    document.querySelector("#modal .modal-footer button.danger").click();
    await new Promise((resolve) => setTimeout(resolve, 200));
    const confirm = document.querySelector("#modal .modal-footer button.primary");
    document.querySelector("#modal .password-form input[type=password]").value = "an e2e master password";
    const label = confirm.textContent;
    confirm.click();
    return label;
  `);
  assert.match(removeLabel, keyring ? /^Remove it$/ : /forget the credentials/,
    "the button says what removing it will actually do");
  assert.equal(await modalSettled("the master password to be removed"), "closed");
  const removed = await evaluate(session, `
    return {
      state: document.getElementById("master-state").textContent,
      options: [...document.getElementById("saved-profile").options].map((option) => option.textContent),
    };
  `);
  assert.match(removed.state, /No master password/);
  if (!keyring) {
    assert.ok(!removed.options.some((name) => name.includes("credentials saved")),
      `credentials with nothing left to protect them are forgotten (${JSON.stringify(removed.options)})`);
  }
  console.log(`• the master password can be removed again (keyring ${keyring ? "available" : "unavailable"})`);

  // The SCP fallback, in the real interface: the same trusted host, with its SFTP
  // subsystem switched off underneath it.
  server.setSftp(false);
  const beforeScp = await evaluate(session, `return document.querySelectorAll("#tabstrip .tab").length;`);
  await evaluate(session, `
    const $ = (id) => document.getElementById(id);
    if (!document.getElementById("workspace").classList.contains("hidden")) {
      $("new-session").click();
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
    $("host").value = ${JSON.stringify(server.host)};
    $("port").value = "${server.port}";
    $("username").value = ${JSON.stringify(server.username)};
    $("auth-type").value = "password";
    $("auth-type").dispatchEvent(new Event("change"));
    $("password").value = ${JSON.stringify(server.password)};
    $("protocol").value = "sftp-scp";
    $("protocol").dispatchEvent(new Event("change"));
    $("start-path").value = "~";
    $("connect-form").requestSubmit();
    return true;
  `);
  await waitFor(session, `document.querySelectorAll("#tabstrip .tab").length === ${beforeScp} + 1`,
    "the SCP session tab");
  await waitFor(session, `document.getElementById("connection-label").textContent.includes("SCP")`,
    "the label to show which protocol is in use");
  // The label is set as soon as the session exists; the notice comes once the first
  // folder has been listed over the fallback.
  await waitFor(session, `document.getElementById("file-message").textContent.includes("SFTP was unavailable")`,
    "the fallback notice");
  const overScp = await evaluate(session, `
    return {
      label: document.getElementById("connection-label").textContent,
      names: [...document.querySelectorAll("#file-rows .name-link")].map((node) => node.textContent).sort(),
    };
  `);
  assert.match(overScp.label, /· SCP/, "a session that fell back says so in its label");
  // Whatever the earlier checks left behind, the pane's idea of the folder has to
  // match the folder itself — that is what parsing ls output has to get right.
  assert.deepEqual(overScp.names, fs.readdirSync(remoteRoot).sort(),
    "the listing read from ls matches the real folder");
  console.log(`• SCP fallback works in the interface ("${overScp.label.trim()}")`);

  // A folder made and removed over the shell, so the write path is exercised too.
  const shellWrites = await evaluate(session, `
    const $ = (id) => document.getElementById(id);
    $("new-folder").click();
    await new Promise((resolve) => setTimeout(resolve, 200));
    document.querySelector("#modal input").value = "made over scp";
    document.querySelector("#modal .modal-footer button:last-child").click();
    await new Promise((resolve) => setTimeout(resolve, 1200));
    return {
      names: [...document.querySelectorAll("#file-rows .name-link")].map((node) => node.textContent).sort(),
      message: $("file-message").textContent,
    };
  `);
  assert.ok(shellWrites.names.includes("made over scp"),
    `a folder should be created over the shell (${shellWrites.message})`);
  assert.equal(fs.existsSync(path.join(remoteRoot, "made over scp")), true, "and it exists on the host");
  console.log("• folders can be created over the SCP transport");

  server.setSftp(true);

  // Two quick Enters must not open two sessions. A disabled submit button does not
  // stop requestSubmit(), so this is worth holding onto.
  const beforeDouble = await evaluate(session, `return document.querySelectorAll("#tabstrip .tab").length;`);
  await evaluate(session, `
    const $ = (id) => document.getElementById(id);
    if (document.getElementById("connect-view").classList.contains("hidden")) {
      $("new-session").click();
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
    $("host").value = ${JSON.stringify(server.host)};
    $("port").value = "${server.port}";
    $("username").value = ${JSON.stringify(server.username)};
    $("auth-type").value = "password";
    $("auth-type").dispatchEvent(new Event("change"));
    $("password").value = ${JSON.stringify(server.password)};
    $("protocol").value = "sftp-scp";
    $("start-path").value = "~";
    const press = () => $("host").dispatchEvent(
      new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
    $("host").focus();
    press();
    press();
    return true;
  `);
  await waitFor(session, `document.querySelectorAll("#tabstrip .tab").length === ${beforeDouble} + 1`,
    "one session from the double Enter");
  // Give a second connection time to appear if the guard were not there.
  await evaluate(session, `await new Promise((resolve) => setTimeout(resolve, 1500)); return true;`);
  assert.equal(await evaluate(session, `return document.querySelectorAll("#tabstrip .tab").length;`),
    beforeDouble + 1, "pressing Enter twice opens one session, not two");
  console.log("• pressing Enter twice opens one session");

  await evaluate(session, `
    document.getElementById("disconnect").click();
    await new Promise((resolve) => setTimeout(resolve, 600));
    return true;
  `);
  await waitFor(session, `document.querySelectorAll("#tabstrip .tab").length === ${beforeDouble}`,
    "that session to close again");

  // Outbound drag is checked last: on Linux the native drag loop keeps running
  // until a real pointer releases it, so nothing after it would respond.
  await evaluate(session, fillAndSubmit(server));
  await waitFor(session,
    `[...document.querySelectorAll("#file-rows .name-link")].some((node) => node.textContent === "readme.txt")`,
    "a fresh session for the outbound drag");
  await evaluate(session, `
    const row = [...document.querySelectorAll("#file-rows .name-link")]
      .find((node) => node.textContent === "readme.txt").closest("tr");
    row.dispatchEvent(new DragEvent("dragstart", { dataTransfer: new DataTransfer(), bubbles: true, cancelable: true }));
    return true;
  `);
  const stagedDeadline = Date.now() + 15000;
  const findStaged = () => {
    const cache = path.join(userData, "drag-cache");
    if (!fs.existsSync(cache)) return null;
    const stack = [cache];
    while (stack.length) {
      const current = stack.pop();
      for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        const full = path.join(current, entry.name);
        if (entry.isDirectory()) stack.push(full);
        else if (entry.name === "readme.txt") return full;
      }
    }
    return null;
  };
  let staged = null;
  // Poll for the finished content: the file appears before its bytes arrive.
  while (Date.now() < stagedDeadline) {
    const candidate = findStaged();
    if (candidate && fs.readFileSync(candidate, "utf8") === "hello from the test server\n") {
      staged = candidate;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  assert.ok(staged, `an outbound drag must stage a real file; status: ${(await describeState(session)).fileMessage}`);
  console.log(`• outbound drag staged a real file (${path.relative(userData, staged)})`);



  if (session.problems.length) {
    throw new Error(`Renderer reported problems:\n${session.problems.join("\n")}`);
  }
  console.log("\nAll multi-session checks passed.");
}

try {
  await main();
} catch (error) {
  process.exitCode = 1;
  console.error(error);
} finally {
  for (const run of cleanups.reverse()) {
    try { await run(); } catch { /* best-effort teardown */ }
  }
  setTimeout(() => process.exit(process.exitCode ?? 0), 500).unref();
}

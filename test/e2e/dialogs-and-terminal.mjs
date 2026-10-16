// End-to-end checks for the dialogs and the terminal: the editor that will not lose
// an edit, dialogs that wait their turn instead of replacing one another, dialog
// buttons that cannot run twice, a sudo question for a background tab that waits for
// that tab, pastes that cannot carry control characters, and the copy, width and
// file-opening details around them. The application is launched for real and driven
// over the Chrome DevTools Protocol; the main process is reached through its own
// inspector, to raise the events a host would raise. Run it with `npm run e2e`; a
// virtual display is required on headless machines
// (`xvfb-run -a node test/e2e/dialogs-and-terminal.mjs`).

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
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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

async function devtoolsTarget(port, wanted) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const target = targets.find((item) => wanted(item) && item.webSocketDebuggerUrl);
      if (target) return target.webSocketDebuggerUrl;
    } catch { /* still starting */ }
    await sleep(200);
  }
  throw new Error(`No DevTools target on port ${port}`);
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

async function main() {
  const remoteRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-e2e-remote-"));
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-e2e-dialogs-"));
  onCleanup(() => fs.rmSync(remoteRoot, { recursive: true, force: true }));
  onCleanup(() => fs.rmSync(userData, { recursive: true, force: true }));
  const files = {
    "notes.txt": "first line\n",
    "settings.ini": Buffer.from("[section]\r\nkey=value\r\nother=1\r\n"),
    "menu.txt": Buffer.from("caf\xe9 cr\xe8me\n", "latin1"),
    "app.conf": "workers=4\n",
    "scan.png": Buffer.alloc(21 * 1024 * 1024, 1),
    "projects/archive/old.txt": "old\n",
    "projects/readme.txt": "hello\n",
  };
  for (const [name, contents] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(remoteRoot, name)), { recursive: true });
    fs.writeFileSync(path.join(remoteRoot, name), contents);
  }
  // A little latency, so a second Enter can arrive while the first is still running.
  const server = await startTestServer({ root: remoteRoot, latency: 120 });
  onCleanup(() => server.close());
  fs.writeFileSync(path.join(userData, "known-hosts.json"), JSON.stringify({
    version: 1,
    hosts: { [`${server.host}:${server.port}`]: { sha256: fingerprint(server.hostPublicKey) } },
  }));

  const debugPort = await freePort();
  const inspectPort = await freePort();
  const electron = spawn(
    path.join(repository, "node_modules", ".bin", "electron"),
    [`--inspect=${inspectPort}`, ".", `--remote-debugging-port=${debugPort}`, `--user-data-dir=${userData}`, "--no-take-over"],
    { cwd: repository, stdio: ["ignore", "pipe", "pipe"], detached: true },
  );
  const output = [];
  electron.stdout.on("data", (chunk) => output.push(String(chunk)));
  electron.stderr.on("data", (chunk) => output.push(String(chunk)));
  onCleanup(() => { try { process.kill(-electron.pid, "SIGKILL"); } catch { /* already gone */ } });
  onCleanup(() => { if (process.exitCode) console.error(`\napplication output:\n${output.join("")}`); });

  const page = await connectDevtools(await devtoolsTarget(debugPort, (item) => item.type === "page"));
  const mainProcess = await connectDevtools(await devtoolsTarget(inspectPort, () => true));

  const evaluate = async (expression) => {
    const result = await page.send("Runtime.evaluate", {
      expression: `(async () => { const $ = (id) => document.getElementById(id); ${expression} })()`,
      awaitPromise: true, returnByValue: true, userGesture: true,
    });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
  };
  const waitFor = async (expression, label, timeout = 20000) => {
    const deadline = Date.now() + timeout;
    let last;
    while (Date.now() < deadline) {
      try {
        last = await evaluate(`return ${expression};`);
        if (last) return last;
      } catch { /* not there yet */ }
      await sleep(120);
    }
    throw new Error(`Timed out waiting for ${label} (last: ${JSON.stringify(last)})`);
  };
  // What a host would make the main process say: sent to the window as it would be.
  const fromMain = async (channel, payload) => {
    const result = await mainProcess.send("Runtime.evaluate", {
      expression: `process.mainModule.require("electron").BrowserWindow.getAllWindows()[0].webContents.send(${JSON.stringify(channel)}, ${JSON.stringify(payload)}); true`,
      returnByValue: true,
    });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
  };
  const KEYS = { Enter: [13, "\r"], Escape: [27], Insert: [45], Tab: [9] };
  const key = async (name, { ctrl = false, shift = false, alt = false } = {}) => {
    const modifiers = (alt ? 1 : 0) | (ctrl ? 2 : 0) | (shift ? 8 : 0);
    const [code, text] = KEYS[name] || [name.toUpperCase().charCodeAt(0)];
    const keyName = name.length === 1 && shift ? name.toUpperCase() : name;
    const domCode = name.length === 1 ? `Key${name.toUpperCase()}` : name;
    await page.send("Input.dispatchKeyEvent", {
      type: text ? "keyDown" : "rawKeyDown", key: keyName, code: domCode, windowsVirtualKeyCode: code, modifiers, text,
    });
    await page.send("Input.dispatchKeyEvent", { type: "keyUp", key: keyName, code: domCode, windowsVirtualKeyCode: code, modifiers });
  };
  const mouse = (type, x, y, { clickCount = 1, modifiers = 0, buttons } = {}) => page.send("Input.dispatchMouseEvent", {
    type, x, y, button: "left", clickCount, modifiers, buttons: buttons ?? (type === "mouseReleased" ? 0 : 1),
  });
  const typeText = (text) => page.send("Input.insertText", { text });
  const message = () => evaluate(`return { text: $("file-message").textContent, tone: $("file-message").className };`);
  const modal = () => evaluate(`
    const shown = document.querySelector("#modal .modal-page:not([hidden])");
    return {
      open: !$("modal-backdrop").classList.contains("hidden"),
      title: shown?.querySelector("h2")?.textContent ?? null,
      waiting: [...document.querySelectorAll("#modal .modal-page[hidden] h2")].map((heading) => heading.textContent),
      text: shown?.querySelector("textarea")?.value ?? null,
      notice: shown?.querySelector(".editor-notice:not(.hidden)")?.textContent ?? null,
    };`);
  const clickButton = (label, scope = "#modal .modal-page:not([hidden])") => evaluate(`
    const button = [...document.querySelectorAll(${JSON.stringify(`${scope} button`)})].find((item) => item.textContent === ${JSON.stringify(label)});
    if (!button) throw new Error("no button " + ${JSON.stringify(label)});
    button.click();
    return true;`);
  const openName = (name) => evaluate(`
    const link = [...document.querySelectorAll("#file-rows .name-link")].find((item) => item.textContent === ${JSON.stringify(name)});
    if (!link) throw new Error("no row " + ${JSON.stringify(name)});
    link.click();
    return true;`);
  const typeIntoEditor = async (text) => {
    await evaluate(`const area = document.querySelector("#modal textarea"); area.focus(); area.setSelectionRange(area.value.length, area.value.length); return true;`);
    await typeText(text);
  };
  const terminalText = () => evaluate(`
    const rows = document.querySelector(".terminal:not(.hidden) .xterm-rows");
    return rows ? [...rows.children].map((row) => row.textContent).join("\\n") : "";`);
  const shell = () => server.shells[server.shells.length - 1];

  await waitFor(`$("credential-storage").textContent.length > 0`, "the renderer to start");
  // Which session id belongs to which tab: each shell is made to print a mark, and
  // the id it arrives under is noted.
  await evaluate(`window.__seen = []; window.sshWorkbench.terminal.onData((payload) => window.__seen.push(payload)); return true;`);
  const connect = async (tabs) => {
    await evaluate(`
      $("host").value = ${JSON.stringify(server.host)};
      $("port").value = "${server.port}";
      $("username").value = ${JSON.stringify(server.username)};
      $("auth-type").value = "password";
      $("auth-type").dispatchEvent(new Event("change"));
      $("password").value = ${JSON.stringify(server.password)};
      $("connect-form").requestSubmit();
      return true;`);
    await waitFor(`document.querySelectorAll("#tabstrip .tab").length === ${tabs} && [...document.querySelectorAll("#file-rows .name-link")].some((link) => link.textContent === "notes.txt") && document.querySelector(".terminal:not(.hidden) .xterm-rows")?.textContent.includes("test-shell-ready")`, `tab ${tabs}`);
    const mark = `tab-mark-${tabs}`;
    shell().write(`${mark}\r\n`);
    return waitFor(`window.__seen.find((payload) => String(payload.data).includes(${JSON.stringify(mark)}))?.id`, `the id of tab ${tabs}`);
  };
  const firstId = await connect(1);
  // The checks on the terminal run in this first tab, which is the one shown again
  // by the time they start.
  const firstShell = shell();

  // 1. The editor keeps an edit through Escape, a click outside, and Close.
  await openName("notes.txt");
  await waitFor(`document.querySelector("#modal textarea")`, "the editor");
  await typeIntoEditor("an hour of edits");
  await key("Escape");
  await sleep(200);
  let state = await modal();
  assert.equal(state.open, true, "Escape with an edit does not close the editor");
  assert.match(state.notice || "", /Discard the changes to notes\.txt\?/);
  await key("Escape");
  await sleep(200);
  state = await modal();
  assert.equal(state.notice, null, "a second Escape takes the question away");
  assert.match(state.text, /an hour of edits/, "and the edit is still there");
  await evaluate(`$("modal-backdrop").dispatchEvent(new MouseEvent("click", { bubbles: true, detail: 1 })); return true;`);
  await sleep(200);
  assert.equal((await modal()).open, true, "a click on the dimmed area never closes the editor");
  await clickButton("Close");
  await waitFor(`document.querySelector("#modal .editor-notice:not(.hidden)")`, "the discard question");
  await clickButton("Discard changes", "#modal .editor-notice");
  await waitFor(`$("modal-backdrop").classList.contains("hidden")`, "the editor to close");
  assert.equal(fs.readFileSync(path.join(remoteRoot, "notes.txt"), "utf8"), "first line\n", "nothing was written");
  // Untouched, it closes on Escape at once.
  await openName("notes.txt");
  await waitFor(`document.querySelector("#modal textarea")`, "the editor again");
  await key("Escape");
  await waitFor(`$("modal-backdrop").classList.contains("hidden")`, "an untouched editor to close on Escape");
  console.log("• the editor asks before discarding an edit, and ignores a click outside it");

  // 2. A dialog that arrives on its own waits behind the editor rather than replacing
  //    it, and comes up once the editor is closed.
  await openName("notes.txt");
  await waitFor(`document.querySelector("#modal textarea")`, "the editor");
  await typeIntoEditor("careful edits");
  await fromMain("session:browse-user", { id: firstId, needsPassword: true, wanted: 0 });
  await waitFor(`document.querySelectorAll("#modal .modal-page").length === 2`, "the sudo question to queue");
  state = await modal();
  assert.equal(state.title, "notes.txt", "the editor is still the dialog shown");
  assert.match(state.text, /careful edits/);
  assert.deepEqual(state.waiting, ["Browse as root too?"]);
  await clickButton("Close");
  await waitFor(`document.querySelector("#modal .editor-notice:not(.hidden)")`, "the discard question");
  await clickButton("Discard changes", "#modal .editor-notice");
  await waitFor(`document.querySelector("#modal .modal-page:not([hidden]) h2")?.textContent === "Browse as root too?"`, "the sudo question to come up");
  assert.equal(await evaluate(`return document.activeElement === document.querySelector("#modal .password-form input");`), true,
    "the waiting dialog takes focus when it comes up");
  await clickButton("Cancel");
  await waitFor(`$("modal-backdrop").classList.contains("hidden")`, "the sudo question to close");
  await waitFor(`$("file-message").textContent.includes("still browsing as")`, "the decline to be reported");
  console.log("• a dialog raised behind the editor waits its turn, then takes focus");

  // 3. Dialog buttons hold while their action runs: Enter twice in New folder makes
  //    one folder and reports success, and a second Enter in a password dialog is not
  //    a second attempt.
  await evaluate(`$("new-folder").click(); return true;`);
  await waitFor(`document.querySelector("#modal input")`, "the New folder prompt");
  await evaluate(`document.querySelector("#modal input").focus(); return true;`);
  await typeText("release-notes");
  await key("Enter");
  await key("Enter");
  await waitFor(`$("modal-backdrop").classList.contains("hidden")`, "the prompt to close");
  await sleep(800);
  assert.ok(fs.existsSync(path.join(remoteRoot, "release-notes")));
  assert.notEqual((await message()).tone, "status-error", `a second Enter ran mkdir again: ${(await message()).text}`);
  // The sudo question again, answered with two quick Enters: one follow-password
  // request reaches the main process.
  await mainProcess.send("Runtime.evaluate", {
    expression: `(() => {
      const { ipcMain } = process.mainModule.require("electron");
      globalThis.__followCalls = 0;
      ipcMain.removeHandler("files:follow-password");
      ipcMain.handle("files:follow-password", async () => {
        globalThis.__followCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 600));
        throw new Error("sudo refused that password");
      });
      return true;
    })()`,
    returnByValue: true,
  });
  await fromMain("session:browse-user", { id: firstId, needsPassword: true, wanted: 0 });
  await waitFor(`document.querySelector("#modal .password-form input")`, "the sudo question");
  await evaluate(`document.querySelector("#modal .password-form input").focus(); return true;`);
  await typeText("not-the-password");
  for (let press = 0; press < 4; press += 1) await key("Enter");
  await waitFor(`document.querySelector("#modal .form-message")?.textContent.includes("refused")`, "the refusal");
  const followCalls = (await mainProcess.send("Runtime.evaluate", { expression: "globalThis.__followCalls", returnByValue: true })).result.value;
  assert.equal(followCalls, 1, "four Enters while the password was being checked sent it once");
  await clickButton("Cancel");
  await waitFor(`$("modal-backdrop").classList.contains("hidden")`, "the sudo question to close");
  console.log("• Enter pressed again while a dialog's action runs does not run it again");

  // 4. A sudo question for a tab in the background waits for that tab.
  await evaluate(`$("new-session").click(); return true;`);
  await waitFor(`!$("connect-view").classList.contains("hidden")`, "the connect view");
  await connect(2);
  await fromMain("session:browse-user", { id: firstId, needsPassword: true, wanted: 0 });
  await sleep(500);
  assert.equal((await modal()).open, false, "no dialog over the tab being looked at");
  await evaluate(`document.querySelectorAll("#tabstrip .tab")[0].click(); return true;`);
  await waitFor(`document.querySelector("#modal .modal-page:not([hidden]) h2")?.textContent === "Browse as root too?"`,
    "the question once its tab is shown");
  await clickButton("Cancel");
  await waitFor(`$("modal-backdrop").classList.contains("hidden")`, "the sudo question to close");
  console.log("• a sudo question for a background tab is asked when that tab is shown");

  // 5. Line endings and stamps (the main process does the work; this is the editor
  //    side of it). An untouched CRLF file saves byte for byte.
  await openName("settings.ini");
  await waitFor(`document.querySelector("#modal textarea")`, "the CRLF file");
  await clickButton("Save");
  await waitFor(`$("file-message").textContent.startsWith("Saved settings.ini")`, "the save");
  assert.deepEqual(fs.readFileSync(path.join(remoteRoot, "settings.ini")), files["settings.ini"], "CRLF survived an untouched save");
  // A file that is not UTF-8 is refused with a reason, not opened to be corrupted.
  await openName("menu.txt");
  await waitFor(`$("file-message").className === "status-error"`, "the refusal of a Latin-1 file");
  assert.equal((await modal()).open, false);
  assert.deepEqual(fs.readFileSync(path.join(remoteRoot, "menu.txt")), files["menu.txt"]);
  // A file changed on the host after it was opened is not silently replaced.
  await openName("app.conf");
  await waitFor(`document.querySelector("#modal textarea")`, "app.conf");
  await sleep(1100);
  fs.writeFileSync(path.join(remoteRoot, "app.conf"), "workers=4\nlimit=from-the-host\n");
  await typeIntoEditor("timeout=30\n");
  await clickButton("Save");
  await waitFor(`document.querySelector("#modal .editor-notice:not(.hidden)")`, "the changed-on-host question");
  assert.match((await modal()).notice, /changed on the host/);
  await clickButton("Cancel", "#modal .editor-notice");
  assert.match((await modal()).text, /timeout=30/, "Cancel keeps editing");
  assert.match(fs.readFileSync(path.join(remoteRoot, "app.conf"), "utf8"), /from-the-host/);
  await clickButton("Save");
  await waitFor(`document.querySelector("#modal .editor-notice:not(.hidden)")`, "the question again");
  await clickButton("Reload", "#modal .editor-notice");
  await waitFor(`document.querySelector("#modal textarea")?.value.includes("from-the-host")`, "the reloaded text");
  await typeIntoEditor("timeout=30\n");
  await clickButton("Save");
  await waitFor(`$("file-message").textContent.startsWith("Saved app.conf")`, "the save after reloading");
  assert.equal(fs.readFileSync(path.join(remoteRoot, "app.conf"), "utf8"), "workers=4\nlimit=from-the-host\ntimeout=30\n");
  await openName("app.conf");
  await waitFor(`document.querySelector("#modal textarea")`, "app.conf again");
  await sleep(1100);
  fs.writeFileSync(path.join(remoteRoot, "app.conf"), "replaced on the host\n");
  await typeIntoEditor("# mine\n");
  await clickButton("Save");
  await waitFor(`document.querySelector("#modal .editor-notice:not(.hidden)")`, "the question");
  await clickButton("Overwrite", "#modal .editor-notice");
  // The status line still says "Saved app.conf" from the save before, so the editor
  // closing is what says this one is done.
  await waitFor(`$("modal-backdrop").classList.contains("hidden") && $("file-message").textContent.startsWith("Saved app.conf")`, "the overwrite");
  assert.equal(fs.readFileSync(path.join(remoteRoot, "app.conf"), "utf8"), "workers=4\nlimit=from-the-host\ntimeout=30\n# mine\n");
  console.log("• the editor keeps CRLF, refuses non-UTF-8, and asks before replacing a change made on the host");

  // 6. An image too large to preview downloads instead of failing.
  // The save dialog is answered by the test rather than shown.
  const saveTo = path.join(userData, "downloaded-scan.png");
  await mainProcess.send("Runtime.evaluate", {
    expression: `process.mainModule.require("electron").dialog.showSaveDialog = async () => ({ canceled: false, filePath: ${JSON.stringify(saveTo)} }); true`,
    returnByValue: true,
  });
  await openName("scan.png");
  await waitFor(`$("file-message").textContent.startsWith("Downloaded") || $("file-message").className === "status-error"`, "the image to download", 30000);
  assert.notEqual((await message()).tone, "status-error", `a 21 MB image ended in an error: ${(await message()).text}`);
  assert.equal(fs.statSync(saveTo).size, files["scan.png"].length, "the whole image was downloaded");
  assert.equal((await modal()).open, false, "and was not previewed");
  console.log("• an image over 20 MB downloads rather than failing to preview");

  // 7. Double-clicking a folder name opens that folder, not the row under it after.
  const point = await evaluate(`
    const link = [...document.querySelectorAll("#file-rows .name-link")].find((item) => item.textContent === "projects");
    const box = link.getBoundingClientRect();
    return { x: box.left + 4, y: box.top + box.height / 2 };`);
  await mouse("mousePressed", point.x, point.y, { clickCount: 1 });
  await mouse("mouseReleased", point.x, point.y, { clickCount: 1 });
  await sleep(400);
  await mouse("mousePressed", point.x, point.y, { clickCount: 2 });
  await mouse("mouseReleased", point.x, point.y, { clickCount: 2 });
  await sleep(800);
  assert.match(await evaluate(`return $("path-input").value;`), /\/projects$/, "the double-click opened only the folder clicked");
  await evaluate(`$("home").click(); return true;`);
  await waitFor(`[...document.querySelectorAll("#file-rows .name-link")].some((link) => link.textContent === "notes.txt")`, "home");
  console.log("• a double-click on a folder name opens that folder only");

  // 8. Every paste path strips control characters, so a clipboard carrying the
  //    bracketed-paste terminator cannot end the bracket early and run what follows.
  firstShell.write("\x1b[?2004h");
  await sleep(200);
  const hostile = "echo harmless\x1b[201~\rtouch pwned-by-paste\r";
  const tryPaste = async (label, run) => {
    await evaluate(`await window.sshWorkbench.clipboard.write(${JSON.stringify(hostile)}); document.querySelector(".terminal:not(.hidden) .xterm-helper-textarea").focus(); return true;`);
    const before = server.received().length;
    await run();
    await sleep(500);
    const sent = server.received().slice(before);
    assert.ok(sent.includes("echo harmless"), `${label} pasted nothing: ${JSON.stringify(sent)}`);
    assert.equal((sent.match(/\x1b\[201~/g) || []).length, 1, `${label}: ${JSON.stringify(sent)}`);
    assert.ok(sent.endsWith("\x1b[201~"), `${label} let text out of the bracket: ${JSON.stringify(sent)}`);
  };
  await tryPaste("Ctrl+Shift+V", () => key("v", { ctrl: true, shift: true }));
  await tryPaste("Shift+Insert", () => key("Insert", { shift: true }));
  await tryPaste("Ctrl+V", () => key("v", { ctrl: true }));
  await tryPaste("right-click", () => evaluate(`
    document.querySelector(".terminal:not(.hidden)").dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true }));
    return true;`));
  await tryPaste("a paste event", () => evaluate(`
    const transfer = new DataTransfer();
    transfer.setData("text/plain", ${JSON.stringify(hostile)});
    document.querySelector(".terminal:not(.hidden) .xterm-helper-textarea")
      .dispatchEvent(new ClipboardEvent("paste", { clipboardData: transfer, bubbles: true, cancelable: true }));
    return true;`));
  firstShell.write("\x1b[?2004l");
  console.log("• no paste path lets a control character through");

  // 9. Copying: an Alt+drag column copies evenly, Ctrl+Insert removes the shared
  //    margin as Help says, and a copy cut short says so.
  firstShell.write("\x1b[2J\x1b[H0123456789\r\n      alpha\r\n      beta\r\n");
  await waitFor(`document.querySelector(".terminal:not(.hidden) .xterm-rows").textContent.includes("beta")`, "the column text");
  await sleep(200);
  const geometry = await evaluate(`
    const rows = [...document.querySelector(".terminal:not(.hidden) .xterm-rows").children];
    const box = rows[0].getBoundingClientRect();
    const range = document.createRange();
    const text = document.createTreeWalker(rows[0], NodeFilter.SHOW_TEXT).nextNode();
    range.setStart(text, 0); range.setEnd(text, 10);
    const cell = range.getBoundingClientRect().width / 10;
    return { left: box.left, cell, y1: rows[1].getBoundingClientRect().top + box.height / 2, y2: rows[2].getBoundingClientRect().top + box.height / 2 };`);
  const x1 = geometry.left + geometry.cell * 4 + 1;
  const x2 = geometry.left + geometry.cell * 12 - 1;
  await mouse("mousePressed", x1, geometry.y1, { modifiers: 1 });
  for (let step = 1; step <= 6; step += 1) {
    await mouse("mouseMoved", x1 + ((x2 - x1) * step) / 6, geometry.y1 + ((geometry.y2 - geometry.y1) * step) / 6, { modifiers: 1, buttons: 1 });
  }
  await mouse("mouseReleased", x2, geometry.y2, { modifiers: 1 });
  await sleep(200);
  await key("c", { ctrl: true });
  await sleep(400);
  const column = (await evaluate(`return await window.sshWorkbench.clipboard.read();`)).split("\n").map((line) => line.trimEnd());
  assert.deepEqual(column, ["alpha", "beta"], "a column selection copies evenly");

  const helpText = await evaluate(`
    $("terminal-help").click();
    const code = [...document.querySelectorAll("#modal .help-grid code")].find((item) => item.textContent === "Ctrl+Insert");
    const text = code.nextElementSibling.textContent;
    document.querySelector("#modal .modal-footer button").click();
    return text;`);
  assert.doesNotMatch(helpText, /exactly/i, "Help no longer says Ctrl+Insert copies exactly");
  firstShell.write("\x1b[2J\x1b[H    hooks:\r\n      child: 1\r\n");
  await waitFor(`document.querySelector(".terminal:not(.hidden) .xterm-rows").textContent.includes("child")`, "the indented block");
  const block = await evaluate(`
    const rows = [...document.querySelector(".terminal:not(.hidden) .xterm-rows").children];
    const a = rows[0].getBoundingClientRect(), b = rows[1].getBoundingClientRect();
    return { x1: a.left + 2, y1: a.top + a.height / 2, x2: a.left + 300, y2: b.top + b.height / 2 };`);
  await mouse("mousePressed", block.x1, block.y1);
  for (let step = 1; step <= 5; step += 1) {
    await mouse("mouseMoved", block.x1 + (block.x2 - block.x1) * step / 5, block.y1 + (block.y2 - block.y1) * step / 5, { buttons: 1 });
  }
  await mouse("mouseReleased", block.x2, block.y2);
  await sleep(200);
  await evaluate(`document.querySelector(".terminal:not(.hidden) .xterm-helper-textarea").focus(); return true;`);
  await key("Insert", { ctrl: true });
  await sleep(400);
  assert.equal(await evaluate(`return await window.sshWorkbench.clipboard.read();`), "hooks:\n  child: 1", "Ctrl+Insert removes the shared margin");

  const LENGTH = 250_000;
  firstShell.write(`\r\n${"q".repeat(LENGTH)}\r\nEND\r\n`);
  await waitFor(`document.querySelector(".terminal:not(.hidden) .xterm-rows").textContent.includes("END")`, "the long line", 30000);
  await sleep(300);
  const tail = await evaluate(`
    const rows = [...document.querySelector(".terminal:not(.hidden) .xterm-rows").children];
    const index = rows.findIndex((row) => row.textContent.startsWith("END"));
    const box = rows[index - 1].getBoundingClientRect();
    return { x: box.left + 20, y: box.top + box.height / 2 };`);
  for (const clickCount of [1, 2, 3]) {
    await mouse("mousePressed", tail.x, tail.y, { clickCount });
    await mouse("mouseReleased", tail.x, tail.y, { clickCount });
  }
  await sleep(300);
  await key("c", { ctrl: true });
  await waitFor(`$("file-message").textContent.startsWith("Copied only the first")`, "the truncation to be reported");
  assert.equal((await message()).tone, "status-error");
  console.log("• column copies are even, Ctrl+Insert matches Help, and a cut-short copy says so");

  // 10. An emoji is two cells, as the host counts it.
  const before = server.received().length;
  firstShell.write("\x1b[2J\x1b[H\u{1F600}\x1b[6n");
  await sleep(800);
  const report = /\x1b\[(\d+);(\d+)R/.exec(server.received().slice(before));
  assert.ok(report, "a cursor position report");
  assert.equal(Number(report[2]), 3, "after one emoji the cursor stands in column 3");
  console.log("• an emoji takes two cells");

  // 11. A disconnection's "Use Reconnect" hint is not overwritten by a listing that
  //     was still on its way.
  await evaluate(`$("refresh").click(); return true;`);
  server.dropClients();
  await waitFor(`!$("reconnect").classList.contains("hidden")`, "the tab to notice it was dropped");
  await sleep(1500);
  assert.match((await message()).text, /Use Reconnect/, "the disconnection is still what the status line says");
  console.log("• the Reconnect hint survives a listing that fails after it");
}

main()
  .then(() => console.log("\ndialog and terminal checks passed"))
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

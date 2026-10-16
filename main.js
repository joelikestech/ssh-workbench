"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const fsPromises = require("node:fs/promises");
const path = require("node:path");
const { app, BrowserWindow, clipboard, dialog, ipcMain, safeStorage, session } = require("electron");
const { KnownHosts } = require("./lib/known-hosts");
const { ProfileStore } = require("./lib/profile-store");
const { SshManager } = require("./lib/ssh-manager");
const { Vault, MIN_PASSWORD, DEFAULT_MINUTES } = require("./lib/vault");
const { sameInstallation, installationPath, installedVersion } = require("./lib/installation");
const { listCopies, otherInstallations, sameProcess } = require("./lib/running-copies");

const MAX_WINDOWS = 8;
const MAX_SESSIONS_PER_WINDOW = 8;
const MAX_SESSIONS_TOTAL = 24;
const DRAG_CACHE_MILLISECONDS = 120_000;
const MAX_DROPPED_ITEMS = 256;
const UPLOAD_CHOICES = new Set(["overwrite", "skip", "keep-both"]);
const MAX_CLIPBOARD_CHARACTERS = 200_000;
const MAX_PASTED_IMAGE_BYTES = 20 * 1024 * 1024;
const IMAGE_EXTENSIONS = new Map([
  ["image/png", "png"],
  ["image/jpeg", "jpg"],
  ["image/gif", "gif"],
  ["image/webp", "webp"],
  ["image/bmp", "bmp"],
  ["image/svg+xml", "svg"],
]);

function imageExtension(mimeType) {
  return IMAGE_EXTENSIONS.get(String(mimeType || "").toLowerCase()) || "png";
}

const startupMarks = [];

function mark(label) {
  if (process.env.SSH_WORKBENCH_TIMING) startupMarks.push([label, Math.round(process.uptime() * 1000)]);
}

function writeStartupTiming() {
  if (!process.env.SSH_WORKBENCH_TIMING || !startupMarks.length) return;
  const report = startupMarks.map(([label, ms]) => `${String(ms).padStart(6)} ms  ${label}`).join("\n");
  try {
    fs.writeFileSync(path.join(app.getPath("userData"), "startup-timing.txt"),
      `milliseconds since the process started\n${report}\n`);
  } catch { /* nowhere to write it */ }
}

let profiles;
let vault;
let knownHosts;
let dragCacheRoot;
let dragInProgress = false;
const sessions = new Map();
// Windows this process opened. A message from anything else — a subframe, or a
// window that has since closed — is refused rather than served.
const openWindows = new Set();

function windowFor(event) {
  if (event.senderFrame !== event.sender.mainFrame) {
    throw new Error("Rejected IPC from a subframe");
  }
  const window = BrowserWindow.fromWebContents(event.sender);
  if (!window || !openWindows.has(window.id)) {
    throw new Error("Rejected IPC from an unknown window");
  }
  return window;
}

// Every handler receives the window that asked, so dialogs open on it and a
// session can only be reached by the window that owns it.
function handle(channel, callback) {
  ipcMain.handle(channel, async (event, ...args) => callback(windowFor(event), ...args));
}

function windowOf(session) {
  const window = BrowserWindow.fromId(session.windowId);
  return window && !window.isDestroyed() ? window : null;
}

function sendToOwner(session, channel, payload) {
  windowOf(session)?.webContents.send(channel, payload);
}

// `signal` closes the dialog when the connection it is asking about has ended without
// waiting for the answer -- the server gave up, or the tab was closed -- so nobody is
// left deciding about a key for a connection that no longer exists.
async function confirmHost(window, { identity, role = "SSH host", fingerprint, previousFingerprint, signal }) {
  const changed = Boolean(previousFingerprint);
  const detail = changed
    ? `The host key for ${identity} changed.\n\nSaved: ${previousFingerprint}\nReceived: ${fingerprint}\n\nThis can indicate a man-in-the-middle attack or a reinstalled server.`
    : `This is the first connection to ${identity}.\n\nHost fingerprint:\n${fingerprint}`;
  const result = await dialog.showMessageBox(window, {
    type: changed ? "warning" : "question",
    title: changed ? `${role} key changed` : `Trust ${role.toLowerCase()}?`,
    message: changed ? `The ${role.toLowerCase()} identity does not match.` : `Verify the ${role.toLowerCase()} fingerprint.`,
    detail,
    buttons: changed ? ["Cancel", "Replace saved key"] : ["Cancel", "Trust once", "Trust and remember"],
    defaultId: 0,
    cancelId: 0,
    noLink: true,
    ...(signal ? { signal } : {}),
  });
  if (signal?.aborted) return { accept: false, remember: false };
  if (changed) return { accept: result.response === 1, remember: result.response === 1 };
  return { accept: result.response > 0, remember: result.response === 2 };
}

function sessionsOfWindow(windowId) {
  return [...sessions.values()].filter((session) => session.windowId === windowId);
}

function createSession(window) {
  if (sessionsOfWindow(window.id).length >= MAX_SESSIONS_PER_WINDOW) {
    throw new Error(`Close a session tab first; ${MAX_SESSIONS_PER_WINDOW} sessions in one window is the maximum`);
  }
  if (sessions.size >= MAX_SESSIONS_TOTAL) {
    throw new Error(`Close a session first; ${MAX_SESSIONS_TOTAL} sessions across all windows is the maximum`);
  }
  const id = crypto.randomUUID();
  const session = {
    id,
    windowId: window.id,
    dragRoot: path.join(dragCacheRoot, id),
    preparedDrags: new Map(),
    cleanupTimers: new Set(),
  };
  session.manager = new SshManager({
    knownHosts,
    // Asked at connection time, so the prompt appears on the window that started it.
    confirmHost: (request) => confirmHost(windowOf(session), request),
  });
  session.manager.on("terminal-data", (data) => sendToOwner(session, "terminal:data", { id, data }));
  session.manager.on("terminal-exit", () => sendToOwner(session, "terminal:exit", { id }));
  session.manager.on("browse-user", (state) => sendToOwner(session, "session:browse-user", { id, ...state }));
  session.manager.on("status", (status) => {
    if (!status.connected) resetSessionDragCache(session);
    sendToOwner(session, "session:status", { id, ...status });
  });
  sessions.set(id, session);
  return session;
}

// A window may only reach its own sessions: an id belonging to another window is
// treated exactly like one that no longer exists.
function requireSession(window, id) {
  const session = sessions.get(String(id || ""));
  if (!session || session.windowId !== window.id) throw new Error("That session is no longer open");
  return session;
}

async function closeSession(id) {
  const session = sessions.get(String(id || ""));
  if (!session) return { ok: true };
  sessions.delete(session.id);
  session.manager.removeAllListeners();
  for (const timer of session.cleanupTimers) clearTimeout(timer);
  session.cleanupTimers.clear();
  await session.manager.disconnect().catch(() => undefined);
  removeDirectory(session.dragRoot);
  session.preparedDrags.clear();
  return { ok: true };
}

function removeDirectory(directory) {
  if (!directory) return;
  try { fs.rmSync(directory, { recursive: true, force: true }); } catch { /* already gone or locked */ }
}

// Deleting last run's staged drag files can mean hundreds of megabytes, and doing
// it before the window exists makes the application look like it has hung — worse
// on Windows, where a virus scanner sees every unlink. Renaming the folder aside is
// instant regardless of size, and the delete then happens in the background.
function purgeStaleDragCache(root) {
  const leftovers = [];
  try {
    const parent = path.dirname(root);
    const base = path.basename(root);
    if (fs.existsSync(root)) {
      const aside = path.join(parent, `${base}-old-${process.pid}`);
      fs.renameSync(root, aside);
      leftovers.push(aside);
    }
    // Anything a previous run failed to finish deleting.
    for (const name of fs.readdirSync(parent)) {
      if (name.startsWith(`${base}-old-`)) leftovers.push(path.join(parent, name));
    }
  } catch {
    removeDirectory(root);
  }
  return () => Promise.all(leftovers.map((target) =>
    fsPromises.rm(target, { recursive: true, force: true }).catch(() => undefined)));
}

function resetSessionDragCache(session) {
  session.preparedDrags.clear();
  for (const timer of session.cleanupTimers) clearTimeout(timer);
  session.cleanupTimers.clear();
  removeDirectory(session.dragRoot);
}

function registerIpc() {
  handle("windows:create", async () => {
    await createWindow();
    return { ok: true };
  });
  handle("sessions:create", (window) => {
    const session = createSession(window);
    return {
      id: session.id,
      maxSessions: MAX_SESSIONS_PER_WINDOW,
      openSessions: sessionsOfWindow(window.id).length,
    };
  });
  handle("sessions:connect", (window, id, config) => {
    const session = requireSession(window, id);
    resetSessionDragCache(session);
    return session.manager.connect(config);
  });
  handle("sessions:disconnect", async (window, id) => {
    const session = requireSession(window, id);
    await session.manager.disconnect();
    resetSessionDragCache(session);
    return { ok: true };
  });
  handle("sessions:close", (window, id) => closeSession(requireSession(window, id).id));

  handle("profiles:list", () => profiles.list());
  // Choosing a connection reads only what the form shows; its secrets come from
  // profiles:secrets, which the window asks for at the moment of connecting and for
  // nothing else. That second call is the one that counts as using a credential.
  handle("profiles:get", (_window, id) => profiles.get(id));
  handle("profiles:secrets", (_window, id) => {
    const answer = profiles.secrets(id);
    // Using a credential moves a timed unlock along, or under "ask every time" ends
    // it, and every window's idea of the vault has to move with it.
    if (vault.configured) announceVault("used");
    return answer;
  });
  // Credentials that cannot be read can only be replaced, and replacing them is a
  // decision rather than a detail. The store refuses and says so; that refusal is
  // turned into an answer rather than an error, because an error crossing this
  // boundary arrives as a bare message with nothing on it to act on -- and what the
  // caller has to do here is ask a question and come back.
  handle("profiles:save", (_window, profile) => {
    try {
      return profiles.save(profile);
    } catch (error) {
      if (!error?.unreadableCredentials) throw error;
      return { needsReplacement: true, message: String(error.message) };
    }
  });
  handle("profiles:delete", (_window, id) => profiles.delete(id));
  handle("profiles:security", () => profileSecurity());
  handle("app:info", () => ({
    version: app.getVersion(),
    electron: process.versions.electron,
    platform: process.platform,
    // Published so a caller putting a list on the clipboard can decide for itself
    // what to leave out, rather than having the tail of it cut off mid-way here.
    clipboardLimit: MAX_CLIPBOARD_CHARACTERS,
  }));

  // The master password. Nothing here returns the password, the key, or anything
  // derived from either; the renderer only ever learns whether the vault is set and
  // whether it is currently unlocked.
  handle("vault:status", () => vaultStatus());
  handle("vault:set", async (_window, password, policy) => {
    if (vault.configured) throw new Error("A master password is already set; change it instead");
    const created = await vault.create(password, policy);
    let result;
    try {
      result = profiles.applyMasterPassword(created);
      vault.adopt(created);
    } catch (error) {
      created.key.fill(0);
      throw error;
    }
    return { ...announceVault("set"), ...result };
  });
  handle("vault:change", async (_window, currentPassword, newPassword) => {
    const currentKey = await vault.keyFor(currentPassword);
    try {
      const created = await vault.create(newPassword, vault.policy);
      try {
        const result = profiles.changeMasterPassword({
          oldKey: currentKey, newKey: created.key, config: created.config,
        });
        vault.adopt(created);
        return { ...announceVault("change"), ...result };
      } catch (error) {
        created.key.fill(0);
        throw error;
      }
    } finally {
      currentKey.fill(0);
    }
  });
  handle("vault:remove", async (_window, password, discardCredentials = false) => {
    const key = await vault.keyFor(password);
    try {
      profiles.clearMasterPassword({ key, discardCredentials: Boolean(discardCredentials) });
      vault.clear();
    } finally {
      key.fill(0);
    }
    return announceVault("remove");
  });
  handle("vault:unlock", async (_window, password) => {
    await vault.unlock(password);
    return announceVault("unlock");
  });
  handle("vault:lock", () => {
    vault.lock();
    return announceVault("lock");
  });
  // Changing how often the password is needed is itself a security decision, so it
  // asks for the password rather than accepting whatever state the vault is in.
  handle("vault:policy", async (_window, password, policy) => {
    const key = await vault.keyFor(password);
    key.fill(0);
    // Stored first, adopted second. A write that fails must leave this process
    // enforcing the policy that is still on disk, not the one it could not save.
    const proposed = vault.configFor(policy);
    profiles.saveVaultConfig(proposed);
    vault.adoptConfig(proposed);
    return announceVault("policy");
  });

  handle("files:list", (window, id, directory) => requireSession(window, id).manager.list(directory));
  handle("files:follow-password", (window, id, password) =>
    requireSession(window, id).manager.followWithPassword(password));
  handle("files:decline-follow", (window, id) => requireSession(window, id).manager.declineFollow());
  handle("files:search", (window, id, directory, query, recursive) =>
    requireSession(window, id).manager.search(directory, query, recursive));
  handle("files:resolve", (window, id, remoteFile) => requireSession(window, id).manager.resolve(remoteFile));
  // `{ text, eol, stamp }`: the stamp comes back with the save so a file changed
  // on the host in the meantime is not silently overwritten.
  handle("files:read", (window, id, remoteFile) => requireSession(window, id).manager.readFile(String(remoteFile ?? "")));
  handle("files:read-binary", (window, id, remoteFile) => requireSession(window, id).manager.readBinary(remoteFile));
  // The options come from the renderer, so they are checked here before anything is
  // written: `eol` is one of the two line endings, and `expect` is a stamp made of
  // two numbers. Anything else is refused rather than guessed at.
  handle("files:write", (window, id, remoteFile, contents, options) => {
    const given = options ?? {};
    if (typeof given !== "object") throw new Error("The save options are not valid");
    const eol = given.eol ?? "\n";
    if (eol !== "\n" && eol !== "\r\n") throw new Error("The line ending to save with is not valid");
    let expect = null;
    if (given.expect !== undefined && given.expect !== null) {
      const size = given.expect?.size;
      const mtime = given.expect?.mtime;
      if (!Number.isFinite(size) || size < 0 || !Number.isFinite(mtime)) {
        throw new Error("The file stamp to save against is not valid");
      }
      expect = { size, mtime };
    }
    return requireSession(window, id).manager.writeFile(String(remoteFile ?? ""), String(contents ?? ""), { eol, expect });
  });
  handle("files:mkdir", (window, id, directory, name) => requireSession(window, id).manager.mkdir(directory, name));
  handle("files:rename", (window, id, remoteFile, name) => requireSession(window, id).manager.rename(remoteFile, name));
  handle("files:delete", (window, id, paths) => requireSession(window, id).manager.delete(remoteSelection(paths)));
  handle("files:plan-upload", (window, id, localPaths, remoteDirectory) => {
    const session = requireSession(window, id);
    return session.manager.planUpload(validateDroppedPaths(localPaths), remoteDirectory);
  });
  handle("files:upload", (window, id, localPaths, remoteDirectory, decisions) => {
    const session = requireSession(window, id);
    const paths = validateDroppedPaths(localPaths);
    return session.manager.upload(paths, remoteDirectory, validateDecisions(decisions, paths));
  });
  handle("files:start-drag", (window, id, items) => startRemoteDrag(window, id, items));

  handle("terminal:start", (window, id, dimensions) => requireSession(window, id).manager.startTerminal(dimensions));

  handle("dialog:private-key", async (window) => {
    const result = await dialog.showOpenDialog(window, {
      title: "Choose an SSH private key",
      properties: ["openFile"],
      filters: [{ name: "SSH keys", extensions: ["pem", "key", "ppk", "*"] }],
    });
    return result.canceled ? null : result.filePaths[0];
  });

  // Choosing and uploading are separate calls so that a name collision can be put to
  // the person in between. The chosen paths go back to the preload world, which holds
  // them across the dialog exactly as it holds the paths read out of a drop event.
  handle("files:choose-upload", async (window, id, kind) => {
    requireSession(window, id);
    const folder = String(kind) === "folder";
    const result = await dialog.showOpenDialog(window, {
      title: folder ? "Upload folder" : "Upload files",
      properties: folder ? ["openDirectory"] : ["openFile", "multiSelections"],
    });
    return result.canceled ? [] : result.filePaths;
  });

  handle("files:download", async (window, id, items) => {
    const session = requireSession(window, id);
    if (!Array.isArray(items) || !items.length) throw new Error("Select something to download");
    if (items.length === 1 && !items[0].directory) {
      const result = await dialog.showSaveDialog(window, {
        title: "Download file",
        defaultPath: items[0].name,
      });
      if (result.canceled || !result.filePath) return [];
      return session.manager.download([items[0].path], path.dirname(result.filePath), result.filePath);
    }
    const result = await dialog.showOpenDialog(window, {
      title: items.length === 1 ? "Choose where to download the folder" : "Choose where to download the selection",
      properties: ["openDirectory", "createDirectory"],
    });
    if (result.canceled) return [];
    return session.manager.download(remoteSelection(items.map((item) => item.path)), result.filePaths[0]);
  });

  handle("files:paste-image", (window, id, bytes, remoteDirectory, mimeType) => {
    const session = requireSession(window, id);
    const data = Buffer.from(bytes || []);
    if (!data.length) throw new Error("The pasted image was empty");
    if (data.length > MAX_PASTED_IMAGE_BYTES) {
      throw new Error(`A pasted image larger than ${MAX_PASTED_IMAGE_BYTES / (1024 * 1024)} MB is too large; save it to a file and upload it`);
    }
    return session.manager.writePastedImage(remoteDirectory, data, imageExtension(mimeType));
  });

  // Keys such as Ctrl+Shift+V raise no paste event, so the image is taken from the
  // system clipboard here instead of from clipboard event data.
  handle("files:paste-clipboard-image", (window, id, remoteDirectory) => {
    const session = requireSession(window, id);
    const image = clipboard.readImage();
    if (image.isEmpty()) return null;
    const data = image.toPNG();
    if (!data.length) throw new Error("The clipboard image could not be read");
    if (data.length > MAX_PASTED_IMAGE_BYTES) {
      throw new Error(`A pasted image larger than ${MAX_PASTED_IMAGE_BYTES / (1024 * 1024)} MB is too large; save it to a file and upload it`);
    }
    return session.manager.writePastedImage(remoteDirectory, data, "png");
  });
  handle("clipboard:read", () => clipboard.readText().slice(0, MAX_CLIPBOARD_CHARACTERS));
  handle("clipboard:write", (_window, text) => {
    const wanted = String(text ?? "");
    clipboard.writeText(wanted.slice(0, MAX_CLIPBOARD_CHARACTERS));
    // The cut is still a last resort, but a caller that gets one back can say so
    // instead of reporting a copy that only partly happened.
    return { ok: true, truncated: wanted.length > MAX_CLIPBOARD_CHARACTERS };
  });

  // Keystrokes and resizes arrive constantly, so these stay one-way; the window is
  // still checked, and a session belonging to another window is ignored.
  const ownSession = (event, id) => {
    let window;
    try {
      window = windowFor(event);
    } catch {
      // These are one-way, so there is no caller to reject: a message from a window
      // that has just closed is dropped rather than thrown from a listener.
      return null;
    }
    const session = sessions.get(String(id || ""));
    return session && session.windowId === window.id ? session : null;
  };
  ipcMain.on("terminal:input", (event, id, data) => ownSession(event, id)?.manager.terminalInput(data));
  ipcMain.on("terminal:binary", (event, id, data) => ownSession(event, id)?.manager.terminalBinary(data));
  ipcMain.on("terminal:resize", (event, id, columns, rows) => ownSession(event, id)?.manager.terminalResize(columns, rows));
}

function remoteSelection(values) {
  if (!Array.isArray(values) || !values.length) throw new Error("Select one or more remote items first");
  if (values.length > MAX_DROPPED_ITEMS) throw new Error("Too many items are selected for one operation");
  return values.map((value) => String(value ?? ""));
}

function validateDroppedPaths(values) {
  if (!Array.isArray(values) || !values.length) throw new Error("Drop one or more local files or folders");
  if (values.length > MAX_DROPPED_ITEMS) throw new Error("Too many top-level items were dropped at once");
  const unique = [];
  const seen = new Set();
  for (const value of values) {
    if (typeof value !== "string" || !value || !path.isAbsolute(value)) {
      throw new Error("A dropped item did not provide a usable local path");
    }
    const resolved = path.resolve(value);
    let attributes;
    try { attributes = fs.lstatSync(resolved); } catch { throw new Error(`Dropped item is no longer available: ${path.basename(resolved)}`); }
    if (!attributes.isFile() && !attributes.isDirectory() && !attributes.isSymbolicLink()) {
      throw new Error(`Unsupported dropped item: ${path.basename(resolved)}`);
    }
    if (!seen.has(resolved)) {
      seen.add(resolved);
      unique.push(resolved);
    }
  }
  return unique;
}

// The choices are made in the renderer, so they are checked here rather than
// trusted: a name that was not part of this upload cannot be decided, and an
// unrecognised choice is refused rather than quietly read as an overwrite.
function validateDecisions(value, localPaths) {
  if (value === undefined || value === null) return {};
  if (typeof value !== "object" || Array.isArray(value)) throw new Error("The upload choices were not usable");
  const names = new Set(localPaths.map((localPath) => path.basename(localPath)));
  const decisions = {};
  for (const [name, choice] of Object.entries(value)) {
    if (!names.has(name)) continue;
    if (!UPLOAD_CHOICES.has(String(choice))) throw new Error(`Unrecognised choice for ${name}`);
    decisions[name] = String(choice);
  }
  return decisions;
}

async function startRemoteDrag(window, id, items) {
  const session = requireSession(window, id);
  if (dragInProgress) throw new Error("Another drag is still being prepared");
  if (!Array.isArray(items) || !items.length) throw new Error("Select something to drag out");
  if (items.length > MAX_DROPPED_ITEMS) throw new Error("Too many items are selected for one drag");
  const remotePaths = items.map((item) => String(item?.path || ""));
  if (remotePaths.some((remotePath) => !path.posix.isAbsolute(remotePath))) {
    throw new Error("A selected remote item has an invalid path");
  }
  if (window.isDestroyed()) throw new Error("The window that started the drag has closed");
  const connection = session.manager.connection;
  const connectionIdentity = connection
    ? [connection.host, connection.port, connection.username, connection.jump]
    : null;
  const cacheKey = JSON.stringify([connectionIdentity, items.map((item) => [item.path, item.size, item.modified])]);
  const cached = session.preparedDrags.get(cacheKey);
  if (cached && cached.files.every((file) => fs.existsSync(file))) {
    dragInProgress = true;
    try {
      await beginNativeDrag(window, cached.files);
      return { dragged: cached.files.length, cached: true };
    } finally {
      dragInProgress = false;
    }
  }
  const stagingDirectory = path.join(session.dragRoot, crypto.randomUUID());
  fs.mkdirSync(stagingDirectory, { recursive: true, mode: 0o700 });
  dragInProgress = true;
  try {
    const files = await session.manager.download(remotePaths, stagingDirectory);
    if (!files.length) throw new Error("Nothing was prepared for dragging");
    session.preparedDrags.set(cacheKey, { files, stagingDirectory });
    await beginNativeDrag(window, files);
    const cleanup = setTimeout(() => {
      session.cleanupTimers.delete(cleanup);
      const current = session.preparedDrags.get(cacheKey);
      if (current?.stagingDirectory === stagingDirectory) session.preparedDrags.delete(cacheKey);
      removeDirectory(stagingDirectory);
    }, DRAG_CACHE_MILLISECONDS);
    cleanup.unref();
    session.cleanupTimers.add(cleanup);
    return { dragged: files.length, cached: false };
  } catch (error) {
    const current = session.preparedDrags.get(cacheKey);
    if (current?.stagingDirectory === stagingDirectory) session.preparedDrags.delete(cacheKey);
    removeDirectory(stagingDirectory);
    throw error;
  } finally {
    dragInProgress = false;
  }
}

async function beginNativeDrag(window, files) {
  const icon = await app.getFileIcon(files[0], { size: "small" })
    .catch(() => app.getFileIcon(process.execPath, { size: "small" }));
  window.webContents.startDrag({ file: files[0], files, icon });
}

// A keyring that exists is not the same as a keyring worth trusting: on Linux the
// fallback backend keeps "encrypted" secrets in plain sight. Both the security
// summary and the vault status answer from here so they cannot disagree.
function keyringAvailable() {
  const encryptionAvailable = safeStorage.isEncryptionAvailable();
  const backend = process.platform === "linux" ? safeStorage.getSelectedStorageBackend() : process.platform;
  const secureBackend = backend !== "basic_text" && backend !== "unknown";
  return { available: encryptionAvailable && secureBackend, backend };
}

function profileSecurity() {
  const { available, backend } = keyringAvailable();
  const label = process.platform === "win32"
    ? "Windows Data Protection"
    : process.platform === "darwin"
      ? "macOS Keychain"
      : backend.startsWith("kwallet")
        ? "KWallet"
        : backend === "gnome_libsecret"
          ? "Secret Service keyring"
          : "No secure keyring detected";
  const warnings = [profiles?.loadWarning, knownHosts?.loadWarning].filter(Boolean);
  return {
    available,
    backend,
    label,
    warning: warnings.join(" ") || null,
    maxSessions: MAX_SESSIONS_PER_WINDOW,
    masterPassword: vaultStatus(),
  };
}

// One process holds one vault, so a master password entered in any window unlocks
// the saved credentials for all of them — and locking does the same in reverse.
function vaultStatus() {
  // Called from the security summary, which can be asked for before the vault has
  // been built during startup.
  if (!vault) return { configured: false, unlocked: false, mode: "minutes", minutes: DEFAULT_MINUTES, secondsRemaining: 0 };
  return {
    ...vault.status(),
    keyring: keyringAvailable().available,
    minimumLength: MIN_PASSWORD,
    defaultMinutes: DEFAULT_MINUTES,
  };
}

// One process holds the vault, so a change made from one window -- locking it above
// all -- is a change for every window, and each of them is told rather than left to
// find out at its next question. A window that still believed the vault unlocked, or
// unset, would go on offering what is no longer true: a shortcut that does nothing, a
// form that looks ready to connect. The status goes to every window, the one that
// asked included; `reason` says what happened, so a window can tell an explicit lock
// from a timed unlock simply running out.
let vaultExpiryTimer = null;

function announceVault(reason) {
  const status = vaultStatus();
  for (const id of openWindows) {
    const window = BrowserWindow.fromId(id);
    if (window && !window.isDestroyed()) window.webContents.send("vault:changed", { ...status, reason });
  }
  scheduleVaultExpiry();
  return status;
}

// A timed unlock ends on its own, and the windows are told when it does rather than
// discovering it on the next connect. Every use moves the end along, so the timer is
// re-read when it fires instead of trusted.
function scheduleVaultExpiry() {
  if (vaultExpiryTimer) clearTimeout(vaultExpiryTimer);
  vaultExpiryTimer = null;
  const remaining = vault?.expiresIn;
  if (remaining === null || remaining === undefined) return;
  vaultExpiryTimer = setTimeout(() => {
    vaultExpiryTimer = null;
    if (vault.unlocked) scheduleVaultExpiry();
    else announceVault("expired");
  }, Math.min(remaining + 250, 2 ** 31 - 1));
  vaultExpiryTimer.unref?.();
}

// Closing a window takes its sessions with it: their connections are dropped and
// their staged drag files removed, while other windows carry on untouched.
async function closeWindowSessions(windowId) {
  await Promise.all(sessionsOfWindow(windowId).map((session) => closeSession(session.id).catch(() => undefined)));
}

async function createWindow() {
  if (openWindows.size >= MAX_WINDOWS) {
    throw new Error(`Close a window first; ${MAX_WINDOWS} windows is the maximum`);
  }
  const window = new BrowserWindow({
    width: 1500,
    height: 900,
    minWidth: 900,
    minHeight: 560,
    backgroundColor: "#0e1116",
    // The window title is where the build belongs: it is on screen whatever the
    // window is showing, and the application's own bar does not have to repeat the
    // name the title bar is already displaying.
    title: `SSH Workbench ${app.getVersion()}`,
    // A packaged Windows build takes its icon from the executable; this is for every
    // other way of running it, where the window would otherwise wear Electron's.
    icon: path.join(__dirname, "build", "icon.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      navigateOnDragDrop: false,
    },
  });
  window.removeMenu();
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event) => event.preventDefault());
  window.webContents.on("will-attach-webview", (event) => event.preventDefault());
  openWindows.add(window.id);
  const windowId = window.id;
  window.on("closed", () => {
    openWindows.delete(windowId);
    closeWindowSessions(windowId);
  });
  await window.loadFile(path.join(__dirname, "src", "index.html"));
  return window;
}

async function shutdown() {
  const open = [...sessions.keys()];
  await Promise.all(open.map((id) => closeSession(id).catch(() => undefined)));
  removeDirectory(dragCacheRoot);
}

async function startUp() {
  mark("electron ready, application code starts");
  dragCacheRoot = path.join(app.getPath("userData"), "drag-cache");
  const deleteStaleDragCache = purgeStaleDragCache(dragCacheRoot);
  fs.mkdirSync(dragCacheRoot, { recursive: true, mode: 0o700 });
  mark("drag cache set aside");
  knownHosts = new KnownHosts(path.join(app.getPath("userData"), "known-hosts.json"));
  profiles = new ProfileStore({
    filePath: path.join(app.getPath("userData"), "connections.json"),
    encrypt: (plaintext) => safeStorage.encryptString(plaintext),
    decrypt: (encrypted) => safeStorage.decryptString(encrypted),
    canEncrypt: () => profileSecurity().available,
  });
  // The store reads the vault's salt and policy along with the connections, so the
  // vault is built from what was found there and handed back to the store.
  vault = new Vault({ config: profiles.vaultConfig });
  profiles.attachVault(vault);
  mark("saved connections and known hosts read");
  // Every window shares the default session, so this is set once rather than being
  // reapplied — identically — by each new window.
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  registerIpc();
  await createWindow();
  mark("window created and page loaded");
  writeStartupTiming();
  // Now that the interface is up, clear what was set aside.
  deleteStaleDragCache();
  app.on("activate", () => {
    if (!openWindows.size) createWindow().catch(() => undefined);
  });
}

// One process serves every window. A second process would point at the same
// Chromium profile directory and contend for its databases, which costs several
// seconds of startup for each copy after the first, so launching the application
// again asks the process that owns the profile for another window instead.
// A launch from a different folder is refused with the path to close, rather than
// answered with a window drawn by whichever build happens to hold the lock.
const TAKEOVER_WAIT_MILLISECONDS = 10_000;

function describeBuild(version) {
  return version ? `SSH Workbench ${version}` : "an unidentified build";
}

// A launch from a different folder that cannot speak for itself: every build before
// 0.11.5 quits without a word when it is refused the lock, so the copy holding the
// lock says what happened rather than drawing a window on the other build's behalf.
function refuseOtherCopy(launchedPath, launchedVersion) {
  const window = BrowserWindow.getAllWindows()[0] || null;
  const options = {
    type: "warning",
    title: "Another copy of SSH Workbench is running",
    message: "A copy from a different folder was just launched, and this one holds the settings it needs.",
    detail: [
      `Running here: SSH Workbench ${app.getVersion()}`,
      `  ${installationPath()}`,
      `Just launched: ${describeBuild(launchedVersion)}`,
      `  ${launchedPath}`,
      "",
      "Close every window of this copy, then start the other one again.",
    ].join("\n"),
    buttons: ["OK"],
    noLink: true,
  };
  if (window) {
    if (window.isMinimized()) window.restore();
    window.focus();
    dialog.showMessageBox(window, options).catch(() => undefined);
  } else {
    dialog.showMessageBox(options).catch(() => undefined);
  }
}

function openAnotherWindow() {
  createWindow().catch(() => {
    const existing = BrowserWindow.getAllWindows()[0];
    if (!existing) return;
    if (existing.isMinimized()) existing.restore();
    existing.focus();
  });
}

function launchedWith(flag) {
  return process.argv.includes(flag);
}

function stillRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // A copy running as another user cannot be signalled, but it is running, and
    // reporting it gone would relaunch into a lock that is still held.
    return error?.code === "EPERM";
  }
}

// Closing another installation means closing every process it runs — the main
// process, its renderers, its GPU process — and then waiting for the operating
// system to agree that they are gone, because the lock is not free until they are.
//
// Every signal goes only to a process that is still the one that was listed. Ids are
// reused, and the forced kill in particular is sent seconds after the listing: one
// whose process has ended in the meantime may by then belong to something else
// entirely, and is treated as gone instead.
async function closeInstallation(group) {
  const ours = (pid) => sameProcess(pid, group.started?.[pid]) && stillRunning(pid);
  const signal = (name) => {
    for (const pid of group.pids.filter(ours)) {
      try { process.kill(pid, name); } catch { /* it ended between the listing and here */ }
    }
  };
  signal("SIGTERM");
  const deadline = Date.now() + TAKEOVER_WAIT_MILLISECONDS;
  // Halfway through the budget, a copy that has not gone is not going to; on Windows
  // both signals are the same call, so this only ever matters elsewhere.
  const insist = Date.now() + Math.round(TAKEOVER_WAIT_MILLISECONDS / 2);
  let insisted = false;
  while (Date.now() < deadline && group.pids.some(ours)) {
    if (!insisted && Date.now() > insist) {
      signal("SIGKILL");
      insisted = true;
    }
    await new Promise((resolve) => setTimeout(resolve, 120));
  }
  return !group.pids.some(ours);
}

// Launched while another copy holds the lock. The same installation means this is a
// second launch of the build already running, which has been asked for another
// window and will open one. A different folder means two builds, and the one just
// launched is the one that was asked for — so rather than vanishing and leaving the
// older build serving windows, it offers to close that copy and take its place.
//
// The offer is a question because the answer costs something: the running copy's
// sessions and any transfer in progress end with it. `--take-over` answers it in
// advance, `--no-take-over` declines it, and `--took-over` marks the relaunch so a
// lock that is still held cannot become a loop.
async function handleLockedOut() {
  const mine = installationPath();
  const running = otherInstallations(
    await listCopies({ execPath: process.execPath }),
    { installation: mine, pid: process.pid },
  );
  if (!running.length) {
    // The copy holding the lock is this same installation; it has the launch.
    app.quit();
    return;
  }
  const other = running[0];
  const otherVersion = installedVersion(other.path);
  const shared = [
    `Running:  ${describeBuild(otherVersion)}`,
    `  ${other.path}`,
    `Launched: SSH Workbench ${app.getVersion()}`,
    `  ${mine}`,
  ];
  await app.whenReady();
  if (launchedWith("--no-take-over")) {
    app.exit(0);
    return;
  }
  if (launchedWith("--took-over")) {
    dialog.showMessageBoxSync({
      type: "error",
      title: "SSH Workbench could not start",
      message: "Another copy took the settings folder before this build could start.",
      detail: shared.join("\n"),
      buttons: ["OK"],
      noLink: true,
    });
    app.exit(1);
    return;
  }
  if (!launchedWith("--take-over")) {
    const choice = dialog.showMessageBoxSync({
      type: "warning",
      title: "Another copy of SSH Workbench is running",
      message: `${describeBuild(otherVersion)} is already running, from a different folder.`,
      detail: [
        ...shared,
        "",
        "One copy runs at a time: both use the same saved connections and the same"
          + " Chromium profile, and two processes cannot share them.",
        "Closing the running copy ends its sessions and any transfer in progress.",
      ].join("\n"),
      buttons: ["Close it and start this build", "Cancel"],
      defaultId: 1,
      cancelId: 1,
      noLink: true,
    });
    if (choice !== 0) {
      app.exit(0);
      return;
    }
  }
  if (!(await closeInstallation(other))) {
    dialog.showErrorBox("The other copy is still running",
      [`${describeBuild(otherVersion)} did not close, so this build cannot start.`, "", ...shared].join("\n"));
    app.exit(1);
    return;
  }
  // A process is given the lock once and cannot ask again, so the build the user
  // launched starts over: the same executable, the same arguments, and the flag that
  // says this has already been tried once.
  app.relaunch({
    args: process.argv.slice(1).filter((argument) => argument !== "--took-over").concat("--took-over"),
  });
  app.exit(0);
}

// One process serves every window. A second process would point at the same
// Chromium profile directory and contend for its databases, which costs several
// seconds of startup for each copy after the first, so launching the application
// again asks the process that owns the profile for another window instead.
if (!app.requestSingleInstanceLock({
  version: app.getVersion(),
  installation: installationPath(),
  speaksForItself: true,
})) {
  handleLockedOut().catch(() => app.exit(1));
} else {
  app.on("second-instance", (_event, argv, _workingDirectory, extra) => {
    // A launch of this same installation is what argv[0] and the lock data agree on;
    // the data is preferred because an AppImage's executable path is a fresh mount
    // point every time and says nothing about which file was run.
    const launched = extra?.installation || argv?.[0];
    if (sameInstallation(launched, installationPath())) {
      openAnotherWindow();
      return;
    }
    // 0.11.5 and later put their own question to the user and may close this copy;
    // there is nothing useful to add, and two dialogs about one launch is noise.
    if (extra?.speaksForItself) return;
    refuseOtherCopy(launched, extra?.version || installedVersion(launched));
  });
  app.whenReady().then(startUp).catch((error) => {
    dialog.showErrorBox("SSH Workbench could not start", String(error?.message || error));
    app.quit();
  });
}

app.on("before-quit", () => { shutdown().catch(() => undefined); });

app.on("window-all-closed", async () => {
  await shutdown();
  if (process.platform !== "darwin") app.quit();
});

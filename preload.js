"use strict";

const { contextBridge, ipcRenderer, webUtils } = require("electron");

const CAPTURE_LIFETIME_MILLISECONDS = 5000;

// Inbound drag-and-drop runs entirely inside this isolated world. Native File
// objects lose their local-path backing when they cross the context bridge, so
// the drop event is captured here, converted to plain path strings, and only
// those strings are handed to the renderer world or to the main process.
let capture = { paths: [], count: 0, at: 0 };

function pathForFile(file) {
  try {
    const local = webUtils.getPathForFile(file);
    return typeof local === "string" ? local : "";
  } catch {
    return "";
  }
}

function pathsFromFileList(list) {
  const paths = [];
  try {
    for (let index = 0; index < list.length; index += 1) {
      const local = pathForFile(list[index]);
      if (local) paths.push(local);
    }
  } catch {
    return paths;
  }
  return paths;
}

function captureDrop(event) {
  const list = event.dataTransfer && event.dataTransfer.files;
  const count = list ? list.length : 0;
  capture = { paths: count ? pathsFromFileList(list) : [], count, at: Date.now() };
}

// A pasted screenshot has no local path — it exists only as bytes on the
// clipboard — so both possibilities are captured here in the isolated world and
// the renderer never has to handle the payload itself.
let clipboardCapture = { paths: [], images: [], at: 0 };

function capturePaste(event) {
  const list = event.clipboardData && event.clipboardData.files;
  const paths = [];
  const images = [];
  try {
    for (let index = 0; index < (list ? list.length : 0); index += 1) {
      const file = list[index];
      const local = pathForFile(file);
      if (local) paths.push(local);
      else if (String(file.type || "").startsWith("image/")) {
        // Start reading immediately: the clipboard item is only valid for this event.
        images.push({ type: file.type, bytes: file.arrayBuffer() });
      }
    }
  } catch { /* an unreadable clipboard entry is simply skipped */ }
  clipboardCapture = { paths, images, at: Date.now() };
}

function takeClipboardCapture() {
  const taken = clipboardCapture;
  clipboardCapture = { paths: [], images: [], at: 0 };
  if (!taken.at || Date.now() - taken.at > CAPTURE_LIFETIME_MILLISECONDS) {
    return { paths: [], images: [] };
  }
  return taken;
}

function takeCapture() {
  const taken = capture;
  capture = { paths: [], count: 0, at: 0 };
  if (!taken.at || Date.now() - taken.at > CAPTURE_LIFETIME_MILLISECONDS) {
    return { paths: [], count: 0 };
  }
  return taken;
}

window.addEventListener("drop", captureDrop, true);
window.addEventListener("dragenter", () => { capture = { paths: [], count: 0, at: 0 }; }, true);
window.addEventListener("paste", capturePaste, true);

// Dropped uploads are queued here rather than in the renderer world: the paths
// are read out of the drop event immediately, while a second drop is still able
// to arrive before the first upload finishes.
let uploadQueue = Promise.resolve();

function queueUpload(run) {
  const started = uploadQueue.then(run, run);
  uploadQueue = started.then(() => undefined, () => undefined);
  return started;
}

// `canceled` says which step stopped: "choice" when no local paths were picked at
// all, "conflicts" when the collision dialog was dismissed. The caller needs the
// difference — one is worth a word in the status bar and the other is not.
function noUpload(reason) {
  return { canceled: reason, uploaded: [], skipped: [], renamed: [] };
}

// Every inbound upload takes the same three steps: find out what is already in the
// destination, let the renderer ask about anything that would be replaced, then
// transfer. The local paths never leave this isolated world — the renderer sees only
// the names in the plan — and the whole sequence runs inside the queue, so a second
// drop waits its turn rather than opening a dialog over the first one.
async function runUpload(id, paths, directory, onConflicts) {
  const plan = await ipcRenderer.invoke("files:plan-upload", id, paths, directory);
  let decisions = {};
  if (plan.collisions.length) {
    const answered = typeof onConflicts === "function" ? await onConflicts(plan) : null;
    // No answer means the dialog was dismissed, and a dismissed dialog is a refusal:
    // nothing is sent, rather than falling back to replacing what is there.
    if (!answered) return noUpload("conflicts");
    decisions = answered;
  }
  const report = await ipcRenderer.invoke("files:upload", id, paths, directory, decisions);
  return { canceled: null, ...report };
}

function subscribe(channel, callback) {
  const listener = (_event, payload) => callback(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}

contextBridge.exposeInMainWorld("sshWorkbench", Object.freeze({
  app: Object.freeze({
    info: () => ipcRenderer.invoke("app:info"),
  }),
  windows: Object.freeze({
    create: () => ipcRenderer.invoke("windows:create"),
  }),
  sessions: Object.freeze({
    create: () => ipcRenderer.invoke("sessions:create"),
    connect: (id, config) => ipcRenderer.invoke("sessions:connect", id, config),
    disconnect: (id) => ipcRenderer.invoke("sessions:disconnect", id),
    close: (id) => ipcRenderer.invoke("sessions:close", id),
    onStatus: (callback) => subscribe("session:status", callback),
    onBrowseUser: (callback) => subscribe("session:browse-user", callback),
  }),
  profiles: Object.freeze({
    list: () => ipcRenderer.invoke("profiles:list"),
    // Everything about a saved connection except its secrets.
    get: (id) => ipcRenderer.invoke("profiles:get", id),
    // Its secrets, decrypted, for a connection that is being opened now. This is a
    // use of the credential, and is called for nothing else.
    secrets: (id) => ipcRenderer.invoke("profiles:secrets", id),
    save: (profile) => ipcRenderer.invoke("profiles:save", profile),
    delete: (id) => ipcRenderer.invoke("profiles:delete", id),
    security: () => ipcRenderer.invoke("profiles:security"),
  }),
  // The master password over saved credentials. Every one of these hands the typed
  // password straight to the main process and gets back only status.
  vault: Object.freeze({
    status: () => ipcRenderer.invoke("vault:status"),
    set: (password, policy) => ipcRenderer.invoke("vault:set", password, policy),
    change: (currentPassword, newPassword) => ipcRenderer.invoke("vault:change", currentPassword, newPassword),
    remove: (password, discardCredentials) => ipcRenderer.invoke("vault:remove", password, discardCredentials),
    unlock: (password) => ipcRenderer.invoke("vault:unlock", password),
    lock: () => ipcRenderer.invoke("vault:lock"),
    policy: (password, policy) => ipcRenderer.invoke("vault:policy", password, policy),
    // Every window hears about every change, whichever window made it.
    onChanged: (callback) => subscribe("vault:changed", callback),
  }),
  files: Object.freeze({
    list: (id, directory) => ipcRenderer.invoke("files:list", id, directory),
    followPassword: (id, password) => ipcRenderer.invoke("files:follow-password", id, password),
    declineFollow: (id) => ipcRenderer.invoke("files:decline-follow", id),
    search: (id, directory, query, recursive) => ipcRenderer.invoke("files:search", id, directory, query, recursive),
    resolve: (id, remoteFile) => ipcRenderer.invoke("files:resolve", id, remoteFile),
    read: (id, remoteFile) => ipcRenderer.invoke("files:read", id, remoteFile),
    readBinary: (id, remoteFile) => ipcRenderer.invoke("files:read-binary", id, remoteFile),
    // `options` is `{ eol, expect }`: the line ending and the stamp `read` returned.
    write: (id, remoteFile, contents, options) => ipcRenderer.invoke("files:write", id, remoteFile, contents, options),
    mkdir: (id, directory, name) => ipcRenderer.invoke("files:mkdir", id, directory, name),
    rename: (id, remoteFile, name) => ipcRenderer.invoke("files:rename", id, remoteFile, name),
    delete: (id, paths) => ipcRenderer.invoke("files:delete", id, paths),
    // The dialog opens before the queue is joined: picking files should not have to
    // wait behind a transfer that is already running.
    uploadFiles: async (id, directory, onConflicts) => {
      const paths = await ipcRenderer.invoke("files:choose-upload", id, "files");
      if (!paths.length) return noUpload("choice");
      return queueUpload(() => runUpload(id, paths, directory, onConflicts));
    },
    uploadFolder: async (id, directory, onConflicts) => {
      const paths = await ipcRenderer.invoke("files:choose-upload", id, "folder");
      if (!paths.length) return noUpload("choice");
      return queueUpload(() => runUpload(id, paths, directory, onConflicts));
    },
    uploadDropped: (id, directory, onConflicts) => {
      const found = takeCapture();
      if (!found.paths.length) {
        const message = found.count
          ? `No local paths were provided for ${found.count} dropped item${found.count === 1 ? "" : "s"}. Use Upload files or Upload folder instead.`
          : "Drop one or more local files or folders.";
        return Promise.reject(new Error(message));
      }
      return queueUpload(() => runUpload(id, found.paths, directory, onConflicts));
    },
    // Clipboard contents go to the remote folder: copied files by path, a pasted
    // screenshot by its bytes.
    pasteClipboard: async (id, directory, onConflicts) => {
      const taken = takeClipboardCapture();
      if (taken.paths.length) {
        const report = await queueUpload(() => runUpload(id, taken.paths, directory, onConflicts));
        return { kind: "files", ...report };
      }
      if (taken.images.length) {
        const image = taken.images[0];
        const bytes = new Uint8Array(await image.bytes);
        const written = await queueUpload(() =>
          ipcRenderer.invoke("files:paste-image", id, bytes, directory, image.type));
        return { kind: "image", ...written, extra: taken.images.length - 1 };
      }
      return { kind: "empty" };
    },
    pasteClipboardImage: (id, directory) =>
      queueUpload(() => ipcRenderer.invoke("files:paste-clipboard-image", id, directory)),
    download: (id, items) => ipcRenderer.invoke("files:download", id, items),
    startDrag: (id, items) => ipcRenderer.invoke("files:start-drag", id, items),
  }),
  terminal: Object.freeze({
    start: (id, dimensions) => ipcRenderer.invoke("terminal:start", id, dimensions),
    input: (id, data) => ipcRenderer.send("terminal:input", id, data),
    binary: (id, data) => ipcRenderer.send("terminal:binary", id, data),
    resize: (id, columns, rows) => ipcRenderer.send("terminal:resize", id, columns, rows),
    onData: (callback) => subscribe("terminal:data", callback),
    onExit: (callback) => subscribe("terminal:exit", callback),
  }),
  clipboard: Object.freeze({
    read: () => ipcRenderer.invoke("clipboard:read"),
    write: (text) => ipcRenderer.invoke("clipboard:write", text),
  }),
  dialogs: Object.freeze({
    privateKey: () => ipcRenderer.invoke("dialog:private-key"),
  }),
}));

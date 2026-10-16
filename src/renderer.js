import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { Unicode11Addon } from "@xterm/addon-unicode11";
import "@xterm/xterm/css/xterm.css";
import { cleanCopy, cleanPaste } from "../lib/terminal-copy.js";
import { pathEntry, pathForClipboard } from "../lib/path-entry.js";
import {
  credentialsBoxChecked, credentialsControlEnabled, credentialsUnreadable, afterSave, fillSavedSecrets,
} from "../lib/saved-credentials.js";

const api = window.sshWorkbench;
const $ = (id) => document.getElementById(id);

const workbench = {
  sessions: new Map(),
  order: [],
  activeId: null,
  reconnectId: null,
  profileId: null,
  secureCredentials: false,
  // The master password state, shared by every window because one process holds it.
  vault: null,
  version: "",
  // Whether the loaded connection is holding credentials that have not been unlocked.
  profileLocked: false,
  // Whether its stored credentials cannot be decrypted at all, which is a different
  // thing and has a different answer: they can only be replaced, not changed.
  profileDamaged: false,
  // Presence is separate from readability and from whether encryption is available
  // today. An existing opaque blob must survive either of those things being false.
  profileCredentialsPresent: false,
  connecting: false,
  maxSessions: 8,
  // Replaced by what the main process actually enforces, once it has been asked.
  clipboardLimit: 200_000,
};

const TERMINAL_OPTIONS = {
  cursorBlink: true,
  fontSize: 14,
  fontFamily: "Cascadia Mono, Consolas, ui-monospace, monospace",
  scrollback: 10000,
  theme: { background: "#101216", foreground: "#e7ebf2", cursor: "#cdd6e4", selectionBackground: "#31518e" },
  // `terminal.unicode`, which the Unicode 11 widths below are switched on through, is
  // still behind xterm's proposed-API flag.
  allowProposedApi: true,
};

// Beyond these a click on the name downloads the file rather than opening it. The
// image limit is the one the main process puts on reading a file for preview.
const EDIT_LIMIT = 2 * 1024 * 1024;
const PREVIEW_IMAGE_LIMIT = 20 * 1024 * 1024;

function active() {
  return workbench.sessions.get(workbench.activeId) || null;
}

function nextFrame() {
  return new Promise((resolve) => requestAnimationFrame(() => resolve()));
}

function storedSearchScope() {
  return localStorage.getItem("searchScope") === "current" ? "current" : "recursive";
}

function connectedSession() {
  const session = active();
  return session && session.connected ? session : null;
}

function cleanError(error) {
  // Strip the IPC wrapper and the bare "Error:" that Electron leaves behind, so the
  // status line reads as a sentence rather than as a stack frame.
  return String(error?.message || error)
    .replace(/^Error invoking remote method '[^']+':\s*/, "")
    .replace(/^Error:\s*/, "")
    .trim();
}

function connectMessage(message) {
  $("connect-message").textContent = message;
}

/* ------------------------------------------------------------------ status */

function setMessage(session, text, tone = "") {
  session.message = { text, tone };
  if (session === active()) renderMessage(session);
}

function renderMessage(session) {
  const node = $("file-message");
  node.textContent = session.message.text;
  // The status bar is one line; the full text stays reachable on hover.
  node.title = session.message.text;
  node.className = session.message.tone === "error" ? "status-error" : session.message.tone === "ok" ? "status-ok" : "";
}

function fileStatus(text, error = false, ok = false) {
  const session = active();
  if (session) setMessage(session, text, error ? "error" : ok ? "ok" : "");
}

/* -------------------------------------------------------------- clipboard */

// Resolves to what the main process reported -- `{ truncated: true }` when the text
// was longer than the clipboard channel carries and only its start was written -- or
// to nothing when the browser's own clipboard had to be used instead.
function copyToClipboard(text) {
  return api.clipboard.write(text).catch(() => navigator.clipboard?.writeText(text).catch(() => undefined));
}

async function readClipboard() {
  try {
    return await api.clipboard.read();
  } catch {
    try { return await navigator.clipboard.readText(); } catch { return ""; }
  }
}

/* ---------------------------------------------------------------- sessions */

function sessionLabel(connection) {
  const host = connection.host || "host";
  const port = Number(connection.port) === 22 ? "" : `:${connection.port}`;
  return `${connection.username || "user"}@${host}${port}`;
}

function publicConnection(config) {
  return {
    host: config.host,
    port: config.port,
    username: config.username,
    authType: config.authType,
    keyPath: config.keyPath,
    protocol: config.protocol,
    jump: {
      enabled: config.jump.enabled,
      host: config.jump.host,
      port: config.jump.port,
      username: config.jump.username,
      authType: config.jump.authType,
      keyPath: config.jump.keyPath,
    },
  };
}

function newSession(id, connection, config, startPath, profileId = null) {
  return {
    id,
    connection,
    config,
    startPath,
    // The saved connection this tab was opened from, if any. Its config above keeps no
    // secrets, so this is where Reconnect goes back for them -- and the only place
    // that says which saved connection they belong to.
    profileId,
    label: sessionLabel(connection),
    connected: true,
    home: connection.home || "/",
    cwd: connection.home || "/",
    parent: null,
    rows: [],
    rowNodes: new Map(),
    selected: new Set(),
    sortKey: "name",
    sortDirection: 1,
    request: 0,
    searchMode: false,
    searchText: "",
    searchScope: storedSearchScope(),
    searchTimer: null,
    countText: "",
    message: { text: "Ready", tone: "" },
    terminal: null,
    fit: null,
    host: null,
    opened: false,
    mouseSelection: false,
    // Whether the selection was made with Alt+drag, which xterm makes a rectangle:
    // every line of it starts at the same column, which changes what its shared
    // indentation is.
    columnSelection: false,
    // A sudo password prompt raised while this tab was in the background, waiting
    // for the tab to be shown rather than being answered "no" on the user's behalf.
    pendingFollow: null,
    followAsking: false,
    disposeWindowListeners: null,
  };
}

// Every way of copying removes the indentation the whole selection shares, because
// a selection is a rectangle of screen and the depth it was printed at is not part
// of what was copied. Ctrl+Shift+C is the one that does not, for the rare case where
// the leading whitespace is the point.
//
// The status line is written once the copy has landed, because a copy longer than
// the clipboard channel carries is cut short there, and saying "Copied" over half a
// selection is worse than saying nothing: it is found out only when the paste comes
// up short.
function copySelection(session, { verbatim = false, announce = true } = {}) {
  if (!session.terminal.hasSelection()) return false;
  const selection = session.terminal.getSelection();
  const startColumn = session.terminal.getSelectionPosition()?.start.x || 0;
  const text = verbatim ? selection : cleanCopy(selection, { startColumn, column: session.columnSelection });
  session.terminal.clearSelection();
  session.mouseSelection = false;
  copyToClipboard(text).then((result) => {
    if (result?.truncated) {
      setMessage(session, `Copied only the first ${workbench.clipboardLimit.toLocaleString()} of ${text.length.toLocaleString()} characters; the clipboard will not take more at once.`, "error");
      return;
    }
    if (!announce) return;
    setMessage(session, text === selection
      ? "Copied the selection."
      : "Copied the selection, without the indentation every line shared.", "ok");
  });
  return true;
}

// Every way text reaches the shell as a paste comes through here -- right-click,
// Ctrl+V, Ctrl+Shift+V, Shift+Insert, a middle-click on Linux -- so none of them can
// carry a control character past it. What is taken out, and why, is in cleanPaste.
function pasteText(session, text) {
  const clean = cleanPaste(text);
  if (clean) session.terminal.paste(clean);
}

function pasteFromClipboard(session) {
  readClipboard().then((text) => {
    if (text) {
      pasteText(session, text);
      return;
    }
    // Nothing a shell can use, so an image on the clipboard goes to the folder.
    pasteClipboardImage(session);
  });
}

async function pasteClipboardImage(session) {
  const target = session.cwd;
  try {
    const written = await api.files.pasteClipboardImage(session.id, target);
    if (!written) return false;
    await refreshView(session);
    setMessage(session, `Pasted ${written.name} (${formatSize(written.bytes)}) into ${target}.`, "ok");
    return true;
  } catch (error) {
    setMessage(session, cleanError(error), "error");
    return false;
  }
}

function createTerminal(session) {
  const host = document.createElement("div");
  host.className = "terminal hidden";
  $("terminals").append(host);
  const fit = new FitAddon();
  const terminal = new Terminal(TERMINAL_OPTIONS);
  terminal.loadAddon(fit);
  // xterm counts an emoji as one cell by default (Unicode 6), while the host's
  // wcwidth -- and so readline, zsh and vim -- counts two. Every emoji on a line then
  // leaves the cursor one cell away from where the shell thinks it is.
  terminal.loadAddon(new Unicode11Addon());
  terminal.unicode.activeVersion = "11";
  terminal.onData((data) => api.terminal.input(session.id, data));
  // Mouse reports in the classic ESC [ M encoding arrive as raw bytes on a
  // separate channel; without this a program that grabs the mouse receives
  // nothing at all while local selection is disabled underneath it.
  terminal.onBinary((data) => api.terminal.binary(session.id, data));
  terminal.onResize(({ cols, rows }) => api.terminal.resize(session.id, cols, rows));
  terminal.attachCustomKeyEventHandler((event) => terminalKeys(session, event));

  // Windows-console habits. Shift held during a drag makes xterm select locally
  // even while the remote program owns the mouse; here it also copies, and any
  // mouse selection can then be copied with Enter or the right button.
  let dragFromHost = false;
  let dragWithShift = false;
  // A drag the remote program owns: where it was pressed, and where the pointer is.
  let grabbedPress = null;
  let pointer = null;
  const synthetic = (type, at, { shiftKey = false, buttons = 1 } = {}) => {
    const event = new MouseEvent(type, {
      bubbles: true,
      cancelable: true,
      view: window,
      button: 0,
      buttons,
      detail: 1,
      shiftKey,
      clientX: at.clientX,
      clientY: at.clientY,
      screenX: at.screenX,
      screenY: at.screenY,
    });
    event.workbenchRestarted = true;
    return event;
  };
  // Capture phase on purpose: when a remote program has grabbed the mouse, xterm
  // cancels these events, and a bubble-phase listener would never run — which is
  // exactly the case where Shift+drag matters most.
  host.addEventListener("mousedown", (event) => {
    if (event.button !== 0) return;
    // The press this handler raised again below; its drag is already being followed.
    if (event.workbenchRestarted) return;
    dragFromHost = true;
    dragWithShift = event.shiftKey;
    // xterm makes an Alt+drag a column selection, and a double or triple click a
    // word or a line whatever else is held.
    session.columnSelection = event.altKey && event.detail <= 1;
    const grabbed = session.terminal.modes?.mouseTrackingMode !== "none";
    grabbedPress = grabbed && !event.shiftKey
      ? { target: event.target, clientX: event.clientX, clientY: event.clientY, screenX: event.screenX, screenY: event.screenY }
      : null;
    pointer = grabbedPress;
    // xterm reads Shift+mousedown as "extend the selection", which is not what
    // Shift+drag means here. With nothing selected there is nothing to extend and the
    // drag selects nothing at all; with something selected it stretches that instead,
    // so the same drag copies different text depending on what came before it — and a
    // block that reaches back to a line at the left margin shares no indentation to
    // remove. Shift+drag starts a selection where it lands, every time.
    //
    // The press is raised again without Shift, which is the press that starts one.
    // Where a remote program has grabbed the mouse, Shift is the only thing that takes
    // the drag back from it, and xterm starts a selection with it already — so there
    // it stays exactly as it is.
    if (event.shiftKey && session.terminal.modes?.mouseTrackingMode === "none") {
      event.preventDefault();
      event.stopPropagation();
      const restart = new MouseEvent("mousedown", {
        bubbles: true,
        cancelable: true,
        view: window,
        button: 0,
        buttons: event.buttons,
        detail: event.detail || 1,
        // Alt is kept, so Shift+Alt+drag still selects a column.
        altKey: event.altKey,
        clientX: event.clientX,
        clientY: event.clientY,
        screenX: event.screenX,
        screenY: event.screenY,
      });
      restart.workbenchRestarted = true;
      event.target.dispatchEvent(restart);
    }
  }, true);
  // Shift pressed after the drag began, while a remote program -- Claude Code, vim,
  // tmux -- holds the mouse. The press has already gone to the program, so there is
  // no local selection for Shift to turn into a copy. The drag is taken back: the
  // program is told the button came up where the pointer is now, so it is not left
  // believing it is still held, and a local selection is started from the original
  // press and stretched to the pointer, as if Shift had been down from the start. The
  // program has still seen the click; that cannot be taken back.
  const followPointer = (event) => {
    if (grabbedPress && !event.workbenchRestarted) {
      pointer = { clientX: event.clientX, clientY: event.clientY, screenX: event.screenX, screenY: event.screenY };
    }
  };
  const takeDragBack = (event) => {
    if (event.key !== "Shift" || !dragFromHost || !grabbedPress) return;
    const press = grabbedPress;
    grabbedPress = null;
    dragWithShift = true;
    const at = pointer || press;
    document.dispatchEvent(synthetic("mouseup", at, { buttons: 0 }));
    press.target.dispatchEvent(synthetic("mousedown", press, { shiftKey: true }));
    document.dispatchEvent(synthetic("mousemove", at, { shiftKey: true }));
  };
  addEventListener("mousemove", followPointer, true);
  addEventListener("keydown", takeDragBack, true);

  // Listening on the window catches a drag that is released past the pane edge.
  const finishDrag = (event) => {
    if (event.workbenchRestarted) return;
    grabbedPress = null;
    if (!dragFromHost) return;
    dragFromHost = false;
    const withShift = dragWithShift || event.shiftKey;
    // The final pointer position reaches the selection after this event.
    setTimeout(() => {
      if (!session.terminal || !session.terminal.hasSelection()) return;
      session.mouseSelection = true;
      if (withShift) copySelection(session);
    }, 0);
  };
  addEventListener("mouseup", finishDrag, true);
  session.disposeWindowListeners = () => {
    removeEventListener("mouseup", finishDrag, true);
    removeEventListener("mousemove", followPointer, true);
    removeEventListener("keydown", takeDragBack, true);
  };

  // Ctrl+V, and a middle-click on Linux, reach xterm as a browser paste event, which
  // xterm turns into input itself without going through `paste()`. It is taken over
  // here, before it gets to xterm's own textarea, so it is cleaned like every other
  // paste. A paste carrying files or an image never gets this far: the window's
  // listener sends that to the remote folder first.
  host.addEventListener("paste", (event) => {
    const text = event.clipboardData?.getData("text/plain");
    event.preventDefault();
    event.stopPropagation();
    if (text) pasteText(session, text);
  }, true);

  host.addEventListener("contextmenu", (event) => {
    event.preventDefault();
    // Copy an existing selection, otherwise paste, exactly as the Windows
    // console does with QuickEdit enabled.
    if (!copySelection(session)) pasteFromClipboard(session);
  }, true);

  session.host = host;
  session.fit = fit;
  session.terminal = terminal;
}

function terminalKeys(session, event) {
  if (event.type !== "keydown") return true;
  const key = String(event.key || "");
  const lower = key.toLowerCase();
  const control = event.ctrlKey || event.metaKey;
  // Combinations the application owns must not also reach the remote shell.
  if (control && event.shiftKey && (lower === "t" || lower === "w" || lower === "n")) return false;
  if (control && (key === "PageUp" || key === "PageDown")) return false;
  if (event.altKey && !control && /^[1-9]$/.test(key)) return false;
  if (control && !event.shiftKey && lower === "f") return false;
  if (key === "F5") return false;

  // Copy: Ctrl+C with a selection, Ctrl+Shift+C, and the console's Ctrl+Insert.
  // The browser's own copy is cancelled: on Linux xterm keeps the selection in its
  // hidden textarea, and the native copy that follows the key would replace the
  // text written here with the raw selection, indentation and all.
  if (control && lower === "c" && session.terminal.hasSelection()) {
    event.preventDefault();
    copySelection(session, { verbatim: event.shiftKey });
    return false;
  }
  if (control && key === "Insert") {
    event.preventDefault();
    copySelection(session);
    return false;
  }
  // Plain Ctrl+V is left to Chromium: returning false stops xterm sending ^V, but
  // without preventDefault the browser still raises a paste event, which is the
  // only thing that carries clipboard images and copied file paths. The paste
  // listener decides from the clipboard contents where it should go.
  if (control && !event.shiftKey && lower === "v") return false;
  // Ctrl+Shift+V and the console's Shift+Insert raise no paste event of their own.
  if ((control && event.shiftKey && lower === "v") || (event.shiftKey && !control && key === "Insert")) {
    event.preventDefault();
    pasteFromClipboard(session);
    return false;
  }
  // Enter copies and clears a mouse selection instead of reaching the shell,
  // which is how the Windows console finishes a QuickEdit selection.
  if (key === "Enter" && !control && !event.altKey && session.mouseSelection) {
    if (copySelection(session)) return false;
  }
  // Typing anything else ends the console-style pending selection.
  if (key !== "Shift" && key !== "Control" && key !== "Alt" && key !== "Meta") {
    session.mouseSelection = false;
  }
  return true;
}

// Two tabs on the same account and host would otherwise be indistinguishable, so
// repeated labels are numbered in tab order. The number is kept out of the
// truncated name so it survives a narrow tab.
function tabOrdinals() {
  const totals = new Map();
  const ordinals = new Map();
  for (const id of workbench.order) {
    const session = workbench.sessions.get(id);
    if (!session) continue;
    const next = (totals.get(session.label) || 0) + 1;
    totals.set(session.label, next);
    ordinals.set(id, next);
  }
  const shown = new Map();
  for (const [id, ordinal] of ordinals) {
    const session = workbench.sessions.get(id);
    if (session && totals.get(session.label) > 1) shown.set(id, ordinal);
  }
  return shown;
}

function renderTabs() {
  const strip = $("tabstrip");
  const ordinals = tabOrdinals();
  strip.replaceChildren();
  for (const [index, id] of workbench.order.entries()) {
    const session = workbench.sessions.get(id);
    if (!session) continue;
    const ordinal = ordinals.get(id);
    const label = ordinal ? `${session.label} (${ordinal})` : session.label;
    const tab = document.createElement("div");
    tab.className = `tab${id === workbench.activeId ? " active" : ""}${session.connected ? "" : " offline"}`;
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-selected", String(id === workbench.activeId));
    tab.title = `${label}${session.connected ? "" : " — disconnected"}${index < 9 ? ` (Alt+${index + 1})` : ""}`;
    tab.onclick = (event) => { if (!event.target.closest("button")) activate(id); };
    const dot = document.createElement("span");
    dot.className = "tab-dot";
    const name = document.createElement("span");
    name.className = "tab-name";
    name.textContent = session.label;
    const badge = document.createElement("span");
    badge.className = "tab-index";
    if (ordinal) badge.textContent = String(ordinal);
    const close = document.createElement("button");
    close.className = "tab-close";
    close.type = "button";
    close.textContent = "×";
    close.title = "Close this session";
    close.setAttribute("aria-label", `Close ${label}`);
    close.onclick = () => closeSession(id);
    tab.append(dot, name, ...(ordinal ? [badge] : []), close);
    strip.append(tab);
  }
  $("new-session").disabled = workbench.order.length >= workbench.maxSessions;
}

function showConnectView(reconnectId = null) {
  workbench.reconnectId = reconnectId;
  $("workspace").classList.add("hidden");
  $("connect-view").classList.remove("hidden");
  $("cancel-connect").classList.toggle("hidden", workbench.order.length === 0);
  connectMessage(reconnectId ? "Re-enter any credentials, then reconnect this session." : "");
  // A timed unlock expires on its own, so the notice is re-read whenever this view
  // comes back rather than left saying whatever it said when it was last set.
  if (workbench.vault?.configured) refreshVaultStatus();
  $("host").focus();
}

function showWorkspace() {
  workbench.reconnectId = null;
  $("connect-view").classList.add("hidden");
  $("workspace").classList.remove("hidden");
}

async function activate(id) {
  const session = workbench.sessions.get(id);
  if (!session) return;
  workbench.activeId = id;
  showWorkspace();
  for (const other of workbench.sessions.values()) {
    if (other.host) other.host.classList.toggle("hidden", other !== session);
  }
  renderTabs();
  paint(session);
  await nextFrame();
  if (workbench.activeId !== id) return;
  if (!session.opened) {
    session.terminal.open(session.host);
    session.opened = true;
    await nextFrame();
    if (workbench.activeId !== id) return;
  }
  fitTerminal();
  session.terminal.focus();
  if (session.pendingFollow) askToFollow(session);
}

function stepSession(delta) {
  if (workbench.order.length < 2) return;
  const index = workbench.order.indexOf(workbench.activeId);
  const next = workbench.order[(index + delta + workbench.order.length) % workbench.order.length];
  activate(next);
}

async function closeSession(id) {
  const session = workbench.sessions.get(id);
  if (!session) return;
  const index = workbench.order.indexOf(id);
  clearTimeout(session.searchTimer);
  workbench.sessions.delete(id);
  workbench.order = workbench.order.filter((value) => value !== id);
  session.disposeWindowListeners?.();
  try { session.terminal?.dispose(); } catch { /* already disposed */ }
  session.host?.remove();
  await api.sessions.close(id).catch(() => undefined);
  if (workbench.activeId !== id) {
    renderTabs();
    return;
  }
  workbench.activeId = null;
  const next = workbench.order[index] || workbench.order[index - 1] || workbench.order[0];
  if (next) await activate(next);
  else { renderTabs(); showConnectView(); }
}

async function startSessionFromForm(config, startPath, profileId) {
  const created = await api.sessions.create();
  workbench.maxSessions = created.maxSessions || workbench.maxSessions;
  let session = null;
  try {
    const connection = await api.sessions.connect(created.id, config);
    session = newSession(created.id, connection, publicConnection(config), startPath, profileId);
    workbench.sessions.set(session.id, session);
    workbench.order.push(session.id);
    createTerminal(session);
    await activate(session.id);
    await api.terminal.start(session.id, { columns: session.terminal.cols, rows: session.terminal.rows });
    await openStartPath(session);
    reportProtocol(session);
    return session;
  } catch (error) {
    if (session) await closeSession(session.id);
    else await api.sessions.close(created.id).catch(() => undefined);
    throw error;
  }
}

async function reconnectSession(id, config, startPath, profileId) {
  const session = workbench.sessions.get(id);
  if (!session) throw new Error("That session tab was closed");
  const connection = await api.sessions.connect(id, config);
  session.connection = connection;
  session.config = publicConnection(config);
  session.profileId = profileId;
  session.startPath = startPath;
  session.label = sessionLabel(connection);
  session.connected = true;
  session.home = connection.home || "/";
  session.rows = [];
  session.selected.clear();
  session.searchMode = false;
  session.searchText = "";
  session.terminal.reset();
  await activate(session.id);
  await api.terminal.start(session.id, { columns: session.terminal.cols, rows: session.terminal.rows });
  await openStartPath(session);
  reportProtocol(session);
  return session;
}

// Falling back is not a failure, but working differently from the way it was asked
// to is worth one line rather than silence.
function reportProtocol(session) {
  if (session.connection.protocol !== "scp") return;
  setMessage(session, session.connection.sftpUnavailable
    ? "SFTP was unavailable on this host, so files are being moved with scp and listed with ls."
    : "Files are being moved with scp and listed with ls, as this connection asks.", "ok");
}

async function openStartPath(session) {
  const requested = String(session.startPath || "").trim();
  const target = !requested || requested === "~" ? session.home :
    requested.startsWith("~/") ? `${session.home}/${requested.slice(2)}` : requested;
  const opened = await loadDirectory(session, target);
  if (!opened && target !== session.home) {
    const fallback = await loadDirectory(session, session.home);
    if (fallback) setMessage(session, `“${target}” could not be opened; showing the home folder instead.`, "error");
  }
}

api.sessions.onStatus((status) => {
  const session = workbench.sessions.get(status?.id);
  if (!session || status.connected || !session.connected) return;
  session.connected = false;
  session.rowNodes.clear();
  // A listing or a search still in flight is bound to fail now, and its error would
  // land on the status line after this and take away the one thing worth saying.
  session.request += 1;
  session.pendingFollow = null;
  setMessage(session, `${status.message}. Use Reconnect to open it again.`, "error");
  session.terminal?.write(`\r\n\x1b[31m[${status.message}]\x1b[0m\r\n`);
  renderTabs();
  if (session === active()) {
    updateSelectionControls(session);
    updateConnectionControls(session);
  }
});

// The file pane follows the user the terminal is working as: `sudo su` in the
// terminal and the pane browses as root, `exit` and it goes back. The main process
// decides from the remote process table; this only shows the result.
api.sessions.onBrowseUser(async (state) => {
  const session = workbench.sessions.get(state?.id);
  if (!session || !session.connected) return;
  const wanted = state.wanted === 0 ? "root" : `user ${state.wanted}`;
  // Whatever the terminal did next supersedes a question still waiting to be asked.
  session.pendingFollow = null;
  if (state.needsPassword) {
    // A tab in the background is not where anyone is looking, and a password dialog
    // over the tab they are in would be asking about a terminal they cannot see. The
    // question waits for the tab to be shown, rather than being answered "no" for
    // them. The main process holds the switch open until it is answered.
    session.pendingFollow = { wanted };
    if (session === active()) askToFollow(session);
    else setMessage(session, `The terminal is now working as ${wanted}; the file pane will ask for the sudo password when this tab is shown.`);
    return;
  }
  if (state.failed) {
    setMessage(session, `The terminal is working as ${wanted}, but the file pane cannot follow: ${state.failed}.`, "error");
    return;
  }
  session.connection.browseAs = state.user;
  if (session === active()) updateConnectionControls(session);
  // Coming back from root usually means leaving a folder only root could read.
  const shown = await refreshView(session);
  if (!shown && !state.elevated) await loadDirectory(session, session.home);
  setMessage(session, state.elevated
    ? `Browsing as ${state.user}, following the terminal.`
    : `Browsing as ${session.connection.username} again.`, "ok");
});

async function askToFollow(session) {
  const pending = session.pendingFollow;
  if (!pending || session.followAsking) return;
  session.pendingFollow = null;
  session.followAsking = true;
  const { wanted } = pending;
  try {
    const followed = await passwordModal({
      title: `Browse as ${wanted} too?`,
      intro: `The terminal ${workbench.order.length > 1 ? `in ${session.label} ` : ""}is now working as ${wanted}. Enter the password sudo asks ${session.connection.username} for, and the file pane will browse as ${wanted} as well.`,
      fields: [{ name: "password", label: `sudo password for ${session.connection.username}` }],
      confirmLabel: `Browse as ${wanted}`,
      run: ({ password }) => api.files.followPassword(session.id, password),
    });
    if (!followed && workbench.sessions.has(session.id) && session.connected) {
      await api.files.declineFollow(session.id).catch(() => undefined);
      setMessage(session, `The file pane is still browsing as ${session.connection.username}.`);
    }
  } finally {
    session.followAsking = false;
  }
}

api.terminal.onData((payload) => {
  workbench.sessions.get(payload?.id)?.terminal?.write(payload.data);
});
api.terminal.onExit((payload) => {
  workbench.sessions.get(payload?.id)?.terminal?.write("\r\n\x1b[33m[remote shell closed]\x1b[0m\r\n");
});

/* ------------------------------------------------------------ connect form */

function updateAuthFields(prefix = "") {
  const type = $(`${prefix}auth-type`).value;
  $(`${prefix}key-fields`).classList.toggle("hidden", type !== "key");
  $(`${prefix}password-fields`).classList.toggle("hidden", type !== "password");
}
$("auth-type").addEventListener("change", () => updateAuthFields());
$("jump-auth-type").addEventListener("change", () => updateAuthFields("jump-"));
$("jump-enabled").addEventListener("change", () => {
  $("jump-fields").classList.toggle("hidden", !$("jump-enabled").checked);
});
$("choose-key").addEventListener("click", async () => {
  const selected = await api.dialogs.privateKey();
  if (selected) $("key-path").value = selected;
});
$("choose-jump-key").addEventListener("click", async () => {
  const selected = await api.dialogs.privateKey();
  if (selected) $("jump-key-path").value = selected;
});

function connectionFromForm() {
  return {
    host: $("host").value.trim(),
    port: Number($("port").value),
    username: $("username").value.trim(),
    authType: $("auth-type").value,
    password: $("password").value,
    keyPath: $("key-path").value,
    passphrase: $("passphrase").value,
    protocol: $("protocol").value,
    jump: {
      enabled: $("jump-enabled").checked,
      host: $("jump-host").value.trim(),
      port: Number($("jump-port").value),
      username: $("jump-username").value.trim(),
      authType: $("jump-auth-type").value,
      password: $("jump-password").value,
      keyPath: $("jump-key-path").value,
      passphrase: $("jump-passphrase").value,
    },
  };
}

function applyConnection(connection, startPath = "~") {
  $("host").value = connection.host || "";
  $("port").value = connection.port || 22;
  $("username").value = connection.username || "";
  $("auth-type").value = connection.authType || "password";
  $("password").value = connection.password || "";
  $("key-path").value = connection.keyPath || "";
  $("passphrase").value = connection.passphrase || "";
  $("protocol").value = connection.protocol || "sftp-scp";
  $("jump-enabled").checked = Boolean(connection.jump?.enabled);
  $("jump-host").value = connection.jump?.host || "";
  $("jump-port").value = connection.jump?.port || 22;
  $("jump-username").value = connection.jump?.username || "";
  // Same three choices in the same order as the destination, but a jump host still
  // starts on the agent: a bastion is the one hop most likely to use one, and a
  // password field opening by default costs the form its fits-on-screen budget.
  $("jump-auth-type").value = connection.jump?.authType || "agent";
  $("jump-password").value = connection.jump?.password || "";
  $("jump-key-path").value = connection.jump?.keyPath || "";
  $("jump-passphrase").value = connection.jump?.passphrase || "";
  $("start-path").value = startPath || "~";
  updateAuthFields();
  updateAuthFields("jump-");
  updateProtocolNote();
  $("jump-fields").classList.toggle("hidden", !$("jump-enabled").checked);
}

const PROTOCOL_NOTES = {
  sftp: "SFTP only: a host with the subsystem switched off will not connect.",
  scp: "A shell and scp throughout. Listings come from ls, so folders open more slowly.",
};

function updateProtocolNote() {
  $("protocol-note").textContent = PROTOCOL_NOTES[$("protocol").value] || "";
}
$("protocol").addEventListener("change", updateProtocolNote);
updateProtocolNote();

function credentialStorageAvailable() {
  return workbench.secureCredentials || Boolean(workbench.vault?.configured);
}

function syncCredentialsControl() {
  const box = $("save-credentials");
  const profile = { credentialsPresent: workbench.profileCredentialsPresent };
  const enabled = credentialsControlEnabled(profile, { secureStorage: credentialStorageAvailable() });
  box.disabled = !enabled;
  if (!enabled) box.checked = false;
}

function resetConnectionForm() {
  workbench.profileCredentialsPresent = false;
  applyConnection({
    port: 22,
    authType: "password",
    protocol: "sftp-scp",
    jump: { enabled: false, port: 22, authType: "agent" },
  });
  $("profile-name").value = "";
  $("save-credentials").checked = credentialStorageAvailable();
  syncCredentialsControl();
}

function clearFormSecrets() {
  $("password").value = "";
  $("passphrase").value = "";
  $("jump-password").value = "";
  $("jump-passphrase").value = "";
}

// Earlier versions remembered the last host, username, and key path here so the
// form could prefill. Saved connections cover that properly, so the app no longer
// records where you connected — and this clears what those versions left behind.
try { localStorage.removeItem("connectionProfile"); } catch { /* storage unavailable */ }
updateAuthFields();
updateAuthFields("jump-");

async function refreshProfiles(selectedId = "") {
  const summaries = await api.profiles.list();
  const select = $("saved-profile");
  select.replaceChildren(new Option("New connection…", ""));
  const locked = Boolean(workbench.vault?.configured) && !workbench.vault?.unlocked;
  for (const profile of summaries) {
    const suffix = profile.credentialsSaved
      ? profile.masterPassword && locked ? " · credentials locked" : " · credentials saved"
      : "";
    select.append(new Option(`${profile.name}${suffix}`, profile.id));
  }
  select.value = summaries.some((profile) => profile.id === selectedId) ? selectedId : "";
  $("delete-profile").disabled = !select.value;
  $("quick-connect").disabled = !select.value;
}

async function loadProfile(id) {
  if (!id) {
    workbench.profileId = null;
    workbench.profileLocked = false;
    workbench.profileDamaged = false;
    workbench.profileCredentialsPresent = false;
    localStorage.removeItem("lastProfileId");
    resetConnectionForm();
    $("delete-profile").disabled = true;
    $("quick-connect").disabled = true;
    connectMessage("");
    return;
  }
  try {
    // Loading a connection fills in the form; it does not use a saved credential, so
    // it asks for nothing and is given nothing secret. Choosing something from a list
    // — or having it chosen for you at startup, because it was the last one used — is
    // not a decision to hand over a password. That happens when Connect is pressed,
    // and the secrets go from the store straight into that connection without ever
    // sitting in a field here, where a lock in this or another window could not
    // reach them.
    const profile = await api.profiles.get(id);
    workbench.profileId = profile.id;
    workbench.profileLocked = Boolean(profile.needsUnlock);
    workbench.profileDamaged = credentialsUnreadable(profile);
    workbench.profileCredentialsPresent = Boolean(profile.credentialsPresent || profile.needsUnlock);
    $("saved-profile").value = profile.id;
    $("profile-name").value = profile.name;
    $("save-credentials").checked = credentialsBoxChecked(profile);
    syncCredentialsControl();
    $("delete-profile").disabled = false;
    $("quick-connect").disabled = false;
    applyConnection(profile.connection, profile.startPath);
    localStorage.setItem("lastProfileId", profile.id);
    const locked = profile.needsUnlock
      ? `Loaded “${profile.name}”. Its master password is asked for when you connect.`
      : "";
    connectMessage(locked || `Loaded “${profile.name}”`);
  } catch (error) {
    connectMessage(cleanError(error));
  }
}

// Called from the connect path when the credentials are about to be used, whenever
// the form is standing in for a saved connection that has credentials stored -- which
// is every time, because the form never holds them: not when the connection was
// chosen, and not when it was refilled from a tab for Reconnect. The form may have
// been edited since, so what comes out of the store fills only the fields left empty,
// and only for the server it was saved for (see fillSavedSecrets).
//
// The secrets are not written back into the form afterwards, so this runs again on the
// next connect rather than once. Under "ask every time" that next connect is meant to
// ask; otherwise it costs nothing anyone can see.
async function withSavedCredentials(config) {
  if (!workbench.profileId || !workbench.profileCredentialsPresent) return config;
  // Nothing is read, and so nothing asked for, when every secret this connection
  // could want has been typed in by hand -- or when it wants none, as with the agent.
  if (!wantsSavedSecret(config)) return config;
  if (!await ensureVaultUnlocked()) throw new Error("The master password is needed to use this connection's saved credentials.");
  const saved = await api.profiles.secrets(workbench.profileId);
  if (saved.needsUnlock) throw new Error("Saved credentials are still locked.");
  if (saved.credentialError) {
    // Damage is found here now, at the first read, rather than when the connection
    // was chosen. Whatever was typed by hand can still be used; only a connection
    // that is left with nothing to authenticate with is stopped, with the reason.
    workbench.profileDamaged = true;
    if (lacksPassword(config)) throw new Error(saved.credentialError);
    return config;
  }
  return fillSavedSecrets(config, saved.connection);
}

function wantsSavedSecret(config) {
  const empty = (hop) => (hop?.authType === "password" && !hop.password) || (hop?.authType === "key" && !hop.passphrase);
  return empty(config) || Boolean(config.jump?.enabled && empty(config.jump));
}

function lacksPassword(config) {
  const missing = (hop) => hop?.authType === "password" && !hop.password;
  return missing(config) || Boolean(config.jump?.enabled && missing(config.jump));
}

// Reconnect refills the form from the tab, which carries no secrets, and the form has
// to go back to standing for the saved connection that tab came from -- not for
// whichever one the list happens to be showing since, whose password belongs to some
// other server. A tab that came from no saved connection, or from one deleted since,
// leaves the form standing for none.
async function prepareReconnect(session) {
  applyConnection(session.config, session.startPath);
  let summary = null;
  if (session.profileId) {
    try {
      summary = (await api.profiles.list()).find((profile) => profile.id === session.profileId) || null;
    } catch { /* nothing to go back to, then */ }
  }
  workbench.profileId = summary?.id || null;
  workbench.profileDamaged = false;
  workbench.profileCredentialsPresent = Boolean(summary?.credentialsSaved);
  workbench.profileLocked = workbench.profileCredentialsPresent;
  $("saved-profile").value = workbench.profileId || "";
  $("profile-name").value = summary?.name || "";
  $("save-credentials").checked = summary
    ? credentialsBoxChecked({ credentialsPresent: summary.credentialsSaved })
    : credentialStorageAvailable();
  syncCredentialsControl();
  $("delete-profile").disabled = !summary;
  $("quick-connect").disabled = !summary;
  return summary;
}

// Which build this is, in the interface rather than in a file property dialog: an
// extracted copy that looks identical to the last one is otherwise impossible to
// tell apart from it. The window title carries it wherever the window has got to —
// a session connected for days never shows the connection screen again, and that is
// exactly when which build drew it comes into question.
async function showVersion() {
  try {
    const info = await api.app.info();
    workbench.version = info.version;
    workbench.clipboardLimit = info.clipboardLimit || workbench.clipboardLimit;
    document.title = `SSH Workbench ${info.version}`;
    const detail = `SSH Workbench ${info.version} · Electron ${info.electron} · ${info.platform}`;
    for (const label of document.querySelectorAll(".app-version")) {
      label.textContent = `v${info.version}`;
      label.title = detail;
    }
  } catch { /* the label simply stays empty, and the title keeps what it was given */ }
}
showVersion();

async function initializeProfiles() {
  try {
    const security = await api.profiles.security();
    workbench.secureCredentials = security.available;
    workbench.maxSessions = security.maxSessions || workbench.maxSessions;
    $("save-credentials").disabled = !security.available;
    $("save-credentials").checked = security.available;
    $("credential-storage").textContent = security.available
      ? `Protected by ${security.label}, and decrypted only for the connection being opened.`
      : "No secure OS keyring here; connections can still be saved without their secrets.";
    $("credential-storage").classList.toggle("warning", !security.available);
    applyVaultStatus(security.masterPassword);
    const lastId = localStorage.getItem("lastProfileId") || "";
    await refreshProfiles(lastId);
    if (lastId && $("saved-profile").value) await loadProfile(lastId);
    if (security.warning) connectMessage(security.warning);
  } catch (error) {
    connectMessage(cleanError(error));
  }
}


/* -------------------------------------------------------- master password */

// A password field, or several, in a modal. Resolves true when the work it was
// given succeeded, false when the person closed it. The typed value goes straight
// to the main process and is never kept here.
function passwordModal({ title, intro, fields, confirmLabel, policy = null, run }) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const form = document.createElement("div");
    form.className = "password-form";
    if (intro) {
      const note = document.createElement("p");
      note.textContent = intro;
      form.append(note);
    }
    const inputs = new Map();
    for (const field of fields) {
      const label = document.createElement("label");
      label.textContent = field.label;
      const input = document.createElement("input");
      input.type = "password";
      input.autocomplete = "off";
      label.append(input);
      form.append(label);
      inputs.set(field.name, input);
    }
    let policyControl = null;
    if (policy) {
      policyControl = buildPolicyControl(policy);
      form.append(policyControl.element);
    }
    const error = document.createElement("div");
    error.className = "form-message";
    error.setAttribute("role", "alert");
    form.append(error);

    // The dialog holds its buttons while this runs (see showModal), so an Enter
    // pressed again while a password is still being checked does nothing. Each one
    // would otherwise be another attempt: another wrong master password towards the
    // lockout, or another failed sudo login on the host.
    let page = null;
    const submit = async () => {
      error.textContent = "";
      const values = {};
      for (const [name, input] of inputs) values[name] = input.value;
      try {
        await run(values, policyControl ? policyControl.value() : null);
        finish(true);
        closeModal(page);
      } catch (failure) {
        error.textContent = cleanError(failure);
        const first = inputs.values().next().value;
        if (first) { first.value = ""; first.focus(); }
      }
    };

    const first = inputs.values().next().value;
    page = showModal(title, form, [
      { label: "Cancel", run: () => closeModal(page) },
      { label: confirmLabel, primary: true, run: submit },
    ], () => finish(false), { onShow: () => first?.focus() });
    const confirm = page.querySelector(".modal-footer button:last-child");
    for (const input of inputs.values()) {
      input.onkeydown = (event) => {
        if (event.key === "Enter") { event.preventDefault(); confirm.click(); }
      };
    }
  });
}

// How often the master password has to be typed: every time a saved credential is
// used, or once for a number of minutes.
function buildPolicyControl({ mode = "minutes", minutes = 15 }) {
  const element = document.createElement("fieldset");
  element.className = "policy-control";
  const legend = document.createElement("legend");
  legend.textContent = "Ask for it";
  element.append(legend);

  const name = `policy-${Math.random().toString(36).slice(2)}`;
  const every = document.createElement("input");
  every.type = "radio";
  every.name = name;
  every.checked = mode === "every";
  const everyLabel = document.createElement("label");
  everyLabel.append(every, document.createTextNode(" Every time saved credentials are used"));

  const timed = document.createElement("input");
  timed.type = "radio";
  timed.name = name;
  timed.checked = mode !== "every";
  const number = document.createElement("input");
  number.type = "number";
  number.min = "1";
  number.max = "1440";
  number.value = String(minutes || 15);
  number.className = "policy-minutes";
  const timedLabel = document.createElement("label");
  timedLabel.append(timed, document.createTextNode(" Once, then again after "), number, document.createTextNode(" minutes"));

  number.addEventListener("focus", () => { timed.checked = true; });
  element.append(everyLabel, timedLabel);
  return {
    element,
    value: () => (every.checked ? { mode: "every" } : { mode: "minutes", minutes: Number(number.value) }),
  };
}

function describeVault(status) {
  if (!status?.configured) return "No master password: the keyring alone protects saved credentials.";
  if (status.cooldownSeconds) {
    return `Too many wrong attempts; the master password can be tried again in ${status.cooldownSeconds} seconds.`;
  }
  if (status.mode === "every") {
    return status.unlocked
      ? "Master password set, and asked for every time a saved credential is used."
      : "Saved credentials are locked; the master password is asked for every use.";
  }
  if (!status.unlocked) return `Saved credentials are locked; the master password lasts ${status.minutes} minutes once entered.`;
  const minutes = Math.ceil((status.secondsRemaining || 0) / 60);
  return `Saved credentials are unlocked for ${minutes} more ${minutes === 1 ? "minute" : "minutes"}.`;
}

function applyVaultStatus(status, { refreshList = false } = {}) {
  workbench.vault = status || workbench.vault;
  const current = workbench.vault;
  // Where there is no keyring, the master password is what makes saving a
  // credential possible at all, so setting one has to open that door.
  syncCredentialsControl();
  $("master-state").textContent = describeVault(current);
  $("master-state").classList.toggle("warning", Boolean(current?.configured) && !current?.unlocked);
  $("master-lock").classList.toggle("hidden", !(current?.configured && current?.unlocked));
  $("master-manage").textContent = current?.configured ? "Master password…" : "Set master password…";
  if (refreshList) refreshProfiles($("saved-profile").value).catch(() => undefined);
  return current;
}

async function refreshVaultStatus() {
  try {
    return applyVaultStatus(await api.vault.status());
  } catch {
    return workbench.vault;
  }
}

// Called before anything reads a saved credential. With no master password set, or
// one already unlocked, it does nothing at all.
async function ensureVaultUnlocked() {
  const status = await refreshVaultStatus();
  if (!status?.configured || status.unlocked) return true;
  return passwordModal({
    title: "Unlock saved credentials",
    intro: "Enter the master password to use the credentials saved with this connection.",
    fields: [{ name: "password", label: "Master password" }],
    confirmLabel: "Unlock",
    run: async ({ password }) => { applyVaultStatus(await api.vault.unlock(password), { refreshList: true }); },
  });
}

function openMasterPasswordModal() {
  const status = workbench.vault;
  if (!status?.configured) {
    const minimum = status?.minimumLength || 6;
    return passwordModal({
      title: "Set a master password",
      intro: `Saved passwords and key passphrases will need this before they can be used. At least ${minimum} characters. It is not stored anywhere and cannot be recovered — if it is lost, the saved credentials have to be entered again.`,
      fields: [
        { name: "password", label: "Master password" },
        { name: "repeat", label: "Repeat it" },
      ],
      confirmLabel: "Set master password",
      policy: { mode: status?.mode || "minutes", minutes: status?.minutes || 15 },
      run: async ({ password, repeat }, policy) => {
        if (password !== repeat) throw new Error("Those two passwords are not the same");
        const status = applyVaultStatus(await api.vault.set(password, policy));
        await refreshProfiles($("saved-profile").value);
        connectMessage(status.carried
          ? `Master password set. ${carriedNote(status.carried)}`
          : "Master password set; saved credentials were re-encrypted with it.");
      },
    });
  }

  const body = document.createElement("div");
  body.className = "password-form";
  const state = document.createElement("p");
  state.textContent = describeVault(status);
  body.append(state);
  showModal("Master password", body, [
    { label: "Remove…", danger: true, run: () => removeMasterPassword() },
    { label: "How often…", run: () => changeUnlockPolicy() },
    { label: "Change…", primary: true, run: () => changeMasterPassword() },
  ]);
  return Promise.resolve(true);
}

function changeMasterPassword() {
  return passwordModal({
    title: "Change the master password",
    intro: "Every saved credential is re-encrypted with the new password.",
    fields: [
      { name: "current", label: "Current master password" },
      { name: "password", label: "New master password" },
      { name: "repeat", label: "Repeat the new one" },
    ],
    confirmLabel: "Change it",
    run: async ({ current, password, repeat }) => {
      if (password !== repeat) throw new Error("Those two passwords are not the same");
      const status = applyVaultStatus(await api.vault.change(current, password));
      connectMessage(status.carried ? `Master password changed. ${carriedNote(status.carried)}` : "Master password changed.");
    },
  });
}

// Credentials the keyring could not open just now are kept, not cleared, and are
// re-encrypted the first time they are used with the keyring back. Saying nothing
// would leave someone believing every credential had been moved across.
function carriedNote(count) {
  return `${count} saved credential${count === 1 ? "" : "s"} could not be re-encrypted because the operating system keyring is unavailable; ${count === 1 ? "it was" : "they were"} kept as before, ${count === 1 ? "needs" : "need"} the new master password to be used, and ${count === 1 ? "is" : "are"} re-encrypted the next time ${count === 1 ? "it is" : "they are"} used.`;
}

function changeUnlockPolicy() {
  const status = workbench.vault;
  return passwordModal({
    title: "How often to ask",
    intro: "Enter the master password to change when it is needed again.",
    fields: [{ name: "password", label: "Master password" }],
    confirmLabel: "Save",
    policy: { mode: status?.mode || "minutes", minutes: status?.minutes || 15 },
    run: async ({ password }, policy) => {
      applyVaultStatus(await api.vault.policy(password, policy));
      connectMessage(policy.mode === "every"
        ? "The master password will be asked for every time saved credentials are used."
        : `The master password will be asked for once every ${policy.minutes} minutes.`);
    },
  });
}

function removeMasterPassword() {
  // With no keyring behind it, the master password is the only thing protecting the
  // saved credentials, so removing it has to mean forgetting them.
  const keyring = Boolean(workbench.vault?.keyring);
  return passwordModal({
    title: "Remove the master password",
    intro: keyring
      ? "Saved credentials go back to being protected by the operating system keyring alone, with nothing to type before they are used."
      : "This machine has no secure keyring, so nothing would be left protecting the saved passwords and key passphrases. They will be forgotten. The connections themselves are kept, and you can enter their passwords again as you use them.",
    fields: [{ name: "password", label: "Master password" }],
    confirmLabel: keyring ? "Remove it" : "Remove it and forget the credentials",
    run: async ({ password }) => {
      applyVaultStatus(await api.vault.remove(password, !keyring));
      await refreshProfiles($("saved-profile").value);
      connectMessage(keyring
        ? "Master password removed."
        : "Master password removed, and the saved credentials with it.");
    },
  });
}

$("master-manage").addEventListener("click", () => openMasterPasswordModal());

// Locking takes back whatever this window is holding, and not only the key in the
// other process. A saved connection's secrets never reach the form any more, but a
// password typed into it would still open a connection with nothing further asked,
// which is the one thing locking exists to stop. Both ways of locking come through
// here, and every other window does the same when it hears of the lock (see
// api.vault.onChanged below), so none of them can quietly stop doing half of it.
async function lockSavedCredentials() {
  applyVaultStatus(await api.vault.lock(), { refreshList: true });
  clearFormSecrets();
  // A loaded connection that is holding credentials is waiting on the master password
  // again, exactly as it would have been had it been chosen after the lock.
  workbench.profileLocked = Boolean(workbench.profileId && workbench.profileCredentialsPresent);
}

// Every window is told about every change to the vault, whichever window made it:
// one process holds it, so a master password set, removed, unlocked or locked in one
// window is set, removed, unlocked or locked in all of them. A lock from elsewhere is
// treated exactly like one made here. A timed unlock simply running out is not a
// lock anyone asked for, and it does not wipe out what is being typed.
api.vault.onChanged((status) => {
  const before = workbench.vault;
  const changed = before?.configured !== status?.configured || before?.unlocked !== status?.unlocked;
  applyVaultStatus(status, { refreshList: changed });
  if (status?.reason === "lock") {
    clearFormSecrets();
    workbench.profileLocked = Boolean(workbench.profileId && workbench.profileCredentialsPresent);
  }
});

$("master-lock").addEventListener("click", async () => {
  await lockSavedCredentials();
  connectMessage("Saved credentials locked.");
});

$("saved-profile").addEventListener("change", () => loadProfile($("saved-profile").value));
$("saved-profile").addEventListener("dblclick", () => quickConnect());
$("quick-connect").addEventListener("click", () => quickConnect());

async function quickConnect() {
  const id = $("saved-profile").value;
  if (!id) {
    connectMessage("Choose a saved connection first, or fill in the fields below.");
    return;
  }
  if (workbench.profileId !== id) await loadProfile(id);
  if ($("saved-profile").value !== id) return;
  $("connect-form").requestSubmit();
}
$("save-profile").addEventListener("click", async () => {
  const button = $("save-profile");
  button.disabled = true;
  try {
    // A vault-status refresh is allowed to change which operations are available,
    // but never the retention decision this click began with.
    const keepingCredentials = $("save-credentials").checked;
    // Wrapping a credential needs the master password just as unwrapping one does.
    if (keepingCredentials && !await ensureVaultUnlocked()) {
      connectMessage("Nothing was saved: the master password is needed to store credentials.");
      return;
    }
    // Credentials that cannot be decrypted cannot be merged into, only replaced, and
    // replacing them is a decision rather than a detail: a keyring that is
    // unavailable today may read the same credentials perfectly well tomorrow.
    //
    // The store is what decides whether that question arises, rather than this
    // deciding in advance from what it thinks it knows. It alone can tell whether
    // any credential that matters was actually entered, and it finds damage this
    // side could not have seen -- a vault secret that was merely locked when the
    // form was filled in turns out to be corrupt only once it is unlocked and read,
    // which is during this very save.
    const write = (replaceCredentials) => api.profiles.save({
      id: workbench.profileId,
      name: $("profile-name").value,
      startPath: $("start-path").value,
      saveCredentials: keepingCredentials,
      replaceCredentials,
      connection: connectionFromForm(),
    });

    let saved = await write(false);
    let replaced = false;
    if (saved.needsReplacement) {
      if (!window.confirm(`${saved.message}\n\nReplace them with what you have entered?`)) {
        connectMessage("Nothing was saved: the credentials that cannot be read were left alone.");
        return;
      }
      saved = await write(true);
      replaced = true;
    }
    workbench.profileId = saved.id;
    const outcome = afterSave({
      name: saved.name,
      damaged: workbench.profileDamaged,
      replaced,
      keepingCredentials,
      credentialsSaved: saved.credentialsSaved,
      credentialsDropped: saved.credentialsDropped || [],
    });
    workbench.profileDamaged = outcome.damaged;
    workbench.profileCredentialsPresent = Boolean(saved.credentialsSaved);
    syncCredentialsControl();
    localStorage.setItem("lastProfileId", saved.id);
    await refreshProfiles(saved.id);
    connectMessage(outcome.message);
  } catch (error) {
    connectMessage(cleanError(error));
  } finally {
    button.disabled = false;
  }
});
$("delete-profile").addEventListener("click", async () => {
  const id = $("saved-profile").value;
  if (!id) return;
  const name = $("profile-name").value || "this connection";
  if (!window.confirm(`Delete the saved connection “${name}”?`)) return;
  try {
    await api.profiles.delete(id);
    workbench.profileId = null;
    localStorage.removeItem("lastProfileId");
    resetConnectionForm();
    await refreshProfiles();
    connectMessage(`Deleted “${name}”`);
  } catch (error) {
    connectMessage(cleanError(error));
  }
});

initializeProfiles();

$("connect-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  // Enter is now the ordinary way to connect, and two presses in quick succession
  // would otherwise start two connections. A disabled submit button does not stop
  // requestSubmit(), so the guard has to be here.
  if (workbench.connecting) return;
  workbench.connecting = true;
  const button = event.submitter || $("connect-form").querySelector("button[type=submit]");
  button.disabled = true;
  const startPath = $("start-path").value;
  const profileId = workbench.profileId;
  try {
    const config = await withSavedCredentials(connectionFromForm());
    connectMessage(workbench.reconnectId ? "Reconnecting…" : "Connecting…");
    if (workbench.reconnectId) await reconnectSession(workbench.reconnectId, config, startPath, profileId);
    else await startSessionFromForm(config, startPath, profileId);
    connectMessage("");
    if (!workbench.profileId) clearFormSecrets();
  } catch (error) {
    connectMessage(cleanError(error));
    if (workbench.order.length) $("cancel-connect").classList.remove("hidden");
  } finally {
    workbench.connecting = false;
    button.disabled = false;
  }
});

$("new-session").onclick = () => {
  if (workbench.order.length >= workbench.maxSessions) {
    fileStatus(`Close a session tab first; ${workbench.maxSessions} open sessions is the maximum.`, true);
    return;
  }
  showConnectView();
};
async function openNewWindow() {
  try {
    await api.windows.create();
  } catch (error) {
    const session = active();
    if (session) setMessage(session, cleanError(error), "error");
    else connectMessage(cleanError(error));
  }
}
$("new-window").onclick = () => openNewWindow();
$("cancel-connect").onclick = () => {
  if (!workbench.order.length) return;
  workbench.reconnectId = null;
  activate(workbench.activeId || workbench.order[workbench.order.length - 1]);
};
$("reconnect").onclick = async () => {
  const session = active();
  if (!session || session.connected) return;
  const summary = await prepareReconnect(session);
  showConnectView(session.id);
  if (summary?.credentialsSaved) {
    connectMessage(`Reconnecting uses the credentials saved with “${summary.name}”. Anything typed here is used instead.`);
  }
};
$("disconnect").addEventListener("click", async () => {
  const session = active();
  if (!session) return;
  if (session.connected) await api.sessions.disconnect(session.id).catch(() => undefined);
  await closeSession(session.id);
});

/* --------------------------------------------------------------- file pane */

function updateConnectionControls(session) {
  const online = Boolean(session && session.connected);
  const scpMode = online && session.connection.protocol === "scp" ? " · SCP" : "";
  const browseAs = online && session.connection.browseAs ? ` · browsing as ${session.connection.browseAs}` : "";
  $("connection-label").textContent = session
    ? `${sessionLabel(session.connection)}${session.connection.jump ? ` via ${sessionLabel(session.connection.jump)}` : ""}${scpMode}${browseAs}${online ? "" : " — disconnected"}`
    : "";
  $("reconnect").classList.toggle("hidden", !session || online);
  for (const id of ["up", "home", "refresh", "search", "clear-search", "search-scope", "upload-files",
    "upload-folder", "new-folder", "select-all", "restart-terminal", "path-input"]) {
    $(id).disabled = !online;
  }
  if (online) {
    $("up").disabled = !session.parent;
    $("clear-search").disabled = !session.searchText.trim();
  }
}

function paint(session) {
  renderPath(session);
  renderRows(session);
  renderMessage(session);
  $("search").value = session.searchText;
  $("search-scope").value = session.searchScope;
  $("file-count").textContent = session.countText;
  updateConnectionControls(session);
}

// Clearing the search belongs to navigation, not to loading: an initial listing
// that lands while the user is typing must not wipe out what they typed.
function clearSearch(session) {
  session.searchTimer = clearTimeout(session.searchTimer);
  session.searchText = "";
  session.searchMode = false;
  if (session === active()) {
    $("search").value = "";
    $("clear-search").disabled = true;
  }
}

function openDirectory(session, directory) {
  clearSearch(session);
  return loadDirectory(session, directory);
}

async function loadDirectory(session, directory) {
  const sequence = ++session.request;
  setMessage(session, "Refreshing…");
  try {
    const result = await api.files.list(session.id, directory);
    if (sequence !== session.request) return false;
    session.cwd = result.path;
    session.parent = result.parent;
    session.rows = result.entries;
    session.selected.clear();
    session.countText = `${result.entries.length} items`;
    sortRows(session);
    if (session === active()) {
      renderPath(session);
      renderRows(session);
      $("file-count").textContent = session.countText;
      updateConnectionControls(session);
    }
    // A name that no filesystem could hold is not shown, and not passed over in
    // silence either: it means the far end sent something it should not have.
    if (result.rejected) {
      setMessage(session, `${result.rejected} ${result.rejected === 1 ? "item was" : "items were"} hidden: the host gave ${result.rejected === 1 ? "a name" : "names"} that cannot be used.`, "error");
    } else {
      setMessage(session, "Ready");
    }
    return true;
  } catch (error) {
    if (sequence === session.request && session.connected) setMessage(session, cleanError(error), "error");
    return false;
  }
}

async function runSearch(session) {
  session.searchTimer = clearTimeout(session.searchTimer);
  const query = session.searchText.trim();
  if (!query) return openDirectory(session, session.cwd);
  const sequence = ++session.request;
  setMessage(session, `Searching for “${query}”…`);
  try {
    const result = await api.files.search(session.id, session.cwd, query, session.searchScope === "recursive");
    if (sequence !== session.request) return false;
    session.rows = result.entries;
    session.parent = result.parent;
    session.selected.clear();
    session.searchMode = true;
    session.countText = `${result.entries.length}${result.truncated ? "+" : ""} matches`;
    sortRows(session);
    if (session === active()) {
      renderPath(session);
      renderRows(session);
      $("file-count").textContent = session.countText;
      updateConnectionControls(session);
    }
    setMessage(session, describeSearch(result), result.truncated ? "" : result.entries.length ? "ok" : "");
    return true;
  } catch (error) {
    if (sequence === session.request && session.connected) setMessage(session, cleanError(error), "error");
    return false;
  }
}

// A search that stops early, cannot read a folder, or skips a build directory
// has to say so, otherwise an empty result looks like a definite answer.
function describeSearch(result) {
  const count = result.entries.length;
  const scope = result.scope === "name" ? "" : ` by ${result.scope}`;
  const found = count
    ? `Found ${count}${result.truncated ? "+" : ""} match${count === 1 ? "" : "es"}${scope}`
    : `No matches${scope}`;
  const notes = [];
  if (result.timedOut) {
    notes.push(`stopped after about ${result.seconds} seconds`);
    if (result.unexplored) notes.push(`${result.unexplored} folder${result.unexplored === 1 ? "" : "s"} not reached`);
  } else if (count >= result.limit) {
    notes.push(`the first ${result.limit} are shown`);
    if (result.unexplored) notes.push(`${result.unexplored} folder${result.unexplored === 1 ? "" : "s"} not reached`);
  }
  if (result.scanned > 1) notes.push(`searched ${result.scanned} folders`);
  if (result.unreadable) notes.push(`${result.unreadable} could not be read`);
  if (result.rejected) notes.push(`${result.rejected} unusable name${result.rejected === 1 ? "" : "s"} ignored`);
  if (result.excluded.length) notes.push(`skipped ${result.excluded.join(", ")}`);
  return notes.length ? `${found}; ${notes.join(", ")}.` : `${found}.`;
}

// One full turn of the glyph, held long enough to register even when the listing
// comes back instantly, and never cut short while a slow refresh is still running.
async function showRefreshing(work) {
  const button = $("refresh");
  button.classList.remove("refreshing");
  // Force a reflow so a second press restarts the animation rather than ignoring it.
  void button.offsetWidth;
  button.classList.add("refreshing");
  try {
    return await Promise.all([work, new Promise((resolve) => setTimeout(resolve, 600))]).then(([result]) => result);
  } finally {
    button.classList.remove("refreshing");
  }
}

function refreshView(session = connectedSession()) {
  if (!session) return Promise.resolve(false);
  return session.searchMode && session.searchText.trim() ? runSearch(session) : loadDirectory(session, session.cwd);
}

/* ----------------------------------------------------------- the path bar */

// The path is a field rather than a label, and it is a field all the time. It is
// there to be selected and copied out, or typed and pasted over -- the two things
// anyone actually wants from the top of a file browser -- without having to ask for
// an editor first. `↑ Up` is what walks back up the tree.

function renderPath(session) {
  const input = $("path-input");
  // Never overwrite what someone is in the middle of typing. A listing landing while
  // a path is half entered would otherwise take it away mid-keystroke.
  if (document.activeElement === input) return;
  input.value = session.cwd;
}

function selectOnly(session, target) {
  session.selected.clear();
  session.selected.add(target);
  if (session !== active()) return;
  for (const [path, node] of session.rowNodes) {
    const on = session.selected.has(path);
    node.row.classList.toggle("selected", on);
    node.choice.checked = on;
  }
  updateSelectionControls(session);
  session.rowNodes.get(target)?.row.scrollIntoView({ block: "nearest" });
}

// A path that names a file is still worth following: the folder holding it opens and
// the file is selected, which is what someone pasting a path out of a log or an error
// message is usually after.
async function goToPath(session, raw) {
  const entry = pathEntry(raw, session);
  if (entry.error) {
    setMessage(session, entry.error, "error");
    return false;
  }
  try {
    const found = await api.files.resolve(session.id, entry.path);
    if (found.directory) return openDirectory(session, found.path);
    const parent = found.path.slice(0, found.path.lastIndexOf("/")) || "/";
    const opened = await openDirectory(session, parent);
    if (opened) {
      selectOnly(session, found.path);
      setMessage(session, `Opened the folder holding ${found.path.split("/").pop()}.`, "ok");
    }
    return opened;
  } catch (error) {
    setMessage(session, cleanError(error), "error");
    return false;
  }
}

// Only ever reached from Enter, while the field still has focus. A button here would
// not work: pressing one takes the focus off the field first, and the blur that
// follows puts the shown folder back, so what got read would be where you already are
// rather than what you typed.
function submitPath() {
  const session = connectedSession();
  if (!session) return;
  const wanted = $("path-input").value;
  $("path-input").blur();
  // A path that went nowhere -- refused, missing, unreadable -- must not be left
  // standing in the bar as though it were the folder on screen. Putting it back here
  // rather than leaving it to the blur means it happens whether the field had focus
  // or not, and the reason it went nowhere is already on the status line.
  goToPath(session, wanted).then((moved) => { if (!moved) renderPath(session); });
}

$("path-input").onkeydown = (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    submitPath();
    return;
  }
  // Escape puts back the folder actually being shown, the way an address bar does.
  if (event.key === "Escape") {
    event.preventDefault();
    const session = connectedSession();
    if (session) $("path-input").value = session.cwd;
  }
};

// A path typed but never entered must not be left standing in the bar, claiming a
// folder that is not the one on screen. Switching to another application is the
// exception: fetching a path from somewhere else is half the reason to type in here,
// and finding it gone on the way back would defeat it. `document.hasFocus()` is what
// tells the two apart.
$("path-input").onblur = () => {
  const session = connectedSession() || active();
  // Set directly rather than through `renderPath`, which declines to touch a field
  // that still has focus -- true of this one until the browser finishes moving it.
  if (session && document.hasFocus()) $("path-input").value = session.cwd;
};

/* --------------------------------------------------- copy as path, on a row */

let closeRowMenu = null;

function hideRowMenu() {
  if (closeRowMenu) closeRowMenu();
}

// Right-clicking one of a group of selected rows acts on the group, and right-
// clicking outside the selection acts on that row alone -- the same rule dragging a
// row out to the desktop already follows.
function rowMenuItems(session, item) {
  const items = session.selected.has(item.path) ? selectedItems(session) : [item];
  return [
    [items.length === 1 ? "Copy as path" : `Copy ${items.length} paths`, async () => {
      // The clipboard has a ceiling, and a selection of a few thousand can reach it.
      // Whole paths are dropped off the end rather than one being cut in half, and
      // how many made it is said out loud -- a path that is half a path is worse
      // than a path that is not there, because it looks like one.
      const lines = items.map((entry) => pathForClipboard(entry.path));
      const fitted = [];
      let length = 0;
      for (const line of lines) {
        const cost = length ? line.length + 1 : line.length;
        if (length + cost > workbench.clipboardLimit) break;
        fitted.push(line);
        length += cost;
      }
      const left = lines.length - fitted.length;
      try {
        if (!fitted.length) throw new Error("That path is too long for the clipboard.");
        await api.clipboard.write(fitted.join("\n"));
        if (left) {
          setMessage(session, `Copied ${fitted.length} of ${lines.length} paths; the clipboard would not hold the rest.`, "error");
        } else {
          setMessage(session, fitted.length === 1 ? `Copied ${fitted[0]}` : `Copied ${fitted.length} paths.`, "ok");
        }
      } catch (error) { setMessage(session, cleanError(error), "error"); }
    }],
  ];
}

function showRowMenu(event, session, item) {
  hideRowMenu();
  const menu = $("row-menu");
  menu.replaceChildren();
  for (const [label, run] of rowMenuItems(session, item)) {
    const button = document.createElement("button");
    button.type = "button";
    button.setAttribute("role", "menuitem");
    button.textContent = label;
    button.onclick = () => { hideRowMenu(); run(); };
    menu.append(button);
  }
  menu.classList.remove("hidden");
  // Placed after it is measurable, so a menu opened near an edge comes back inside
  // the window rather than off it.
  const box = menu.getBoundingClientRect();
  const left = Math.min(event.clientX, Math.max(0, innerWidth - box.width - 4));
  const top = Math.min(event.clientY, Math.max(0, innerHeight - box.height - 4));
  menu.style.left = `${left}px`;
  menu.style.top = `${top}px`;
  menu.querySelector("button")?.focus();

  const dismiss = (dismissEvent) => {
    if (dismissEvent.type === "keydown" && dismissEvent.key !== "Escape") return;
    if (dismissEvent.type === "mousedown" && menu.contains(dismissEvent.target)) return;
    hideRowMenu();
  };
  addEventListener("mousedown", dismiss, true);
  addEventListener("keydown", dismiss, true);
  addEventListener("blur", hideRowMenu);
  // Scrolling the listing would leave it pointing at whatever row slid underneath.
  $("file-scroll").addEventListener("scroll", hideRowMenu, { once: true });
  closeRowMenu = () => {
    closeRowMenu = null;
    removeEventListener("mousedown", dismiss, true);
    removeEventListener("keydown", dismiss, true);
    removeEventListener("blur", hideRowMenu);
    $("file-scroll").removeEventListener("scroll", hideRowMenu);
    menu.classList.add("hidden");
    menu.replaceChildren();
  };
}

function sortRows(session) {
  const key = session.sortKey;
  session.rows.sort((a, b) => {
    if (key === "name" && a.directory !== b.directory) return a.directory ? -1 : 1;
    const left = key === "name" ? a.name.toLocaleLowerCase() : a[key];
    const right = key === "name" ? b.name.toLocaleLowerCase() : b[key];
    return (left < right ? -1 : left > right ? 1 : 0) * session.sortDirection;
  });
}

function renderRows(session) {
  // The row menu is anchored to a row and holds the paths that row had when it
  // opened. Rebuilding the listing under it -- a refresh, a sort, a new folder --
  // leaves it pointing at whatever slid into that place, so it goes with them.
  hideRowMenu();
  const body = $("file-rows");
  const fragment = document.createDocumentFragment();
  session.rowNodes = new Map();
  for (const item of session.rows) {
    const row = document.createElement("tr");
    const chosen = session.selected.has(item.path);
    row.className = `file-row${item.directory ? " directory" : ""}${chosen ? " selected" : ""}`;
    row.draggable = true;
    row.ondragstart = (event) => startRemoteItemDrag(event, session, row, item);
    row.onclick = (event) => {
      if (event.target.closest("a,input")) return;
      toggleSelection(session, item);
    };
    row.oncontextmenu = (event) => {
      event.preventDefault();
      if (session.connected) showRowMenu(event, session, item);
    };
    const choiceCell = document.createElement("td");
    const choice = document.createElement("input");
    choice.type = "checkbox";
    choice.checked = chosen;
    choice.setAttribute("aria-label", `Select ${item.name}`);
    choice.onchange = () => toggleSelection(session, item);
    choiceCell.append(choice);
    const nameCell = document.createElement("td");
    nameCell.className = "name";
    const wrap = document.createElement("div");
    wrap.className = "name-wrap";
    const icon = document.createElement("span");
    icon.className = "file-icon";
    icon.textContent = item.directory ? "▸" : item.symlink ? "↗" : isImage(item.name) ? "◧" : "·";
    const block = document.createElement("span");
    block.className = "name-block";
    const link = document.createElement("a");
    link.href = "#";
    link.draggable = false;
    link.className = "name-link";
    link.textContent = item.name;
    // A name opens on one click, and what it opens is drawn under the pointer at
    // once, so the second click of a double-click -- the habit from every file
    // manager -- would land on whatever row took this one's place and open that too.
    // A click counting as the second of a pair is not a request of its own.
    link.onclick = (event) => {
      event.preventDefault();
      if (event.detail > 1) return;
      openItem(session, item);
    };
    block.append(link);
    if (item.location !== undefined) {
      const where = document.createElement("span");
      where.className = "where";
      where.textContent = item.location === "." ? "Current folder" : item.location;
      block.append(where);
    }
    wrap.append(icon, block);
    nameCell.append(wrap);
    row.append(
      choiceCell,
      nameCell,
      cell(item.directory ? "" : formatSize(item.size), "size"),
      cell(formatDate(item.modified), "modified"),
      cell(item.mode, "mode"),
    );
    session.rowNodes.set(item.path, { row, choice });
    fragment.append(row);
  }
  body.replaceChildren(fragment);
  updateSelectionControls(session);
}

function cell(text, className) {
  const node = document.createElement("td");
  node.className = className;
  node.textContent = text;
  return node;
}

function toggleSelection(session, item) {
  if (session.selected.has(item.path)) session.selected.delete(item.path);
  else session.selected.add(item.path);
  const node = session.rowNodes.get(item.path);
  if (node) {
    const chosen = session.selected.has(item.path);
    node.row.classList.toggle("selected", chosen);
    node.choice.checked = chosen;
  }
  updateSelectionControls(session);
}

function setAllSelected(session, chosen) {
  session.selected.clear();
  if (chosen) for (const item of session.rows) session.selected.add(item.path);
  for (const [path, node] of session.rowNodes) {
    const on = session.selected.has(path);
    node.row.classList.toggle("selected", on);
    node.choice.checked = on;
  }
  updateSelectionControls(session);
}

function selectedItems(session) {
  return session.rows.filter((item) => session.selected.has(item.path));
}

function updateSelectionControls(session) {
  const count = selectedItems(session).length;
  const online = Boolean(session.connected);
  $("select-all").checked = online && Boolean(session.rows.length) && count === session.rows.length;
  $("select-all").indeterminate = online && count > 0 && count < session.rows.length;
  $("rename").disabled = !online || count !== 1;
  $("download").disabled = !online || count === 0;
  $("delete").disabled = !online || count === 0;
}

async function startRemoteItemDrag(event, session, row, item) {
  event.preventDefault();
  if (!session.connected) return;
  const items = session.selected.has(item.path) ? selectedItems(session) : [item];
  row.classList.add("drag-preparing");
  setMessage(session, `Preparing ${items.length} remote item${items.length === 1 ? "" : "s"} for your desktop; keep holding the drag…`);
  try {
    const result = await api.files.startDrag(session.id, items);
    const retry = result.cached ? "" : " If it did not land, drag again—the prepared copy is cached.";
    setMessage(session, `Dragged ${result.dragged} real item${result.dragged === 1 ? "" : "s"}.${retry}`, "ok");
  } catch (error) {
    setMessage(session, cleanError(error), "error");
  } finally {
    row.classList.remove("drag-preparing");
  }
}

function formatSize(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${unit ? value.toFixed(1) : value} ${units[unit]}`;
}
function formatDate(value) { return value ? new Date(value).toLocaleString() : ""; }
function isImage(name) { return /\.(png|jpe?g|gif|webp|bmp|svg)$/i.test(name); }
function imageType(name) {
  const extension = name.split(".").pop().toLowerCase();
  return ({ png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", bmp: "image/bmp", svg: "image/svg+xml" })[extension] || "application/octet-stream";
}

async function openItem(session, item) {
  if (!session.connected) return;
  let entry = item;
  if (item.symlink) {
    try {
      const resolved = await api.files.resolve(session.id, item.path);
      entry = { ...item, directory: resolved.directory, size: resolved.size };
    } catch (error) {
      setMessage(session, cleanError(error), "error");
      return;
    }
  }
  if (entry.directory) return openDirectory(session, entry.path);
  if (isImage(entry.name)) {
    // An image too large to preview is not one nobody wants: it downloads, the same
    // as a text file too large to edit, rather than ending in an error.
    if (entry.size > PREVIEW_IMAGE_LIMIT) return downloadItems(session, [entry]);
    try {
      const data = await api.files.readBinary(session.id, entry.path);
      const blob = new Blob([data], { type: imageType(entry.name) });
      const url = URL.createObjectURL(blob);
      const image = document.createElement("img");
      image.src = url;
      image.alt = entry.name;
      showModal(entry.name, image, [
        { label: "Download", run: () => downloadItems(session, [entry]) },
        { label: "Close", primary: true, run: closeModal },
      ], () => URL.revokeObjectURL(url));
    } catch (error) { setMessage(session, cleanError(error), "error"); }
    return;
  }
  if (entry.size > EDIT_LIMIT) return downloadItems(session, [entry]);
  try {
    // Refused, with a reason worth reading, for anything that is not a regular file,
    // is too large, or is not UTF-8 text -- a Latin-1 file opened here would have its
    // accented letters replaced on the first save.
    const file = await api.files.read(session.id, entry.path);
    showEditor(session, entry, file);
  } catch (error) { setMessage(session, cleanError(error), "error"); }
}

/* ------------------------------------------------------------------ modals */

// One dialog is shown at a time, and one that wants the screen while another is
// open waits its turn instead of taking that one's place. Most dialogs open because
// someone clicked something, but some arrive on their own -- a queued drop reaching
// its name-clash question, the file pane asking for a sudo password -- and one of
// those replacing whatever was open used to throw away what was in it: the text in
// an editor, or the answer to another upload's question, since a name-clash dialog
// closed unanswered cancels its upload. A waiting dialog is built straight away and
// kept, hidden, behind the one being shown, so whoever opened it can already reach
// into it; `onShow` runs when it actually comes up, which is when it can take focus.
//
// The one exception is a dialog opened by a button of the dialog being shown, such as
// "Change…" in the master password dialog. That is the same dialog moving on to its
// next step, so it takes the place of the first.
const modalPages = [];
const modalPageOf = new WeakMap();
let modalActionOf = null;

function showModal(title, body, actions = [], cleanup = null, { dismiss = null, onShow = null, backdropCloses = true, note = null } = {}) {
  const element = document.createElement("div");
  element.className = "modal-page";
  const page = { element, cleanup, dismiss, onShow, backdropCloses, busy: false };
  modalPageOf.set(element, page);
  const header = document.createElement("header");
  header.className = "modal-header";
  const heading = document.createElement("h2");
  heading.textContent = title;
  const spacer = document.createElement("span");
  spacer.className = "spacer";
  const close = document.createElement("button");
  close.textContent = "×";
  close.title = "Close";
  close.setAttribute("aria-label", "Close");
  close.onclick = () => dismissModal(page);
  header.append(heading, spacer, close);
  const content = document.createElement("div");
  content.className = "modal-body";
  content.append(body);
  const footer = document.createElement("footer");
  footer.className = "modal-footer";
  if (note) footer.append(note);
  for (const action of actions) {
    const button = document.createElement("button");
    button.textContent = action.label;
    if (action.primary) button.className = "primary";
    if (action.danger) button.className = "danger";
    button.onclick = (event) => runModalAction(page, action, event);
    footer.append(button);
  }
  element.append(header, content, footer);

  const replacing = modalActionOf && modalActionOf === modalPages[0] ? modalActionOf : null;
  if (replacing) {
    modalPages.shift();
    replacing.element.remove();
    runModalCleanup(replacing);
  }
  if (modalPages.length && !replacing) {
    element.hidden = true;
    modalPages.push(page);
    $("modal").append(element);
    return element;
  }
  modalPages.unshift(page);
  $("modal").prepend(element);
  showFrontModal();
  return element;
}

// An action that returns a promise holds every button of its dialog until it has
// settled, so a second click or a second Enter -- which the dialogs' fields turn into
// a click -- cannot start the same thing again while the first is still running: a
// folder created twice, a deletion sent twice, a password tried twice.
function runModalAction(page, action, event) {
  if (page.busy) return;
  modalActionOf = page;
  let result;
  try { result = action.run(event); } finally { modalActionOf = null; }
  if (!result || typeof result.then !== "function") return;
  page.busy = true;
  const restore = holdModalButtons(page);
  Promise.resolve(result).catch(() => undefined).then(() => {
    page.busy = false;
    restore();
  });
}

// Disables a dialog's buttons and returns what puts them back as they were, so two
// holds that overlap undo in the order they were made.
function holdModalButtons(page) {
  const buttons = Array.from(page.element.querySelectorAll(".modal-header button, .modal-footer button"));
  const before = buttons.map((button) => button.disabled);
  for (const button of buttons) button.disabled = true;
  return () => buttons.forEach((button, index) => { button.disabled = before[index]; });
}

function runModalCleanup(page) {
  const cleanup = page.cleanup;
  page.cleanup = null;
  if (cleanup) cleanup();
}

function showFrontModal() {
  const page = modalPages[0];
  if (!page) {
    $("modal-backdrop").classList.add("hidden");
    active()?.terminal?.focus();
    return;
  }
  page.element.hidden = false;
  $("modal-backdrop").classList.remove("hidden");
  if (page.onShow) page.onShow(page.element);
}

// Closes one dialog: the one whose element is given, or else the one being shown --
// which is what a button wired straight to `closeModal` means, since it receives the
// click event. A dialog that has already gone is left gone, so work finishing late
// cannot close whichever dialog has come up since.
function closeModal(which) {
  const page = which instanceof Element ? modalPageOf.get(which) : modalPages[0];
  const index = page ? modalPages.indexOf(page) : -1;
  if (index < 0) return;
  modalPages.splice(index, 1);
  page.element.remove();
  runModalCleanup(page);
  if (index === 0) showFrontModal();
}

// Escape, the × in the corner, and a click on the dimmed area. A dialog can ask to
// decide this for itself, as the editor does; otherwise it closes, unless it is busy.
function dismissModal(page = modalPages[0]) {
  if (!page) return;
  if (page.dismiss) {
    page.dismiss();
    return;
  }
  if (page.busy) return;
  closeModal(page.element);
}

// A click whose `detail` is above one is the second half of a double-click that
// opened the dialog -- on a file name, say -- and not a request to close it.
$("modal-backdrop").onclick = (event) => {
  if (event.target !== $("modal-backdrop") || event.detail > 1) return;
  const page = modalPages[0];
  if (page && page.backdropCloses) dismissModal(page);
};

// The text editor. What is typed into it is the one thing a dialog holds that cannot
// be had back, so it never closes on a stray click on the dimmed area, and Escape, ×
// and Close ask first when there is an edit to lose.
//
// What was read is kept beside the text: the line endings the file had, because a
// textarea only ever holds LF and they are put back on save; and the size and time
// the file had, so a save can tell when the file has been changed on the host since
// -- by a deploy, or in the terminal beside it -- and ask instead of replacing that.
function showEditor(session, item, file) {
  const body = document.createElement("div");
  body.className = "editor";
  const notice = document.createElement("div");
  notice.className = "editor-notice hidden";
  notice.setAttribute("role", "alert");
  const textarea = document.createElement("textarea");
  textarea.spellcheck = false;
  body.append(notice, textarea);
  const note = document.createElement("span");
  note.className = "modal-note";

  const state = { saved: "", eol: "\n", stamp: null, error: "", saving: false };
  let question = null;
  let page = null;
  const dirty = () => textarea.value !== state.saved;
  const sync = () => {
    const parts = [];
    if (state.eol === "\r\n") parts.push("CRLF line endings, kept on save");
    if (dirty()) parts.push("Unsaved changes");
    note.textContent = state.error || parts.join(" · ");
    note.classList.toggle("status-error", Boolean(state.error));
  };
  const load = (loaded) => {
    textarea.value = String(loaded?.text ?? "");
    // Read back rather than taken from what was loaded: a textarea makes changes of
    // its own -- a lone CR becomes LF -- and comparing against those is what keeps
    // an untouched file from counting as edited.
    state.saved = textarea.value;
    state.eol = loaded?.eol === "\r\n" ? "\r\n" : "\n";
    state.stamp = loaded?.stamp || null;
    state.error = "";
    sync();
  };
  const fail = (error) => {
    state.error = cleanError(error);
    sync();
  };
  textarea.addEventListener("input", () => {
    state.error = "";
    sync();
  });

  // A question asked inside the editor rather than in a dialog over it, which would
  // have to take the editor's place. Resolves to the value of the button chosen, or
  // to the cancelling one's on Escape. The editor's own buttons wait meanwhile.
  const ask = (text, choices) => new Promise((resolve) => {
    const restore = holdModalButtons(modalPageOf.get(page));
    const message = document.createElement("span");
    message.textContent = text;
    notice.replaceChildren(message);
    const cancel = choices.find((choice) => choice.cancel);
    const answer = (value) => {
      question = null;
      notice.classList.add("hidden");
      notice.replaceChildren();
      restore();
      resolve(value);
    };
    for (const choice of choices) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = choice.label;
      if (choice.danger) button.className = "danger";
      button.onclick = () => answer(choice.value);
      notice.append(button);
    }
    question = { cancel: () => answer(cancel?.value) };
    notice.classList.remove("hidden");
    notice.querySelectorAll("button")[choices.indexOf(cancel)]?.focus();
  });

  const requestClose = async () => {
    if (dirty()) {
      const discard = await ask(`Discard the changes to ${item.name}?`, [
        { label: "Keep editing", value: false, cancel: true },
        { label: "Discard changes", value: true, danger: true },
      ]);
      if (!discard) {
        textarea.focus();
        return;
      }
    }
    closeModal(page);
  };

  const reload = async () => {
    try {
      load(await api.files.read(session.id, item.path));
      note.textContent = `Reloaded ${item.name} from the host.`;
    } catch (error) { fail(error); }
    textarea.focus();
  };

  const save = async (expect = state.stamp) => {
    const text = textarea.value;
    let result;
    state.saving = true;
    textarea.readOnly = true;
    try {
      result = await api.files.write(session.id, item.path, text, { eol: state.eol, expect: expect || undefined });
    } catch (error) {
      fail(error);
      return;
    } finally {
      state.saving = false;
      textarea.readOnly = false;
    }
    if (result && result.ok === false && result.changed) {
      const choice = await ask(`${item.name} has been changed on the host since it was opened here. Saving now would replace that change.`, [
        { label: "Cancel", value: "cancel", cancel: true },
        { label: "Reload", value: "reload" },
        { label: "Overwrite", value: "overwrite", danger: true },
      ]);
      // Overwriting is checked against what is there now, so a third change made
      // while this was being asked is still caught rather than replaced unseen.
      if (choice === "overwrite") return save(result.stamp);
      if (choice === "reload") return reload();
      textarea.focus();
      return;
    }
    state.stamp = result?.stamp || null;
    state.saved = text;
    closeModal(page);
    // After the listing, which says "Ready" when it lands and would otherwise take
    // the confirmation away as soon as it appeared.
    await refreshView(session);
    setMessage(session, `Saved ${item.name}`, "ok");
  };

  page = showModal(item.name, body, [
    { label: "Download", run: () => downloadItems(session, [item]) },
    { label: "Close", run: requestClose },
    { label: "Save", primary: true, run: () => save() },
  ], null, {
    note,
    backdropCloses: false,
    onShow: () => textarea.focus(),
    dismiss: () => {
      if (question) question.cancel();
      else if (!state.saving) requestClose();
    },
  });
  load(file);
}

function promptModal(session, title, initial, confirmLabel, callback) {
  const input = document.createElement("input");
  input.value = initial;
  let page = null;
  page = showModal(title, input, [
    { label: "Cancel", run: () => closeModal(page) },
    { label: confirmLabel, primary: true, run: async () => {
      try {
        await callback(input.value);
        closeModal(page);
        await refreshView(session);
      } catch (error) { setMessage(session, cleanError(error), "error"); }
    } },
  ], null, { onShow: () => { input.focus(); input.select(); } });
  // Enter clicks the button rather than calling the action itself, so a second Enter
  // meets the button held while the first one runs.
  const confirm = page.querySelector(".modal-footer button:last-child");
  input.onkeydown = (event) => {
    if (event.key === "Enter") { event.preventDefault(); confirm.click(); }
  };
}

/* --------------------------------------------- upload name collisions */

const CONFLICT_OPTIONS = {
  file: [
    ["overwrite", "Overwrite"],
    ["keep-both", "Keep both"],
    ["skip", "Skip"],
  ],
  folder: [
    ["overwrite", "Merge, replacing files that clash"],
    ["keep-both", "Upload as a separate copy"],
    ["skip", "Skip"],
  ],
  // A file cannot replace a folder, or a folder a file, so overwriting is not on
  // offer: the only answers left are to leave it alone or to land beside it.
  mismatch: [
    ["keep-both", "Keep both"],
    ["skip", "Skip"],
  ],
  // Nothing is on the host yet; the clash is between two of the dropped items. The
  // answers are the same three, but what they do is worth saying in those terms:
  // whichever is written first is what a later copy then lands on.
  // Keeping both leads, unlike the other kinds: someone who dragged two files in has
  // both of them in mind, and replacing one with the other loses something they chose
  // rather than something that was already on the host.
  duplicate: [
    ["keep-both", "Keep both, numbered"],
    ["overwrite", "Keep the last one"],
    ["skip", "Keep the first one"],
  ],
};

// A kind clash comes first, because it is the one that rules an answer out. It can
// be with what is on the host or between two of the dropped items, and either way
// overwriting is not among the things that can happen.
function conflictKind(collision) {
  if (collision.mismatch) return "mismatch";
  if (!collision.remote) return "duplicate";
  return collision.directory ? "folder" : "file";
}

function describeSide(label, info, directory) {
  const parts = [directory ? "folder" : formatSize(info.size)];
  if (info.symlink) parts.push("shortcut");
  if (info.modified) parts.push(formatDate(info.modified));
  return `${label} ${parts.join(" · ")}`;
}

// Asked before a single byte is sent, because the answer decides where the bytes go.
// Resolves to a name→choice map, or to null when nothing should be uploaded: a dialog
// closed unanswered is a refusal, not consent to replace what is already there.
function askUploadConflicts(plan) {
  return new Promise((resolve) => {
    let settled = false;
    const settle = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const choices = new Map();
    const selects = [];
    const total = plan.collisions.length;

    const body = document.createElement("div");
    body.className = "conflict-view";
    const onHost = plan.collisions.filter((item) => item.remote).length;
    const between = total - onHost;
    const said = [];
    if (onHost) said.push(`${onHost} name${onHost === 1 ? "" : "s"} already in ${plan.directory}`);
    if (between) said.push(`${between} name${between === 1 ? "" : "s"} used by more than one dropped item`);
    const intro = document.createElement("p");
    intro.textContent = `${said.join(", and ")}. Nothing has been sent yet.`;
    body.append(intro);

    if (total > 1) {
      const row = document.createElement("label");
      row.className = "conflict-all";
      const caption = document.createElement("span");
      caption.textContent = "Apply to all";
      const select = document.createElement("select");
      // Only answers every row can actually take. An answer no row accepts would do
      // nothing at all when it was chosen, which is the same broken promise as
      // offering to overwrite something that cannot be overwritten -- a whole column
      // of rows refusing it in silence rather than one.
      //
      // The wording comes from what the rows are about: a list that is entirely
      // clashes between dropped items has nothing on the host to overwrite, and
      // "Overwrite" above a column of "Keep the last one" reads as a different
      // question from the one it settles.
      const spoken = onHost ? CONFLICT_OPTIONS.file : CONFLICT_OPTIONS.duplicate;
      const everyRowTakes = (value) => plan.collisions
        .every((item) => CONFLICT_OPTIONS[conflictKind(item)].some(([choice]) => choice === value));
      const shared = spoken.filter(([value]) => everyRowTakes(value));
      for (const [value, label] of [["", "Choose…"], ...shared]) {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = label;
        select.append(option);
      }
      select.onchange = () => {
        const wanted = select.value;
        if (!wanted) return;
        for (const item of selects) {
          // A row that cannot take this answer keeps the one it has, rather than
          // being forced into a choice its kind does not allow.
          if (!Array.from(item.select.options).some((option) => option.value === wanted)) continue;
          item.select.value = wanted;
          choices.set(item.name, wanted);
        }
        sync();
      };
      row.append(caption, select);
      body.append(row);
    }

    const list = document.createElement("div");
    list.className = "conflict-list";
    for (const collision of plan.collisions) {
      const kind = conflictKind(collision);
      const options = CONFLICT_OPTIONS[kind];
      choices.set(collision.name, options[0][0]);

      const row = document.createElement("div");
      row.className = "conflict-row";
      const icon = document.createElement("span");
      icon.className = "file-icon";
      icon.textContent = collision.directory ? "▸" : "·";
      const block = document.createElement("div");
      block.className = "conflict-block";
      const name = document.createElement("span");
      name.className = "conflict-name";
      name.textContent = collision.name;
      const detail = document.createElement("span");
      detail.className = "conflict-detail";
      detail.textContent = collision.remote
        ? [
          describeSide("On the host:", collision.remote, collision.remote.directory),
          describeSide("Being uploaded:", collision.local, collision.directory),
        ].join(" — ")
        : `${collision.duplicates} of the dropped items are named this — nothing on the host has this name.`;
      block.append(name, detail);
      const say = (text) => {
        const note = document.createElement("span");
        note.className = "conflict-note";
        note.textContent = text;
        block.append(note);
      };
      if (collision.mixed) {
        say(`${collision.duplicates} of the dropped items are named this, and they are not all the same kind — one is a folder and one is a file, so neither can replace the other.`);
      } else if (kind === "mismatch") {
        say(collision.directory
          ? "A folder cannot replace a file of the same name."
          : "A file cannot replace a folder of the same name.");
      } else if (collision.duplicates && collision.remote) {
        say(`${collision.duplicates} of the dropped items are also named this; the answer covers each of them.`);
      }
      const select = document.createElement("select");
      for (const [value, label] of options) {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = label;
        select.append(option);
      }
      select.onchange = () => {
        choices.set(collision.name, select.value);
        sync();
      };
      selects.push({ name: collision.name, select });
      row.append(icon, block, select);
      list.append(row);
    }
    body.append(list);

    const tally = document.createElement("p");
    tally.className = "conflict-tally";
    body.append(tally);

    // Nothing is "already taken" when the clash is only between two dropped items.
    const heading = onHost ? "Some names are already taken" : "Some names are used more than once";
    // It may have to wait behind another dialog -- an editor, say -- and only takes
    // focus when it comes up.
    const modal = showModal(heading, body, [
      { label: "Cancel", run: () => closeModal(modal) },
      { label: "Upload", primary: true, run: () => {
        settle(Object.fromEntries(choices));
        closeModal(modal);
      } },
    ], () => settle(null), { onShow: (element) => element.querySelector(".modal-footer button:last-child").focus() });

    // The confirm button carries the weight of the choices behind it, so it reads as
    // a destructive action exactly when one of them is.
    const confirm = modal.querySelector(".modal-footer button:last-child");
    const byName = new Map(plan.collisions.map((item) => [item.name, item]));
    function sync() {
      // "Overwrite" means two different things depending on what the name clashes
      // with, and the tally is the one line that reads them all together, so it has
      // to keep them apart: something on the host is replaced, whereas two dropped
      // items sharing a name means only the last of them is kept.
      const counts = { replaced: 0, lastOnly: 0, "keep-both": 0, skip: 0 };
      for (const [name, choice] of choices) {
        if (choice !== "overwrite") counts[choice] += 1;
        else if (byName.get(name)?.remote) counts.replaced += 1;
        else counts.lastOnly += 1;
      }
      const spoken = [];
      if (counts.replaced) spoken.push(`${counts.replaced} replaced`);
      if (counts.lastOnly) spoken.push(`${counts.lastOnly} where only the last copy is kept`);
      if (counts["keep-both"]) spoken.push(`${counts["keep-both"]} kept alongside`);
      if (counts.skip) spoken.push(`${counts.skip} skipped`);
      tally.textContent = spoken.length ? `On upload: ${spoken.join(", ")}.` : "";
      // Either one loses something that was chosen, which is what the button says.
      confirm.classList.toggle("danger", counts.replaced > 0 || counts.lastOnly > 0);
    }
    sync();
  });
}

function baseName(remote) {
  return String(remote).split("/").pop();
}

// One line for the status bar covering all four outcomes, because "Uploaded 3 items"
// on its own would hide the two that were skipped.
function uploadSummary(report, target) {
  if (report.canceled) return "Nothing was uploaded; the upload was cancelled.";
  const extra = [];
  if (report.renamed.length === 1) {
    extra.push(`Kept both copies of ${baseName(report.renamed[0].from)}, as ${baseName(report.renamed[0].to)}.`);
  } else if (report.renamed.length) {
    extra.push(`Kept both copies of ${report.renamed.length} items.`);
  }
  if (report.skipped.length === 1) extra.push(`Skipped ${baseName(report.skipped[0])}.`);
  else if (report.skipped.length) extra.push(`Skipped ${report.skipped.length} items.`);
  if (!report.uploaded.length) {
    return [`Nothing was uploaded into ${target}.`, ...extra].join(" ");
  }
  const count = report.uploaded.length;
  return [`Uploaded ${count} item${count === 1 ? "" : "s"} into ${target}.`, ...extra].join(" ");
}

async function downloadItems(session, items = selectedItems(session)) {
  if (!items.length) return;
  try {
    const saved = await api.files.download(session.id, items);
    if (saved.length) setMessage(session, `Downloaded ${saved.length} item${saved.length === 1 ? "" : "s"}.`, "ok");
  } catch (error) {
    setMessage(session, cleanError(error), "error");
  }
}

/* ------------------------------------------------------------ pane actions */

function withSession(run) {
  return (...args) => {
    const session = connectedSession();
    if (!session) return undefined;
    return run(session, ...args);
  };
}

$("home").onclick = withSession((session) => openDirectory(session, session.home));
$("refresh").onclick = withSession((session) => showRefreshing(refreshView(session)));
$("up").onclick = withSession((session) => { if (session.parent) openDirectory(session, session.parent); });
$("search").oninput = withSession((session) => {
  session.searchText = $("search").value;
  $("clear-search").disabled = !session.searchText.trim();
  session.searchTimer = clearTimeout(session.searchTimer);
  session.searchTimer = setTimeout(() => runSearch(session), 300);
});
$("search").onkeydown = withSession((session, event) => {
  if (event.key === "Enter") { event.preventDefault(); session.searchText = $("search").value; runSearch(session); }
  if (event.key === "Escape") openDirectory(session, session.cwd);
});
$("clear-search").onclick = withSession((session) => {
  openDirectory(session, session.cwd);
  $("search").focus();
});
$("search-scope").onchange = withSession((session) => {
  session.searchScope = $("search-scope").value;
  localStorage.setItem("searchScope", session.searchScope);
  if (session.searchText.trim()) runSearch(session);
});
$("select-all").onchange = withSession((session, event) => setAllSelected(session, event.target.checked));
document.querySelectorAll("th[data-sort]").forEach((heading) => {
  heading.onclick = withSession((session) => {
    const key = heading.dataset.sort;
    session.sortDirection = key === session.sortKey ? -session.sortDirection : 1;
    session.sortKey = key;
    sortRows(session);
    renderRows(session);
  });
});
$("new-folder").onclick = withSession((session) =>
  promptModal(session, "New remote folder", "", "Create", (name) => api.files.mkdir(session.id, session.cwd, name)));
$("rename").onclick = withSession((session) => {
  const item = selectedItems(session)[0];
  if (item) {
    promptModal(session, "Rename remote item", item.name, "Rename", (name) =>
      api.files.rename(session.id, item.path, name));
  }
});
$("download").onclick = withSession((session) => downloadItems(session));
$("delete").onclick = withSession((session) => {
  const items = selectedItems(session);
  if (!items.length) return;
  const body = document.createElement("p");
  body.textContent = `Permanently delete ${items.length} selected item${items.length === 1 ? "" : "s"} from ${session.label}?`;
  const page = showModal("Confirm remote deletion", body, [
    { label: "Cancel", run: () => closeModal(page) },
    { label: "Delete", danger: true, run: async () => {
      try {
        const result = await api.files.delete(session.id, items.map((item) => item.path));
        closeModal(page);
        await refreshView(session);
        setMessage(session, `Deleted ${result.deleted}; ${result.failures.length} failed.`,
          result.failures.length ? "error" : "ok");
      } catch (error) {
        closeModal(page);
        setMessage(session, cleanError(error), "error");
      }
    } },
  ]);
});
$("upload-files").onclick = withSession(async (session) => {
  const target = session.cwd;
  try {
    const report = await api.files.uploadFiles(session.id, target, askUploadConflicts);
    if (report.canceled === "choice") return;
    await refreshView(session);
    setMessage(session, uploadSummary(report, target), report.canceled ? "" : "ok");
  } catch (error) { setMessage(session, cleanError(error), "error"); }
});
$("upload-folder").onclick = withSession(async (session) => {
  const target = session.cwd;
  try {
    const report = await api.files.uploadFolder(session.id, target, askUploadConflicts);
    if (report.canceled === "choice") return;
    await refreshView(session);
    setMessage(session, uploadSummary(report, target), report.canceled ? "" : "ok");
  } catch (error) { setMessage(session, cleanError(error), "error"); }
});

/* ------------------------------------------------------- inbound drag-drop */

let dropDepth = 0;
let dropsInFlight = 0;
function containsLocalFiles(event) {
  const transfer = event.dataTransfer;
  if (!transfer) return false;
  if (Array.from(transfer.types || []).includes("Files")) return true;
  return Array.from(transfer.items || []).some((item) => item.kind === "file");
}
$("files-pane").addEventListener("dragenter", (event) => {
  if (!containsLocalFiles(event)) return;
  event.preventDefault();
  dropDepth += 1;
  $("files-pane").classList.add("drop-target");
});
$("files-pane").addEventListener("dragover", (event) => {
  if (!containsLocalFiles(event)) return;
  event.preventDefault();
  event.dataTransfer.dropEffect = "copy";
});
$("files-pane").addEventListener("dragleave", (event) => {
  if (!containsLocalFiles(event)) return;
  dropDepth = Math.max(0, dropDepth - 1);
  if (!dropDepth) $("files-pane").classList.remove("drop-target");
});
$("files-pane").addEventListener("drop", async (event) => {
  if (!containsLocalFiles(event)) return;
  event.preventDefault();
  event.stopPropagation();
  dropDepth = 0;
  $("files-pane").classList.remove("drop-target");
  const session = connectedSession();
  if (!session) return;
  const count = event.dataTransfer.files.length;
  const target = session.cwd;
  // The upload has to be started from inside this event, before the drop data is
  // released. Queued drops wait their turn inside the preload bridge.
  const upload = api.files.uploadDropped(session.id, target, askUploadConflicts);
  dropsInFlight += 1;
  const queued = dropsInFlight > 1 ? ` (${dropsInFlight} drops queued)` : "";
  setMessage(session, `Uploading ${count} dropped item${count === 1 ? "" : "s"} into ${target}…${queued}`);
  try {
    const report = await upload;
    await refreshView(session);
    setMessage(session, uploadSummary(report, target), report.canceled ? "" : "ok");
  } catch (error) {
    setMessage(session, cleanError(error), "error");
  } finally {
    dropsInFlight -= 1;
  }
});
// Pasting into the remote folder: a screenshot arrives as bytes with no filename,
// files copied in a file manager arrive as local paths.
async function pasteIntoFolder(session, { announceEmpty = true } = {}) {
  const target = session.cwd;
  try {
    const result = await api.files.pasteClipboard(session.id, target, askUploadConflicts);
    if (result.kind === "empty") {
      // The paste event carried nothing usable; the system clipboard may still
      // hold an image that this application can read directly.
      if (await pasteClipboardImage(session)) return true;
      if (announceEmpty) setMessage(session, "The clipboard holds nothing that can be pasted into a folder.", "error");
      return false;
    }
    await refreshView(session);
    if (result.kind === "image") {
      const more = result.extra > 0 ? ` The other ${result.extra} clipboard image${result.extra === 1 ? " was" : "s were"} ignored.` : "";
      setMessage(session, `Pasted ${result.name} (${formatSize(result.bytes)}) into ${target}.${more}`, "ok");
    } else {
      setMessage(session, uploadSummary(result, target), result.canceled ? "" : "ok");
    }
    return true;
  } catch (error) {
    setMessage(session, cleanError(error), "error");
    return false;
  }
}

// Routed by what is on the clipboard, not by what has focus. Text is ambiguous —
// the shell wants it — but an image or a file has only one possible destination,
// so it goes to the remote folder from wherever it was pasted. Capture phase, so
// this decision is made before the terminal handles the event.
addEventListener("paste", (event) => {
  if (!$("modal-backdrop").classList.contains("hidden")) return;
  const session = connectedSession();
  if (!session) return;
  const files = event.clipboardData && event.clipboardData.files;
  if (!files || !files.length) return;
  if (isTextField(event.target)) return;
  event.preventDefault();
  event.stopPropagation();
  pasteIntoFolder(session);
}, true);

document.addEventListener("dragover", (event) => {
  if (containsLocalFiles(event)) event.preventDefault();
});
document.addEventListener("drop", (event) => {
  if (containsLocalFiles(event)) event.preventDefault();
});

/* ---------------------------------------------------------------- terminal */

$("restart-terminal").onclick = withSession(async (session) => {
  session.terminal.reset();
  try {
    await api.terminal.start(session.id, { columns: session.terminal.cols, rows: session.terminal.rows });
    session.terminal.focus();
  } catch (error) { setMessage(session, cleanError(error), "error"); }
});
const HELP_SECTIONS = [
  ["Terminal · selecting and copying", [
    ["Drag", "Select text. Nothing is copied yet."],
    ["Shift+drag", "Select and copy immediately. Shift also forces a local selection while a remote program such as Claude Code, vim, tmux, or less is using the mouse, even when pressed after the drag has started."],
    ["Double-click", "Select a word."],
    ["Triple-click", "Select a whole line."],
    ["Enter", "Copy and clear a selection made with the mouse, as the Windows console does. With no such selection it is an ordinary Enter."],
    ["Right-click", "Copy the selection; paste when nothing is selected."],
    ["Ctrl+C", "Copy the selection with its common leading indentation removed, so pasted commands run. Sends SIGINT when nothing is selected."],
    ["Ctrl+Shift+C", "Copy the selection exactly, indentation included."],
    ["Ctrl+Insert", "Copy the selection with its common leading indentation removed, as Ctrl+C does."],
    ["Alt+drag", "Select a rectangle of columns rather than whole lines. Copying it removes the indentation its lines share, as with any other selection."],
  ]],
  ["Terminal · pasting and scrolling", [
    ["Ctrl+V", "Paste clipboard text. An image or copied file goes to the remote folder instead. Every paste has control characters such as Escape taken out first, so pasted text cannot act as keystrokes; tabs and line breaks are kept."],
    ["Ctrl+Shift+V", "Paste clipboard text."],
    ["Shift+Insert", "Paste clipboard text."],
    ["Wheel", "Scroll the scrollback; 10000 lines are kept per session."],
    ["⟳ Restart", "Start a fresh remote shell in this session without reconnecting."],
  ]],
  ["Sessions and tabs", [
    ["Enter", "Connect, from anywhere on the connection form. With a saved connection chosen in the list, it opens that one."],
    ["Connect (saved connections)", "Connect to the highlighted saved connection at once. A double-click in the list does the same."],
    ["Ctrl+Shift+T", "New session in its own tab."],
    ["Ctrl+Shift+N", "New window, with its own tabs. Launching the application again does the same."],
    ["Ctrl+Shift+W", "Close the current session."],
    ["Ctrl+Shift+L", "Lock the saved credentials, when a master password is set."],
    ["Ctrl+PageUp / Ctrl+PageDown", "Previous / next session."],
    ["Alt+1…9", "Jump straight to that tab."],
    ["Green / red dot", "The session is live / the far end went away. Reconnect reopens the same tab."],
    ["Disconnect", "Close the active session. Closing the last one returns to the connection screen."],
  ]],
  ["Searching remote names and paths", [
    ["report", "Matches any name containing “report”."],
    ["logs/report", "A query with a slash matches the path below the searched folder, so folder names count too."],
    ["/var/log/rep", "A query starting with a slash matches the whole remote path."],
    ["*.log", "“*” and “?” make the query a wildcard pattern that must match the whole name; “*” spans folders."],
    ["Subfolders / Current folder", "Search the tree below this folder, or only this folder."],
    ["Coverage", "The search reads folders nearest first and stops after about 4 seconds or 500 matches. The status line reports how many folders were searched, how many were unreachable, and which build folders were skipped."],
    ["Skipped folders", ".git, .cache, .venv, venv, node_modules, and __pycache__ are never entered. Links to folders are not followed."],
  ]],
  ["Remote files", [
    ["Ctrl+F", "Focus the search box. Choose Subfolders or Current folder beside it."],
    ["F5", "Refresh the listing, or re-run the current search."],
    ["Click a name", "Open a folder, edit a text file, or preview an image. A text file over 2 MB or an image over 20 MB downloads instead. A file that is not UTF-8 text is refused by the editor; download it instead."],
    ["The editor", "Escape, × and Close ask before discarding an edit, and a click outside does nothing. Save keeps CRLF line endings, and asks — overwrite, reload, or cancel — when the file was changed on the host after it was opened."],
    ["Click a row", "Select it. Column headings sort; click again to reverse."],
    ["Delete", "Delete the selected remote items after confirmation."],
    ["F2", "Rename the single selected item."],
    ["Escape", "Clear the search box, close the open dialog (the editor asks first if there are unsaved edits), or put the shown folder back in the path box."],
  ]],
  ["Paths in and out", [
    ["The path box", "Always a text field holding the folder shown. Select it to copy the path out, or type or paste a path over it and press Enter to go there."],
    ["Ctrl+L", "Focus the path box and select all of it, ready to copy or to type over. The terminal keeps Ctrl+L for clearing the screen."],
    ["Escape", "Put the folder actually being shown back in the box."],
    ["Right-click a row", "Copy as path: the full remote path of that item, or of the whole selection one per line. A path needing it is quoted for a shell."],
    ["~ and relative paths", "“~” is your home folder on the host, and a path with no leading slash is read from the folder shown."],
  ]],
  ["Getting files in and out", [
    ["Drag a row out", "Download that item, or the whole selection, to the desktop as real files. Keep holding the first drag while it is prepared."],
    ["Drop files in", "Upload into the folder shown in the active tab. Folders upload recursively; further drops queue behind the first. A name already in that folder is put to you first — overwrite, keep both, or skip — and nothing is sent until you answer."],
    ["Ctrl+V", "Paste the clipboard into this folder from anywhere in the window: a screenshot is saved as pasted-<date>.png, and files copied in Explorer are uploaded. Clipboard text still goes to the terminal, since only text is ambiguous."],
    ["Upload files / Upload folder", "Pick local items with a dialog instead."],
  ]],
];

$("terminal-help").onclick = () => {
  // One grid for every section so the key column lines up throughout.
  const help = document.createElement("div");
  help.className = "help-grid";
  for (const [title, rows] of HELP_SECTIONS) {
    const heading = document.createElement("h3");
    heading.className = "help-heading";
    heading.textContent = title;
    help.append(heading);
    for (const [key, value] of rows) {
      const code = document.createElement("code");
      code.textContent = key;
      const text = document.createElement("span");
      text.textContent = value;
      help.append(code, text);
    }
  }
  showModal(`Keyboard and mouse reference${workbench.version ? ` — SSH Workbench ${workbench.version}` : ""}`,
    help, [{ label: "Close", primary: true, run: closeModal }]);
};

function fitTerminal() {
  const session = active();
  if (!session || !session.opened || $("workspace").classList.contains("hidden")) return;
  try { session.fit.fit(); } catch { /* hidden or zero-sized */ }
}
new ResizeObserver(fitTerminal).observe($("terminals"));

/* ------------------------------------------------------------------ layout */

let dragging = false;
$("gutter").onmousedown = (event) => { dragging = true; $("gutter").classList.add("dragging"); event.preventDefault(); };
addEventListener("mousemove", (event) => {
  if (!dragging) return;
  const bounds = $("split").getBoundingClientRect();
  const percent = Math.max(25, Math.min(75, ((event.clientX - bounds.left) / bounds.width) * 100));
  $("split").style.setProperty("--split", `${percent}%`);
  localStorage.setItem("split", String(percent));
  fitTerminal();
});
addEventListener("mouseup", () => { dragging = false; $("gutter").classList.remove("dragging"); });
const savedSplit = Number(localStorage.getItem("split"));
if (savedSplit >= 25 && savedSplit <= 75) $("split").style.setProperty("--split", `${savedSplit}%`);

/* --------------------------------------------------------------- shortcuts */

function isTypingTarget(target) {
  if (!target || !target.tagName) return false;
  return target.tagName === "INPUT" || target.tagName === "TEXTAREA" ||
    target.tagName === "SELECT" || target.isContentEditable === true;
}

// The terminal is driven through a hidden textarea. It is a typing target for keys,
// but it is not one of the window's own fields, and the two shortcuts that reach
// into a field from anywhere have to be able to tell the difference.
function isTerminalInput(target) {
  return Boolean(target && target.classList && target.classList.contains("xterm-helper-textarea"));
}

// A real text field keeps its own paste; the terminal's hidden textarea does not
// count, or a file could never be pasted while the terminal has focus.
function isTextField(target) {
  return isTypingTarget(target) && !isTerminalInput(target);
}

addEventListener("keydown", (event) => {
  const key = String(event.key || "");
  const lower = key.toLowerCase();
  const control = event.ctrlKey || event.metaKey;
  if (!$("modal-backdrop").classList.contains("hidden")) {
    if (key === "Escape") dismissModal();
    return;
  }
  const inWorkspace = !$("workspace").classList.contains("hidden");
  if (control && event.shiftKey && lower === "t") {
    event.preventDefault();
    $("new-session").click();
    return;
  }
  if (control && event.shiftKey && lower === "n") {
    event.preventDefault();
    openNewWindow();
    return;
  }
  if (control && event.shiftKey && lower === "l" && workbench.vault?.configured) {
    event.preventDefault();
    lockSavedCredentials().then(() => {
      const session = connectedSession();
      if (session) setMessage(session, "Saved credentials locked.", "ok");
      else connectMessage("Saved credentials locked.");
    }).catch(() => undefined);
    return;
  }
  if (inWorkspace) {
    if (control && event.shiftKey && lower === "w") {
      event.preventDefault();
      if (workbench.activeId) closeSession(workbench.activeId);
      return;
    }
    if (control && (key === "PageDown" || key === "PageUp")) {
      event.preventDefault();
      stepSession(key === "PageDown" ? 1 : -1);
      return;
    }
    if (event.altKey && !control && /^[1-9]$/.test(key)) {
      const id = workbench.order[Number(key) - 1];
      if (id) { event.preventDefault(); activate(id); }
      return;
    }
  } else if (key === "Escape" && workbench.order.length) {
    event.preventDefault();
    $("cancel-connect").click();
    return;
  } else if (key === "Enter" && !control && !event.altKey && !event.defaultPrevented) {
    // On the connection screen Enter means connect, wherever the focus happens to be.
    // A select does not submit a form on its own, and a saved connection chosen in the
    // list goes through Quick connect so its credentials are loaded first. A focused
    // button keeps its own behaviour: Enter on Save connection still saves.
    const target = event.target;
    if (target?.tagName === "BUTTON" || target?.tagName === "TEXTAREA") return;
    event.preventDefault();
    if (target === $("saved-profile") && $("saved-profile").value) quickConnect();
    else $("connect-form").requestSubmit();
    return;
  }
  const session = connectedSession();
  if (!session || !inWorkspace) return;
  if (control && lower === "f") { event.preventDefault(); $("search").focus(); $("search").select(); }
  // Ctrl+L reaches the path box from wherever the focus is, the same as Ctrl+F
  // reaches the search box -- including from the other one of the two, which is
  // where wanting it is most likely. The terminal is the exception, and only for
  // Ctrl itself: clearing the screen is what every shell does with Ctrl+L, while
  // Command+L on a Mac means nothing to a shell and should behave like Command+F.
  if (control && !event.shiftKey && lower === "l" && !(event.ctrlKey && isTerminalInput(event.target))) {
    event.preventDefault();
    $("path-input").focus();
    $("path-input").select();
    return;
  }
  if (key === "F5") { event.preventDefault(); showRefreshing(refreshView(session)); }
  if (isTypingTarget(event.target)) return;
  if (key === "Delete" && session.selected.size) { event.preventDefault(); $("delete").click(); }
  if (key === "F2" && session.selected.size === 1) { event.preventDefault(); $("rename").click(); }
});

showConnectView();

"use strict";

const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const path = require("node:path");
const { StringDecoder } = require("node:string_decoder");
const { Client } = require("ssh2");
const { KnownHosts, displayFingerprint, hostIdentity } = require("./known-hosts");
const { localName, remoteJoin, remoteParent, remotePath, safeRemoteName, temporaryName } = require("./remote-path");
const { buildMatcher } = require("./search-match");
const { normalizeProtocol } = require("./protocols");
const { SftpTransport } = require("./sftp-transport");
const { ShellTransport } = require("./shell-transport");
const { openSudoSftp } = require("./sudo-sftp");
const { PROBE_COMMAND, parseProbe, terminalUser } = require("./terminal-user");

const SFTP_OPEN_TIMEOUT = 15000;
// The process table is read 400 ms after the last Enter -- put off by further
// Enters, but never past 3 s from the first -- and once more 2 s after the last
// one, for a root shell that is slow to start (su against LDAP, a long .bashrc).
const FOLLOW_QUICK = 400;
const FOLLOW_LONGEST = 3000;
const FOLLOW_LATE = 2000;
const PROBE_TIMEOUT = 10000;

const SEARCH_LIMIT = 500;
const SEARCH_MILLISECONDS = 4000;
const SEARCH_CONCURRENCY = 12;
const MAX_PRIVATE_KEY_BYTES = 1024 * 1024;
const SEARCH_SKIP = new Set([".git", ".cache", ".venv", "venv", "node_modules", "__pycache__"]);
const UNIQUE_NAME_ATTEMPTS = 50;
const PLAN_CONCURRENCY = 8;
const UPLOAD_CHOICES = new Set(["overwrite", "skip", "keep-both"]);
const EDIT_LIMIT = 2 * 1024 * 1024;
const PREVIEW_LIMIT = 20 * 1024 * 1024;
const LINE_ENDINGS = new Set(["\n", "\r\n"]);
// How many left-out items a download names before it just counts the rest.
const LEFT_OUT_NAMED = 5;

class SshManager extends EventEmitter {
  // `knownHosts` is shared between sessions so that trusting a host in one tab
  // is visible to the others and no tab can overwrite another tab's decision.
  constructor({ knownHosts, knownHostsPath, confirmHost }) {
    super();
    this.knownHosts = knownHosts || new KnownHosts(knownHostsPath);
    this.confirmHost = confirmHost;
    this.client = null;
    this.jumpClient = null;
    this.jumpStream = null;
    this.transport = null;
    this.terminal = null;
    this.connection = null;
    this.closing = false;
    this.#resetFollowing();
  }

  // The file pane follows the user the terminal is working as. `loginTransport` is
  // the session opened at connect time; `transport` is whichever one is in use.
  #loginTransport = null;
  #loginUid = null;
  #browseUid = null;
  #sudoPassword = null;
  #followTimer = null;
  #followLateTimer = null;
  #followSince = 0;
  #following = false;
  #followAgain = false;
  #pendingUid = null;
  #seenUid = null;

  #resetFollowing() {
    if (this.#followTimer) clearTimeout(this.#followTimer);
    if (this.#followLateTimer) clearTimeout(this.#followLateTimer);
    this.#followTimer = null;
    this.#followLateTimer = null;
    this.#loginTransport = null;
    this.#loginUid = null;
    this.#browseUid = null;
    this.#sudoPassword = null;
    this.#followSince = 0;
    this.#following = false;
    this.#followAgain = false;
    this.#pendingUid = null;
    this.#seenUid = null;
  }

  // File operations in progress. Switching the pane between users waits for these
  // to finish: closing the session a download is reading from cuts it off, and an
  // upload that changed user halfway would leave a tree owned by two people.
  #busy = 0;
  #idleWaiters = [];

  #whenIdle() {
    return this.#busy === 0 ? Promise.resolve() : new Promise((resolve) => this.#idleWaiters.push(resolve));
  }

  async #tracked(run) {
    this.#busy += 1;
    try {
      return await run();
    } finally {
      this.#busy -= 1;
      if (this.#busy === 0) for (const resolve of this.#idleWaiters.splice(0)) resolve();
    }
  }

  static {
    for (const name of ["list", "search", "resolve", "readFile", "readBinary", "writeFile", "writePastedImage",
      "mkdir", "rename", "delete", "planUpload", "upload", "download"]) {
      const operation = this.prototype[name];
      this.prototype[name] = function tracked(...args) {
        return this.#tracked(() => operation.apply(this, args));
      };
    }
  }

  get connected() {
    return Boolean(this.client && this.transport);
  }

  // Each connect is numbered. One that has been overtaken -- a second connect begun
  // while this one was still authenticating: Reconnect pressed again, Enter twice --
  // closes what it opened itself instead of installing it. Without this the earlier
  // attempt finishes after the later one's disconnect() has already run, and its
  // connection stays open with nothing holding a reference to it.
  #attempt = 0;

  async connect(input) {
    const attempt = ++this.#attempt;
    await this.disconnect();
    if (attempt !== this.#attempt) throw new Error("A newer connection was started before this one opened");
    this.closing = false;
    const targetConfig = this.#connectionConfig(input, "Target");
    // The handshake limit can be set per manager, so a test of what happens around it
    // does not have to wait out the real twenty seconds.
    if (this.handshakeTimeout) targetConfig.readyTimeout = this.handshakeTimeout;
    const targetIdentity = hostIdentity(targetConfig.host, targetConfig.port);
    const protocol = normalizeProtocol(input.protocol);
    let jumpInfo = null;
    // What this attempt itself opened, newest last, so that an overtaken attempt can
    // close its own and nothing belonging to the attempt that overtook it.
    const opened = [];
    // Checked after every wait. A disconnect can arrive while the handshake is still
    // in flight -- closing the window that asked for this connection does exactly
    // that -- and so can a newer connect. Either way nothing more is installed.
    const stillWanted = () => {
      if (attempt !== this.#attempt) throw new Error("A newer connection was started before this one opened");
      if (this.closing) throw new Error("The connection was closed before it finished opening");
    };

    try {
      if (input.jump?.enabled) {
        const jumpConfig = this.#connectionConfig(input.jump, "Jump host");
        if (this.handshakeTimeout) jumpConfig.readyTimeout = this.handshakeTimeout;
        const jumpIdentity = hostIdentity(jumpConfig.host, jumpConfig.port);
        const jumpClient = await this.#openClient(jumpConfig, jumpIdentity, "Jump host");
        opened.push(() => jumpClient.end());
        stillWanted();
        this.jumpClient = jumpClient;
        jumpClient.once("close", () => this.#handleUnexpectedClose("jump", jumpClient));
        const jumpStream = await new Promise((resolve, reject) => {
          jumpClient.forwardOut(
            "127.0.0.1", 0, targetConfig.host, targetConfig.port,
            (error, stream) => error ? reject(error) : resolve(stream),
          );
        });
        opened.push(() => jumpStream.destroy());
        stillWanted();
        this.jumpStream = jumpStream;
        targetConfig.sock = jumpStream;
        jumpInfo = { host: jumpConfig.host, port: jumpConfig.port, username: jumpConfig.username };
      }

      const client = await this.#openClient(targetConfig, targetIdentity, "Destination host");
      opened.push(() => client.end());
      stillWanted();
      this.client = client;
      client.once("close", () => this.#handleUnexpectedClose("target", client));
      const { transport, sftpError } = await this.#openTransport(protocol);
      opened.push(() => transport.close());
      stillWanted();
      this.transport = transport;
      this.#loginTransport = transport;
      // sudo asks for the password of the user who is running it, which for a
      // password login is the one just used. It goes nowhere but to sudo on this host.
      this.#sudoPassword = input.authType === "password" ? String(input.password || "") || null : null;
      const home = await this.#call("realpath", ".").catch(() => "/");
      stillWanted();
      this.connection = {
        host: targetConfig.host,
        port: targetConfig.port,
        username: targetConfig.username,
        home,
        jump: jumpInfo,
        protocol: transport.kind,
        requestedProtocol: protocol,
        // Why the fallback happened, so the interface can say so rather than
        // quietly working differently from the way it was asked to.
        sftpUnavailable: sftpError,
      };
      const where = `${targetConfig.host}:${targetConfig.port}`;
      const route = jumpInfo ? `${where} through ${jumpInfo.host}:${jumpInfo.port}` : where;
      const how = transport.kind === "scp"
        ? sftpError ? " over SCP; SFTP was unavailable" : " over SCP"
        : "";
      this.emit("status", { connected: true, message: `Connected to ${route}${how}`, protocol: transport.kind });
      return this.connection;
    } catch (error) {
      for (const close of opened.reverse()) {
        try { close(); } catch { /* already closed */ }
      }
      // Only the attempt that is still the current one may tear down the session's
      // state; an overtaken one would be tearing down its successor.
      if (attempt === this.#attempt) await this.disconnect();
      throw error;
    }
  }

  // SFTP first unless SCP was asked for outright. A refused subsystem is an
  // ordinary configuration, not a broken host, so with the fallback allowed the
  // session carries on over a shell and scp and says which one it ended up using.
  async #openTransport(protocol) {
    if (protocol !== "scp") {
      try {
        return { transport: await this.#openSftp(), sftpError: null };
      } catch (error) {
        const reason = String(error?.message || error);
        if (protocol !== "sftp-scp") {
          throw new Error(`SFTP is unavailable on the destination host: ${reason}`);
        }
        if (this.closing) throw error;
        try {
          return { transport: await this.#openShell(), sftpError: reason };
        } catch (fallbackError) {
          throw new Error(
            `SFTP is unavailable (${reason}), and SCP could not be used either: ${fallbackError.message}`,
          );
        }
      }
    }
    return { transport: await this.#openShell(), sftpError: null };
  }

  #openSftp() {
    return new Promise((resolve, reject) => {
      let settled = false;
      // A refused subsystem comes back as an error, but a host that accepts the
      // channel and then never answers would otherwise hold the connection open
      // for ever and never reach the fallback.
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        reject(new Error("the SFTP subsystem did not answer"));
      }, SFTP_OPEN_TIMEOUT);
      this.client.sftp((error, session) => {
        if (settled) {
          if (!error) { try { session.end(); } catch { /* nothing to close */ } }
          return;
        }
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else resolve(new SftpTransport(session));
      });
    });
  }

  async #openShell() {
    const transport = new ShellTransport(this.client);
    await transport.probe();
    return transport;
  }

  async disconnect() {
    this.closing = true;
    if (this.terminal) {
      this.terminal.end();
      this.terminal = null;
    }
    this.#closeTransports();
    if (this.client) {
      const client = this.client;
      this.client = null;
      client.end();
    }
    if (this.jumpStream) {
      const stream = this.jumpStream;
      this.jumpStream = null;
      stream.destroy();
    }
    if (this.jumpClient) {
      const client = this.jumpClient;
      this.jumpClient = null;
      client.end();
    }
    this.connection = null;
  }

  async list(directory) {
    this.#requireConnection();
    const current = remotePath(directory, this.connection.home);
    const { items, rejected } = await this.#readEntries(current);
    const entries = items.map((item) => this.#entry(current, item));
    entries.sort((a, b) => Number(b.directory) - Number(a.directory) || a.name.localeCompare(b.name));
    return {
      path: current,
      parent: remoteParent(current),
      entries,
      rejected,
    };
  }

  // Breadth-first on purpose: a search that runs out of time or fills up should
  // have covered the folders nearest the one being searched, not one deep branch
  // chosen at random. Reads are kept continuously in flight rather than in
  // level-sized batches, because on a high-latency link the round trip is the
  // limit and one slow folder must not leave the other slots idle.
  // `bounds` exists so the limit and deadline can be driven from a test; the IPC
  // call passes only the first three arguments.
  async search(directory, query, recursive = true, bounds = {}) {
    this.#requireConnection();
    const limit = Number(bounds.limit) > 0 ? Number(bounds.limit) : SEARCH_LIMIT;
    const milliseconds = Number.isFinite(bounds.milliseconds) ? Number(bounds.milliseconds) : SEARCH_MILLISECONDS;
    const asked = recursive ? (Number(bounds.concurrency) > 0 ? Number(bounds.concurrency) : SEARCH_CONCURRENCY) : 1;
    // In SCP mode each folder read is its own exec channel, and a host allows only
    // so many at once, so the transport caps how wide the search may fan out.
    const concurrency = Math.max(1, Math.min(asked, this.transport.concurrencyLimit));
    const root = remotePath(directory, this.connection.home);
    const cleanQuery = String(query || "").trim();
    if (!cleanQuery) throw new Error("Search text is empty");
    if (cleanQuery.length > 200) throw new Error("Search text is too long");

    const matcher = buildMatcher(cleanQuery);
    const deadline = Date.now() + milliseconds;
    const queue = [root];
    const matches = [];
    const excluded = new Set();
    const reading = new Map();
    let timedOut = false;
    let unreadable = 0;
    let scanned = 0;
    let nextRead = 0;
    let rejected = 0;

    const startRead = (current) => {
      const key = nextRead++;
      reading.set(key, (async () => {
        try {
          const read = await this.#readEntries(current);
          return { key, current, items: read.items, rejected: read.rejected };
        } catch {
          return { key, current, items: null, rejected: 0 };
        }
      })());
    };

    while (matches.length < limit) {
      while (queue.length && reading.size < concurrency) startRead(queue.shift());
      if (!reading.size) break;
      if (Date.now() >= deadline) { timedOut = true; break; }

      const { key, current, items, rejected: dropped } = await Promise.race(reading.values());
      reading.delete(key);
      rejected += dropped;
      if (items === null) { unreadable += 1; continue; }
      scanned += 1;

      const location = path.posix.relative(root, current);
      for (const item of items) {
        // The deadline is checked here as well as between folders. One folder with a
        // great many entries in it can outrun it on its own, and the limit is on how
        // long the search may take -- not on how long each folder may take -- because
        // the main process is serving every window while it runs.
        if (Date.now() >= deadline) { timedOut = true; break; }
        const name = item.filename;
        const relativePath = location ? `${location}/${name}` : name;
        // Only a match is worth turning into a full record; formatting a mode
        // string for every entry of a large tree is pure waste.
        if (matcher.test(name, relativePath, path.posix.join(current, name))) {
          const record = this.#entry(current, item);
          record.location = location || ".";
          matches.push(record);
          if (matches.length >= limit) break;
        }
        if (recursive && item.attrs.isDirectory() && !item.attrs.isSymbolicLink()) {
          if (SEARCH_SKIP.has(name)) excluded.add(name);
          else queue.push(path.posix.join(current, name));
        }
      }
      if (timedOut || !recursive) break;
    }

    matches.sort((a, b) => Number(b.directory) - Number(a.directory) ||
      a.name.localeCompare(b.name) || a.location.localeCompare(b.location));
    return {
      path: root,
      parent: remoteParent(root),
      entries: matches,
      search: true,
      query: cleanQuery,
      scope: matcher.scope,
      wildcard: matcher.wildcard,
      truncated: timedOut || matches.length >= limit,
      timedOut,
      limit,
      seconds: milliseconds / 1000,
      scanned,
      unreadable,
      rejected,
      unexplored: queue.length + reading.size,
      excluded: [...excluded].sort(),
    };
  }

  async resolve(remoteFile) {
    this.#requireConnection();
    const target = remotePath(remoteFile);
    const attributes = await this.#call("stat", target);
    return {
      path: target,
      directory: attributes.isDirectory(),
      size: attributes.size,
    };
  }

  // The editor's view of a file: `{ text, eol, stamp }`.
  //
  // - Only an ordinary file is read. A named pipe blocks sftp-server, which serves
  //   one request at a time, so every later request on the session hung behind it;
  //   a device such as /dev/zero reports a size of 0 and never ends.
  // - The cap is on the bytes actually read, not only on the size `stat` claimed.
  // - The text must be UTF-8 as it stands. Decoding anything else replaced each
  //   stray byte with U+FFFD, and saving unchanged then wrote those over the
  //   originals; refusing is the only honest answer for a plain text box. A byte
  //   order mark is kept in the text, so it is written back as it was.
  // - Line endings are reported, not kept: `text` has CRLF turned into LF, which is
  //   what the text box does anyway, and `eol` is CRLF when at least as many lines
  //   end that way as with LF alone. A file that mixes the two comes back with the
  //   majority ending throughout once saved.
  // - `stamp` is the size and modification time read here, for `writeFile` to
  //   check that nothing changed the file in the meantime.
  async readFile(remoteFile, limit = EDIT_LIMIT) {
    this.#requireConnection();
    const target = remotePath(remoteFile);
    const name = path.posix.basename(target) || target;
    const attributes = await this.#call("stat", target);
    if (!regularFile(attributes)) throw new Error(`${name} is not an ordinary file, so it cannot be opened in the editor`);
    if (attributes.size > limit) throw new Error("File is too large to edit here");
    const data = await this.#readCapped(target, limit, "File is too large to edit here");
    if (data.includes(0)) throw new Error("Binary file cannot be edited as text");
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
    } catch {
      throw new Error(`${name} is not UTF-8 text, and editing it here would change bytes you did not touch`);
    }
    const crlf = (text.match(/\r\n/g) || []).length;
    const lf = (text.match(/\n/g) || []).length - crlf;
    return {
      text: text.replace(/\r\n/g, "\n"),
      eol: crlf > 0 && crlf >= lf ? "\r\n" : "\n",
      stamp: stampOf(attributes),
    };
  }

  async readBinary(remoteFile, limit = PREVIEW_LIMIT) {
    this.#requireConnection();
    const target = remotePath(remoteFile);
    const attributes = await this.#call("stat", target);
    if (!regularFile(attributes)) {
      throw new Error(`${path.posix.basename(target) || target} is not an ordinary file, so it cannot be previewed`);
    }
    if (attributes.size > limit) throw new Error("Image is too large to preview here");
    return this.#readCapped(target, limit, "Image is too large to preview here");
  }

  // Saves the editor's text. `eol` is what `readFile` reported, and turns the text
  // box's LF back into CRLF. `expect` is the stamp `readFile` returned: when the file
  // has changed since -- another editor, a deploy, a log rotation -- nothing is
  // written and the current stamp comes back, so the person can choose rather than
  // silently losing the other change. A file that has gone counts as changed. The
  // check compares size and the modification time to the second, so a change of the
  // same size within the same second can slip past it.
  async writeFile(remoteFile, contents, options = {}) {
    this.#requireConnection();
    const target = remotePath(remoteFile);
    const { eol, expect } = editOptions(options);
    let text = String(contents ?? "");
    if (eol === "\r\n") text = text.replace(/\r?\n/g, "\r\n");
    const buffer = Buffer.from(text, "utf8");
    if (buffer.length > EDIT_LIMIT) throw new Error("File is too large to edit here");
    if (expect) {
      const current = await this.#call("stat", target).catch((error) => {
        if (missing(error)) return null;
        throw error;
      });
      if (!current || current.size !== expect.size || current.mtime !== expect.mtime) {
        return { ok: false, changed: true, stamp: current ? stampOf(current) : null };
      }
    }
    await this.#putWhole(target, (destination) => this.#call("writeFile", destination, buffer));
    return { ok: true, stamp: stampOf(await this.#call("stat", target)) };
  }

  // A pasted screenshot has no filename of its own, so one is generated from the
  // time and checked against the folder rather than overwriting anything.
  async writePastedImage(remoteDirectory, data, extension = "png") {
    this.#requireConnection();
    // Local time, so the name matches the clock the person pasting is looking at.
    const now = new Date();
    const pad = (value) => String(value).padStart(2, "0");
    const stamp = [
      now.getFullYear(), pad(now.getMonth() + 1), pad(now.getDate()),
      pad(now.getHours()), pad(now.getMinutes()), pad(now.getSeconds()),
    ].join("-");
    for (let attempt = 1; attempt <= 50; attempt += 1) {
      const name = attempt === 1
        ? `pasted-${stamp}.${extension}`
        : `pasted-${stamp}-${attempt}.${extension}`;
      const target = remoteJoin(remoteDirectory, name);
      const taken = await this.#call("lstat", target).then(() => true, () => false);
      if (taken) continue;
      await this.#putWhole(target, (destination) => this.#call("writeFile", destination, data));
      return { path: target, name, bytes: data.length };
    }
    throw new Error("Could not find an unused name for the pasted image");
  }

  async mkdir(directory, name) {
    const target = remoteJoin(directory, name);
    await this.#call("mkdir", target);
    return { path: target };
  }

  // A rename never replaces anything. OpenSSH's sftp-server refuses a name that is
  // taken, but other servers, and `mv` in SCP mode, would quietly overwrite a file
  // or move the item inside a folder of that name. A name that differs only in
  // letter case is let through: on a host whose disk ignores case, the item already
  // "there" is the one being renamed.
  async rename(remoteFile, name) {
    const source = remotePath(remoteFile);
    const target = remoteJoin(path.posix.dirname(source), name);
    if (target === source) return { path: target };
    if (target.toLowerCase() !== source.toLowerCase()) {
      const taken = await this.#call("lstat", target).then(() => true, () => false);
      if (taken) throw new Error(`Something named ${name} is already here; choose another name`);
    }
    await this.#call("rename", source, target);
    return { path: target };
  }

  async delete(paths) {
    let deleted = 0;
    const failures = [];
    for (const value of paths) {
      try {
        await this.#removeTree(remotePath(value));
        deleted += 1;
      } catch (error) {
        failures.push({ path: value, error: error.message });
      }
    }
    return { deleted, failures };
  }

  // What is already sitting in the destination, so the caller can ask before any
  // byte is written. Only the names that were dropped are probed: a folder that
  // already exists is reported as one collision, and the files inside it are settled
  // by the choice made for the folder rather than by a second round of questions.
  //
  // Two dropped items can also collide with each other rather than with the host --
  // dragging out of a search results window gathers files from several folders, and
  // two of them can share a name. Nothing is in the way when the first is written, so
  // probing alone would never see it and the second would quietly replace the first.
  // Such a name is reported once, and the answer given for it settles every copy,
  // because the write itself is what each later copy then collides with.
  //
  // Two of them can disagree about what they are as well as what they are called --
  // one a file and one a folder. Neither can replace the other, exactly as neither
  // can replace something of the wrong kind on the host, so that is reported as the
  // same mismatch and overwriting is not offered for it either.
  async planUpload(localPaths, remoteDirectory) {
    this.#requireConnection();
    const directory = remotePath(remoteDirectory);
    // One entry per name, in the order it was first dropped, so a shared name is one
    // question and the list reads in the order the items were picked. Every dropped
    // item is measured, not only the first of each name: what a later copy is has to
    // be known before the question can be put honestly, and these are local calls
    // with no round trip to spend.
    const wanted = new Map();
    for (const localPath of localPaths) {
      const name = uploadName(localPath);
      const kind = localUploadKind(localPath);
      const seen = wanted.get(name);
      if (seen) {
        seen.copies += 1;
        if (kind.directory !== seen.local.directory) seen.mixed = true;
      } else {
        wanted.set(name, { name, local: kind, copies: 1, mixed: false });
      }
    }
    // The probes do not depend on each other, and on a link where the round trip is
    // the cost, a couple of hundred dropped items would otherwise spend it a couple
    // of hundred times over before the question could even be put. In SCP mode each
    // probe is its own exec channel, and the transport knows how many of those a host
    // will allow at once.
    const entries = [...wanted.values()];
    const limit = Math.max(1, Math.min(PLAN_CONCURRENCY, this.transport.concurrencyLimit, entries.length));
    const found = new Array(entries.length);
    let next = 0;
    await Promise.all(Array.from({ length: limit }, async () => {
      while (next < entries.length) {
        const index = next;
        next += 1;
        found[index] = await this.#probeUpload(directory, entries[index]);
      }
    }));
    return { directory, collisions: found.filter(Boolean) };
  }

  // Whether one dropped name would land on something, and what that something is.
  // `null` means the way is clear.
  async #probeUpload(directory, { name, local, copies, mixed }) {
    const target = remoteJoin(directory, name);
    const existing = await this.#call("lstat", target).then((value) => value, () => null);
    const duplicates = copies > 1 ? copies : 0;
    if (!existing && !duplicates) return null;
    const entry = {
      name,
      path: target,
      directory: local.directory,
      // A file cannot replace a folder or the other way round, so the caller must
      // not offer to overwrite; skipping or keeping both is all that is left. Two
      // dropped items of different kinds are that same impossibility, arriving
      // before anything has been written rather than from the host.
      mismatch: mixed,
      mixed,
      duplicates,
      local: { size: local.size, modified: local.modified },
      remote: null,
    };
    if (!existing) return entry;
    const symlink = existing.isSymbolicLink();
    // A shortcut is reported as whatever it points at, because that is what an upload
    // through it would land on.
    const remoteIsDirectory = symlink
      ? await this.#call("stat", target).then((value) => value.isDirectory(), () => false)
      : existing.isDirectory();
    entry.mismatch = mixed || local.directory !== remoteIsDirectory;
    entry.remote = {
      directory: remoteIsDirectory,
      symlink,
      size: existing.size,
      modified: existing.mtime ? new Date(existing.mtime * 1000).toISOString() : "",
    };
    return entry;
  }

  // `decisions` maps a top-level name to what should happen when something is
  // already there: "overwrite", "skip" or "keep-both". A name with no decision is
  // overwritten, so a caller that asks nothing behaves as this always has; the
  // question belongs to `planUpload`, before this is called.
  //
  // "overwrite" on a folder means merging into it, which is what the mkdir below has
  // always done — the files inside are replaced where they clash. That is the one
  // place a name is still replaced without being named in the dialog, and it follows
  // from a choice the person made about the folder.
  async upload(localPaths, remoteDirectory, decisions = {}) {
    this.#requireConnection();
    const report = { uploaded: [], skipped: [], renamed: [] };
    for (const localPath of localPaths) {
      const name = uploadName(localPath);
      const choice = uploadChoice(decisions?.[name]);
      const target = remoteJoin(remoteDirectory, name);
      let destination = target;
      if (choice !== "overwrite") {
        const taken = await this.#call("lstat", target).then(() => true, () => false);
        if (taken) {
          if (choice === "skip") {
            report.skipped.push(target);
            continue;
          }
          destination = await this.#freeRemotePath(remoteDirectory, name);
          report.renamed.push({ from: target, to: destination });
        }
      }
      await this.#uploadTree(localPath, destination, new Set());
      report.uploaded.push(destination);
    }
    return report;
  }

  // Inside a folder being downloaded, some things are left out rather than copied:
  // a shortcut that leads outside the folder (a `docs -> /` someone planted in a
  // shared folder would otherwise start copying the whole host), a shortcut to
  // nothing, and anything that is not an ordinary file or folder (a pipe would hang
  // the session, a device would never end). The rest is downloaded, and then the
  // call fails with a message naming what was left out, because the person has to
  // hear about it and a list of saved paths has nowhere to say it.
  async download(remotePaths, localDirectory, singleFilePath = null) {
    const downloaded = [];
    const leftOut = [];
    for (const [index, sourceValue] of remotePaths.entries()) {
      const source = remotePath(sourceValue);
      const single = Boolean(singleFilePath) && remotePaths.length === 1;
      // Everything written for this item has to stay under the folder that was
      // chosen. Names are already checked as they are read; this is the second lock
      // on the same door, and it is the one that does not depend on getting that
      // right -- which is why it is taken from the choice itself, never from a path
      // built out of a name the host supplied.
      const boundary = path.resolve(single ? path.dirname(singleFilePath) : localDirectory);
      // The host's name, as this computer's disk can hold it: on Windows a backslash
      // in it would otherwise be a separator, and `..\..\evil.bat` a way out.
      const destination = single
        ? singleFilePath
        : uniqueLocalPath(path.join(localDirectory, localName(path.posix.basename(source), path.sep) || `download-${index + 1}`));
      await this.#downloadTree(source, destination, { boundary, ancestors: new Set(), root: null, leftOut });
      downloaded.push(destination);
    }
    if (leftOut.length) throw leftOutError(downloaded, leftOut);
    return downloaded;
  }

  // Shells replaced by a restart. Their channels close some time after the new
  // shell is in place, and that close is no news: it must neither drop the new
  // shell nor print "[remote shell closed]" into it.
  #retiredTerminals = new WeakSet();

  async startTerminal({ columns = 100, rows = 30 } = {}) {
    this.#requireConnection();
    // ⟳ Restart is usually pressed because something in the shell is stuck. EOF
    // goes to that program, not to the shell, so the old shell outlived it on the
    // host; closing the channel hangs up the whole session instead.
    const previous = this.terminal;
    if (previous) {
      this.#retiredTerminals.add(previous);
      this.terminal = null;
      try { previous.close(); } catch { /* already gone */ }
    }
    const stream = await new Promise((resolve, reject) => {
      this.client.shell({ term: "xterm-256color", cols: columns, rows }, (error, channel) => {
        if (error) return reject(error);
        resolve(channel);
      });
    });
    this.terminal = stream;
    // One decoder for the life of the stream: a character whose bytes are split
    // across two SSH packets is held until the rest arrives, rather than each half
    // turning into U+FFFD.
    const decoder = new StringDecoder("utf8");
    stream.on("data", (data) => {
      const text = decoder.write(data);
      if (text) this.emit("terminal-data", text);
    });
    stream.on("close", () => {
      if (this.#retiredTerminals.has(stream)) return;
      if (this.terminal === stream) this.terminal = null;
      const rest = decoder.end();
      if (rest) this.emit("terminal-data", rest);
      this.emit("terminal-exit");
    });
    return { ok: true };
  }

  terminalInput(data) {
    if (!this.terminal) return;
    const text = String(data);
    this.terminal.write(text);
    // Enter runs a command and Ctrl+D ends a shell; either can change who the
    // terminal is working as, and nothing else can.
    if (/[\r\n\x04]/.test(text)) this.#scheduleFollow();
  }

  // The password sudo asked for, typed into the prompt the interface showed. It is
  // kept for the rest of the connection so following root again does not ask twice.
  async followWithPassword(password) {
    this.#requireConnection();
    const uid = this.#pendingUid;
    if (uid === null) return this.#browseState();
    const given = String(password || "");
    // A refusal goes back to the dialog, and the password is not kept.
    const opened = await this.#openAs(uid, given);
    this.#sudoPassword = given;
    this.#pendingUid = null;
    // The switch itself may wait for a transfer to finish; the dialog does not.
    this.#swapIn(uid, opened).catch(() => undefined);
    return this.#browseState();
  }

  // Leave the file pane as the login user until the terminal changes user again.
  declineFollow() {
    this.#pendingUid = null;
    return this.#browseState();
  }

  #closeTransports() {
    const login = this.#loginTransport;
    if (this.transport && this.transport !== login) this.transport.close();
    if (login) login.close();
    this.transport = null;
    this.#resetFollowing();
  }

  #scheduleFollow() {
    if (!this.connection) return;
    if (!this.#followSince) this.#followSince = Date.now();
    if (this.#followTimer) clearTimeout(this.#followTimer);
    const wait = Math.max(0, Math.min(FOLLOW_QUICK, this.#followSince + FOLLOW_LONGEST - Date.now()));
    this.#followTimer = setTimeout(() => {
      this.#followTimer = null;
      this.#followSince = 0;
      this.#follow();
    }, wait);
    if (this.#followLateTimer) clearTimeout(this.#followLateTimer);
    this.#followLateTimer = setTimeout(() => {
      this.#followLateTimer = null;
      this.#follow();
    }, FOLLOW_LATE);
  }

  async #follow() {
    if (this.#following) {
      this.#followAgain = true;
      return;
    }
    this.#following = true;
    try {
      const probe = parseProbe(await this.#probe());
      if (this.#loginUid === null && Number.isInteger(probe.uid)) this.#loginUid = probe.uid;
      const uid = terminalUser(probe);
      if (uid === null || this.#loginUid === null || !this.connection) return;
      // Only a change is acted on. Declining the password prompt, or a sudo that
      // refuses, then holds until the terminal becomes someone else, rather than
      // asking again at every command typed as root.
      const seen = this.#seenUid ?? this.#loginUid;
      if (uid === seen) return;
      this.#seenUid = uid;
      this.#pendingUid = null;
      if (uid === this.#loginUid) {
        await this.#returnToLogin();
        return;
      }
      const password = this.#sudoPassword;
      const opened = await this.#openAs(uid, password).catch((error) => {
        if (!this.connection) return null;
        // A password sudo refused is forgotten at once. Offering it again at the
        // next switch would be another failed login on the host, and enough of
        // those lock the account.
        if (error.rejected && password !== null && this.#sudoPassword === password) this.#sudoPassword = null;
        if (error.sudoPasswordNeeded) {
          this.#pendingUid = uid;
          this.emit("browse-user", { ...this.#browseState(), needsPassword: true, wanted: uid });
          return;
        }
        this.emit("browse-user", { ...this.#browseState(), failed: `${error.message || error}`, wanted: uid });
        return null;
      });
      if (opened) await this.#swapIn(uid, opened);
    } catch {
      // A host without ps, or one that hides other users' processes, simply is not
      // followed; the pane stays as the user who logged in.
    } finally {
      this.#following = false;
      // One more reading for whatever arrived while this one ran -- not the pair
      // an Enter schedules, which on a slow host would keep scheduling itself.
      if (this.#followAgain && this.connection) {
        this.#followAgain = false;
        setTimeout(() => this.#follow(), 0);
      }
    }
  }

  #openAs(uid, password) {
    if (!this.#loginTransport || this.#loginTransport.kind !== "sftp") {
      return Promise.reject(new Error("following the terminal to another user needs SFTP; this connection is using SCP"));
    }
    return openSudoSftp(this.client, uid, password);
  }

  async #swapIn(uid, { transport, user }) {
    await this.#whenIdle();
    if (!this.connection || this.#loginTransport === null) {
      transport.close();
      return;
    }
    if (this.transport && this.transport !== this.#loginTransport) this.transport.close();
    this.transport = transport;
    this.#browseUid = uid;
    // sudo's session can end on its own -- the host restarts sshd, or an
    // administrator kills it -- and the pane then goes back to the login user
    // rather than failing every request.
    transport.sftp.once("close", () => {
      if (this.transport !== transport) return;
      this.#seenUid = null;
      this.#returnToLogin({ now: true });
    });
    this.#pendingUid = null;
    // `id -un` has nothing to say for a uid with no name.
    this.connection.browseAs = user || (uid === 0 ? "root" : `uid ${uid}`);
    this.emit("browse-user", this.#browseState());
  }

  // `now` is for a sudo session that has already gone: there is nothing left to
  // wait for, and every request on it would fail.
  async #returnToLogin({ now = false } = {}) {
    if (!now) await this.#whenIdle();
    if (!this.#loginTransport) return;
    if (this.transport && this.transport !== this.#loginTransport) this.transport.close();
    this.transport = this.#loginTransport;
    const changed = this.#browseUid !== null;
    this.#browseUid = null;
    if (this.connection) this.connection.browseAs = null;
    if (changed) this.emit("browse-user", this.#browseState());
  }

  #browseState() {
    return { user: this.connection?.browseAs || null, elevated: this.#browseUid !== null };
  }

  #probe() {
    return new Promise((resolve, reject) => {
      this.client.exec(PROBE_COMMAND, (error, stream) => {
        if (error) return reject(error);
        const out = [];
        const timer = setTimeout(() => {
          try { stream.close(); } catch { /* already gone */ }
          reject(new Error("the process table could not be read in time"));
        }, PROBE_TIMEOUT);
        stream.on("data", (chunk) => out.push(chunk));
        stream.stderr.on("data", () => {});
        stream.once("close", () => {
          clearTimeout(timer);
          resolve(Buffer.concat(out).toString("utf8"));
        });
      });
    });
  }

  // Each character of `data` is one byte, so it must not be re-encoded as UTF-8:
  // a mouse report for a column past 95 would otherwise become two bytes and the
  // remote program would read a corrupt escape sequence.
  terminalBinary(data) {
    if (this.terminal) this.terminal.write(Buffer.from(String(data), "latin1"));
  }

  terminalResize(columns, rows) {
    if (this.terminal) this.terminal.setWindow(rows, columns, 0, 0);
  }

  #connectionConfig(input, label = "SSH") {
    const host = String(input.host || "").trim();
    const username = String(input.username || "").trim();
    const port = Number(input.port || 22);
    if (!host || !username) throw new Error(`${label} host and username are required`);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`${label} SSH port is invalid`);
    const config = { host, username, port, readyTimeout: 20000, keepaliveInterval: 10000 };
    if (input.authType === "password") {
      if (!input.password) throw new Error(`${label} password is required`);
      config.password = String(input.password);
      config.tryKeyboard = true;
    } else if (input.authType === "key") {
      if (!input.keyPath) throw new Error(`${label} private-key path is required`);
      config.privateKey = readPrivateKey(input.keyPath, label);
      if (input.passphrase) config.passphrase = String(input.passphrase);
    } else {
      const agent = process.platform === "win32"
        ? "\\\\.\\pipe\\openssh-ssh-agent"
        : process.env.SSH_AUTH_SOCK;
      if (!agent) throw new Error(`No SSH agent is available for ${label.toLowerCase()}; choose a key or password`);
      config.agent = agent;
    }
    return config;
  }

  // The handshake has a time limit, and the person reading a fingerprint does not.
  // ssh2's own limit runs from the moment the socket opens, straight through the
  // host-key prompt, so someone who took more than twenty seconds to compare a
  // fingerprint got "Timed out" -- and then, pressing Trust, had the key remembered
  // for a connection that no longer existed. The limit is kept here instead: it stops
  // while a host-key decision is pending and starts afresh once it is made, and a
  // decision that arrives after the connection has failed is not acted on at all.
  async #openClient(config, identity, role) {
    const client = new Client();
    const limit = config.readyTimeout;
    config.readyTimeout = 0;
    let settled = false;
    let timer = null;
    let fail = () => undefined;
    // Closes a host-key prompt still open for a connection that has since ended.
    const asking = new AbortController();
    const stopClock = () => {
      if (timer) clearTimeout(timer);
      timer = null;
    };
    const startClock = () => {
      stopClock();
      if (limit > 0) timer = setTimeout(() => fail(new Error("Timed out while waiting for handshake")), limit);
    };
    config.hostHash = "sha256";
    config.hostVerifier = (fingerprint, accept) => {
      const known = this.knownHosts.get(identity);
      if (known && known.sha256 === fingerprint) return accept(true);
      stopClock();
      this.knownHosts.exclusive(identity, () => this.#decideHost({
        identity, role, fingerprint, signal: asking.signal, gone: () => settled,
      })).then((trusted) => {
        if (settled) return;
        startClock();
        accept(trusted);
      }).catch(() => accept(false));
    };
    if (config.password) {
      // Some hosts ask for the password over keyboard-interactive rather than the
      // password method, and one hidden prompt is what that looks like. Anything
      // else is a different question -- a second factor, a challenge, a visible
      // field asking for something that is not a secret -- and answering all of
      // them with the password hands it to whatever thought to ask. A destination
      // is not trusted with more than it needs to let this connection in.
      // A server may ask more than once, and the password is only an answer to the
      // first asking. Having given it, a second round is by definition something
      // else -- the password was wrong, or what is wanted now is a second factor --
      // and repeating it there hands it over twice for one connection.
      //
      // The same goes across methods. A host offering both "password" and
      // "keyboard-interactive" -- PAM, commonly -- that has just refused the password
      // over the first would otherwise be sent it again as the answer to its
      // "Password:" prompt: two failed logins for one connect, which halves the
      // tries before an account lockout -- or sent an empty answer instead, which
      // PAM counts just the same. So the methods are taken in order, skipping any the
      // host did not offer; keyboard-interactive is only given the password when the
      // password method was never used, and is not tried at all after a refused
      // password unless the host said the password was accepted and something more
      // is wanted (a partial success).
      let given = false;
      const methods = ["none", "password", "keyboard-interactive"];
      config.authHandler = (offered, partialSuccess) => {
        while (methods.length) {
          const method = methods.shift();
          if (method !== "none" && Array.isArray(offered) && !offered.includes(method)) continue;
          if (method === "keyboard-interactive" && given && !partialSuccess) return false;
          if (method === "password") given = true;
          return method;
        }
        return false;
      };
      client.on("keyboard-interactive", (_name, _instructions, _language, prompts, finish) => {
        const asksForOneSecret = !given && prompts.length === 1 && prompts[0]?.echo !== true;
        given = given || asksForOneSecret;
        finish(asksForOneSecret ? [config.password] : prompts.map(() => ""));
      });
    }
    try {
      await new Promise((resolve, reject) => {
        fail = (error) => {
          if (settled) return;
          settled = true;
          stopClock();
          asking.abort();
          reject(error);
        };
        client.once("ready", () => {
          if (settled) return;
          settled = true;
          stopClock();
          resolve();
        });
        client.once("error", fail);
        client.once("close", () => fail(new Error(`${role} connection closed during setup`)));
        startClock();
        client.connect(config);
      });
      // Keep a listener after setup so a late socket error cannot become an
      // unhandled EventEmitter error. The close handler reports the disconnect.
      client.on("error", () => {});
      return client;
    } catch (error) {
      client.end();
      throw new Error(`${role}: ${error.message}`);
    }
  }

  // Whether to trust a host key that does not match the one remembered, decided
  // while no other prompt for the same host is open (KnownHosts.exclusive). What is
  // stored is read now, at this prompt's turn, rather than when the key arrived: an
  // earlier prompt may have just remembered a key, and this one must then be shown
  // as the mismatch it is. It is read once more after the answer, and a store that
  // has moved in the meantime is asked about again rather than overwritten.
  async #decideHost({ identity, role, fingerprint, signal, gone }) {
    for (;;) {
      const known = this.knownHosts.get(identity);
      if (known && known.sha256 === fingerprint) return true;
      if (gone()) return false;
      const decision = await this.confirmHost({
        identity,
        role,
        fingerprint: displayFingerprint(fingerprint),
        previousFingerprint: known ? displayFingerprint(known.sha256) : null,
        signal,
      });
      // An answer to a connection that has already failed decides nothing.
      if (gone()) return false;
      if ((this.knownHosts.get(identity)?.sha256 || null) !== (known?.sha256 || null)) continue;
      if (decision?.remember) {
        try {
          this.knownHosts.remember(identity, fingerprint);
        } catch { /* the store is read-only or unwritable; this connection is trusted once */ }
      }
      return Boolean(decision?.accept);
    }
  }

  #handleUnexpectedClose(role, closedClient) {
    if (this.closing) return;
    if (role === "jump" && this.jumpClient !== closedClient) return;
    if (role === "target" && this.client !== closedClient) return;

    const message = role === "jump"
      ? "Jump-host connection closed"
      : "Destination SSH connection closed";

    if (this.terminal) {
      try { this.terminal.end(); } catch { /* channel already closed */ }
      this.terminal = null;
    }
    this.#closeTransports();
    if (this.client && this.client !== closedClient) this.client.end();
    this.client = null;
    if (this.jumpStream) {
      this.jumpStream.destroy();
      this.jumpStream = null;
    }
    if (this.jumpClient && this.jumpClient !== closedClient) this.jumpClient.end();
    this.jumpClient = null;
    this.connection = null;
    this.emit("status", { connected: false, message });
  }

  #entry(directory, item) {
    const attrs = item.attrs;
    return {
      name: item.filename,
      path: path.posix.join(directory, item.filename),
      directory: attrs.isDirectory(),
      symlink: attrs.isSymbolicLink(),
      size: attrs.size,
      modified: attrs.mtime ? new Date(attrs.mtime * 1000).toISOString() : "",
      mode: modeString(attrs.mode),
    };
  }

  #requireConnection() {
    if (!this.connected) throw new Error("Not connected to an SSH server");
  }

  #call(method, ...args) {
    this.#requireConnection();
    return this.transport.call(method, args);
  }

  // Every folder read goes through here. The names in a listing come from the far
  // end, and a name holding a separator or a dot-dot would change the meaning of the
  // path it is joined to — enough to write a downloaded file outside the folder that
  // was chosen, or to delete a sibling of the folder that was selected. No real
  // filesystem can hold such a name, so anything that claims one is dropped and
  // counted rather than followed.
  // `strict` decides what happens when a name is refused. Browsing and searching
  // count them and carry on, because seeing the rest of a folder is the point. A
  // recursive download or deletion stops instead: a name that could not exist means
  // something is badly wrong at the far end, and that is not a moment to keep
  // writing to, or removing from, a tree on either side.
  async #readEntries(directory, { strict = false } = {}) {
    const items = await this.#call("readdir", directory);
    const usable = [];
    let rejected = 0;
    for (const item of items) {
      if (safeRemoteName(item?.filename)) {
        usable.push(item);
        continue;
      }
      if (strict) {
        throw new Error(`The host offered an unusable name in ${directory}; nothing further was read there`);
      }
      rejected += 1;
    }
    return { items: usable, rejected };
  }

  async #removeTree(target) {
    const attributes = await this.#call("lstat", target);
    if (attributes.isDirectory() && !attributes.isSymbolicLink()) {
      const { items } = await this.#readEntries(target, { strict: true });
      for (const child of items) await this.#removeTree(path.posix.join(target, child.filename));
      await this.#call("rmdir", target);
    } else {
      await this.#call("unlink", target);
    }
  }

  // A free name beside `name`, in the style the download side already uses when a
  // local name is taken: report.txt, then report_2.txt. There is no atomic "create
  // only if absent" for a whole tree, so this probes; a name that appears in the gap
  // between the probe and the write is a race this cannot close.
  async #freeRemotePath(directory, name) {
    const parsed = path.posix.parse(name);
    for (let attempt = 2; attempt <= UNIQUE_NAME_ATTEMPTS; attempt += 1) {
      const target = remoteJoin(directory, `${parsed.name}_${attempt}${parsed.ext}`);
      const taken = await this.#call("lstat", target).then(() => true, () => false);
      if (!taken) return target;
    }
    throw new Error(`Could not find an unused name beside ${name}`);
  }

  // Local links are followed so that what the user selected is what arrives on
  // the remote host. `ancestors` holds the resolved directories currently open on
  // this branch, so a link that points back up cannot recurse forever while two
  // sibling links to the same directory are both still uploaded.
  async #uploadTree(localPath, remoteTarget, ancestors) {
    const link = fs.lstatSync(localPath);
    let attributes = link;
    if (link.isSymbolicLink()) {
      try {
        attributes = fs.statSync(localPath);
      } catch {
        throw new Error(`Local shortcut target is unavailable: ${path.basename(localPath)}`);
      }
    }
    if (attributes.isDirectory()) {
      let identity = localPath;
      try { identity = fs.realpathSync(localPath); } catch { /* keep the literal path */ }
      if (ancestors.has(identity)) return;
      ancestors.add(identity);
      // A folder that is already there is merged into, which is what overwriting a
      // folder has always meant. One that is there as a file cannot be merged into
      // or replaced, and saying which is which beats passing on the far end's own
      // one-word account of it.
      await this.#call("mkdir", remoteTarget).catch(async (error) => {
        const existing = await this.#call("stat", remoteTarget).catch(() => null);
        if (existing?.isDirectory()) return;
        if (existing) {
          throw new Error(`${path.posix.basename(remoteTarget)} is already there as a file, and a folder cannot replace it`);
        }
        throw error;
      });
      try {
        for (const name of fs.readdirSync(localPath)) {
          await this.#uploadTree(path.join(localPath, name), remoteJoin(remoteTarget, name), ancestors);
        }
      } finally {
        ancestors.delete(identity);
      }
    } else if (attributes.isFile()) {
      await this.#putWhole(remoteTarget, (destination) => this.#call("fastPut", localPath, destination));
    } else {
      throw new Error(`Unsupported local item: ${path.basename(localPath)}`);
    }
  }

  // `context` is shared by everything downloaded for one selected item: `boundary`
  // is the local folder nothing may be written outside of, `root` the real path of
  // the remote folder that was selected (set by the first call), `ancestors` the
  // real paths of the folders open on the current branch, and `leftOut` collects
  // what was not copied and why. `real` is this item's real path when the caller
  // already knows it -- a child that is not a link is its parent's real path plus
  // its name -- so only links cost a round trip to resolve.
  async #downloadTree(remoteSource, localTarget, context, real = null) {
    const { boundary, ancestors, leftOut } = context;
    const resolved = path.resolve(localTarget);
    const prefix = boundary.endsWith(path.sep) ? boundary : boundary + path.sep;
    if (resolved !== boundary && !resolved.startsWith(prefix)) {
      throw new Error(`The host offered a name that would write outside the chosen folder: ${path.basename(remoteSource)}`);
    }
    // Writing through a shortcut that is already sitting there would put the file
    // wherever it points, which is not where this download was sent.
    const existing = fs.lstatSync(localTarget, { throwIfNoEntry: false });
    if (existing?.isSymbolicLink()) {
      throw new Error(`${path.basename(localTarget)} already exists here as a shortcut; nothing was written to it`);
    }
    // The item that was selected is what the person asked for, links and all, so
    // anything wrong with it is an error. Inside it, one odd entry is left out and
    // reported rather than costing the rest of the folder.
    const top = context.root === null;
    const name = path.posix.basename(remoteSource) || remoteSource;
    const leaveOut = (reason) => {
      if (top) throw new Error(`${name} ${reason}, so it was not downloaded`);
      leftOut.push({ path: remoteSource, reason });
    };
    const link = await this.#call("lstat", remoteSource);
    let attributes = link;
    let identity = real;
    if (link.isSymbolicLink()) {
      attributes = await this.#call("stat", remoteSource).catch(() => null);
      if (!attributes) return leaveOut("is a shortcut to something that is not there");
      identity = await this.#call("realpath", remoteSource).catch(() => (top ? remoteSource : null));
      if (identity === null) return leaveOut("is a shortcut that could not be followed");
      if (!top && !within(identity, context.root)) {
        return leaveOut("is a shortcut that leads outside the folder being downloaded");
      }
    } else if (identity === null) {
      identity = link.isDirectory()
        ? await this.#call("realpath", remoteSource).catch(() => remoteSource)
        : remoteSource;
    }
    if (top) context.root = identity;
    if (attributes.isDirectory()) {
      if (ancestors.has(identity)) return undefined;
      ancestors.add(identity);
      fs.mkdirSync(localTarget, { recursive: true });
      try {
        const { items } = await this.#readEntries(remoteSource, { strict: true });
        for (const child of items) {
          const written = localName(child.filename, path.sep);
          // A name changed to fit this disk could now match a sibling's.
          const childTarget = written === child.filename
            ? path.join(localTarget, written)
            : uniqueLocalPath(path.join(localTarget, written));
          await this.#downloadTree(
            path.posix.join(remoteSource, child.filename),
            childTarget,
            context,
            child.attrs.isSymbolicLink() ? null : path.posix.join(identity, child.filename),
          );
        }
      } finally {
        ancestors.delete(identity);
      }
      return undefined;
    }
    if (!regularFile(attributes)) return leaveOut("is not an ordinary file (a pipe, device or socket)");
    return this.#fetchFile(remoteSource, localTarget);
  }

  // A file arrives under a temporary name beside its destination and takes the real
  // name only once it is complete. A transfer that fails part way -- the connection
  // drops, the disk fills -- removes its temporary copy and leaves nothing under the
  // real name, so a truncated file is never mistaken for the real one and a second
  // attempt is not saved as name_2 beside it.
  async #fetchFile(remoteSource, localTarget) {
    const folder = path.dirname(localTarget);
    fs.mkdirSync(folder, { recursive: true });
    const temporary = path.join(folder, temporaryName(path.basename(localTarget)));
    try {
      await this.#call("fastGet", remoteSource, temporary);
      fs.renameSync(temporary, localTarget);
    } catch (error) {
      try { fs.rmSync(temporary, { force: true }); } catch { /* nothing to remove */ }
      // A local failure names the path it failed on; the person chose the real one.
      if (typeof error?.message === "string") error.message = error.message.split(temporary).join(localTarget);
      throw error;
    }
  }

  // Writes a whole file under `target` so the name never holds a partial one: `put`
  // writes to a temporary name in the same folder, which then takes the real name
  // in one rename. An upload or a save that fails part way leaves the old file as it
  // was, and the temporary copy is removed when the host can still be reached.
  //
  // Replacing a file by renaming over it would quietly change two things writing in
  // place never did, and both are kept:
  // - A shortcut stays a shortcut: the file it points at is what gets replaced.
  // - The owner, group and mode stay the old file's. The mode is copied. A
  //   different owner -- root saving another user's file, or a file in a shared
  //   folder -- is set on the temporary copy before anything is written to it; when
  //   the host will not allow that, or will not let a new file be made in the folder
  //   at all, the file is written in place as before, because keeping its owner
  //   matters more than the protection against a failed write.
  async #putWhole(target, put) {
    const missingIsNull = (error) => {
      if (missing(error)) return null;
      throw error;
    };
    let destination = target;
    let existing = await this.#call("lstat", target).catch(missingIsNull);
    if (existing?.isSymbolicLink()) {
      const followed = await this.#call("stat", target).catch(() => null);
      // A shortcut to nothing: writing through it creates what it names, as before.
      if (!followed) return put(target);
      destination = await this.#call("realpath", target);
      existing = followed;
    }
    const name = path.posix.basename(destination);
    if (existing?.isDirectory()) throw new Error(`${name} is already there as a folder, and a file cannot replace it`);
    if (existing && !regularFile(existing)) throw new Error(`${name} is not an ordinary file, so nothing was written to it`);
    const temporary = path.posix.join(path.posix.dirname(destination), temporaryName(name));
    const discard = () => this.#call("unlink", temporary).catch(() => undefined);
    if (existing) {
      try {
        await this.#call("writeFile", temporary, Buffer.alloc(0));
      } catch (error) {
        if (refused(error)) return put(destination);
        throw error;
      }
      let kept;
      try {
        kept = await this.#keepOwner(temporary, existing);
      } catch (error) {
        await discard();
        throw error;
      }
      if (!kept) {
        await discard();
        return put(destination);
      }
    }
    try {
      await put(temporary);
      if (existing && typeof existing.mode === "number") {
        await this.#call("setstat", temporary, { mode: existing.mode & 0o7777 });
      }
      // Over an existing file the rename has to replace it. Onto a free name a plain
      // rename is used, which refuses a name that something else took meanwhile.
      await this.#call(existing ? "replace" : "rename", temporary, destination);
    } catch (error) {
      await discard();
      throw error;
    }
    return undefined;
  }

  // Whether the temporary copy has, or could be given, the old file's owner and
  // group. An owner the transport does not report has nothing to compare against.
  async #keepOwner(temporary, existing) {
    if (!Number.isInteger(existing.uid) || !Number.isInteger(existing.gid)) return true;
    const same = (attributes) => attributes.uid === existing.uid && attributes.gid === existing.gid;
    if (same(await this.#call("lstat", temporary))) return true;
    await this.#call("setstat", temporary, { uid: existing.uid, gid: existing.gid }).catch(() => undefined);
    return same(await this.#call("lstat", temporary));
  }

  #readCapped(target, limit, message) {
    return this.#call("readCapped", target, limit).catch((error) => {
      throw error?.tooLarge ? new Error(message) : error;
    });
  }
}

// The key path is the one local path the renderer can name, so check what it
// points at before reading it: a character device such as /dev/zero would
// otherwise be read until memory ran out.
function readPrivateKey(keyPath, label) {
  const target = String(keyPath);
  let attributes;
  try {
    attributes = fs.statSync(target);
  } catch {
    throw new Error(`${label} private key could not be read: ${path.basename(target)}`);
  }
  if (!attributes.isFile()) throw new Error(`${label} private key is not a file: ${path.basename(target)}`);
  if (attributes.size > MAX_PRIVATE_KEY_BYTES) throw new Error(`${label} private key is too large to be a key file`);
  try {
    return fs.readFileSync(target);
  } catch {
    throw new Error(`${label} private key could not be read: ${path.basename(target)}`);
  }
}

// An ordinary file, as opposed to a folder, a link, a pipe, a device or a socket.
// The mode carries the type; a server that leaves the mode out says nothing either
// way, and is believed about anything that is not a folder, as before.
function regularFile(attributes) {
  if (typeof attributes?.mode !== "number") return !attributes?.isDirectory?.();
  return (attributes.mode & 0o170000) === 0o100000;
}

function stampOf(attributes) {
  return { size: Number(attributes.size), mtime: Number(attributes.mtime) };
}

// A path that is `root` or lies beneath it, on the host's POSIX rules.
function within(candidate, root) {
  if (root === "/") return candidate.startsWith("/");
  return candidate === root || candidate.startsWith(`${root}/`);
}

// Whether a failure says the thing is not there. SFTP reports NO_SUCH_FILE as status
// 2; the shell transport uses the Node code.
function missing(error) {
  return error?.code === 2 || error?.code === "ENOENT";
}

// Whether a failure says the host would not allow it, as opposed to having failed
// at it. SFTP reports PERMISSION_DENIED as status 3.
function refused(error) {
  return error?.code === 3 || error?.code === "EACCES" || error?.code === "EPERM"
    || /permission denied|operation not permitted/i.test(String(error?.message || ""));
}

// The options the editor saves with, checked: `eol` is LF or CRLF, and `expect`,
// when given, is the `{ size, mtime }` stamp `readFile` returned.
function editOptions(options) {
  if (options === undefined || options === null) return { eol: "\n", expect: null };
  if (typeof options !== "object") throw new Error("The save options are not valid");
  const eol = options.eol ?? "\n";
  if (!LINE_ENDINGS.has(eol)) throw new Error("The line ending to save with is not valid");
  let expect = null;
  if (options.expect !== undefined && options.expect !== null) {
    const size = options.expect?.size;
    const mtime = options.expect?.mtime;
    if (!Number.isFinite(size) || size < 0 || !Number.isFinite(mtime)) {
      throw new Error("The file stamp to save against is not valid");
    }
    expect = { size, mtime };
  }
  return { eol, expect };
}

function leftOutError(downloaded, leftOut) {
  const named = leftOut.slice(0, LEFT_OUT_NAMED)
    .map((item) => `${path.posix.basename(item.path)} ${item.reason}`);
  const rest = leftOut.length - named.length;
  const items = `${downloaded.length} item${downloaded.length === 1 ? "" : "s"}`;
  const error = new Error(
    `Downloaded ${items}, but left out ${leftOut.length}: ${named.join("; ")}${rest ? `; and ${rest} more` : ""}`,
  );
  error.downloaded = downloaded;
  error.leftOut = leftOut;
  return error;
}

function modeString(mode) {
  const type = (mode & 0o170000) === 0o040000 ? "d" :
    (mode & 0o170000) === 0o120000 ? "l" : "-";
  const bits = [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001];
  return type + bits.map((bit, index) => mode & bit ? "rwx"[index % 3] : "-").join("");
}

function uploadName(localPath) {
  const name = path.basename(localPath);
  if (!name) throw new Error("A whole drive or root folder cannot be uploaded; choose a folder inside it");
  return name;
}

function uploadChoice(value) {
  const choice = String(value ?? "overwrite");
  if (!UPLOAD_CHOICES.has(choice)) throw new Error(`Unknown upload choice: ${choice}`);
  return choice;
}

// What the person actually chose, resolved the same way the upload itself resolves
// it: a shortcut is described by what it points at, because that is what is sent.
function localUploadKind(localPath) {
  const link = fs.lstatSync(localPath, { throwIfNoEntry: false });
  if (!link) throw new Error(`Local item is no longer available: ${path.basename(localPath)}`);
  let attributes = link;
  if (link.isSymbolicLink()) {
    try { attributes = fs.statSync(localPath); } catch { attributes = link; }
  }
  return {
    directory: attributes.isDirectory(),
    size: attributes.size,
    modified: new Date(attributes.mtimeMs).toISOString(),
  };
}

function uniqueLocalPath(candidate) {
  if (!fs.existsSync(candidate)) return candidate;
  const parsed = path.parse(candidate);
  let number = 2;
  while (true) {
    const next = path.join(parsed.dir, `${parsed.name}_${number}${parsed.ext}`);
    if (!fs.existsSync(next)) return next;
    number += 1;
  }
}

module.exports = { SshManager, modeString, editOptions };

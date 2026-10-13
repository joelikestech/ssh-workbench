"use strict";

const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const path = require("node:path");
const { Client } = require("ssh2");
const { KnownHosts, displayFingerprint } = require("./known-hosts");
const { remoteJoin, remoteParent, remotePath, safeRemoteName } = require("./remote-path");
const { buildMatcher } = require("./search-match");
const { normalizeProtocol } = require("./protocols");
const { SftpTransport } = require("./sftp-transport");
const { ShellTransport } = require("./shell-transport");

const SFTP_OPEN_TIMEOUT = 15000;

const SEARCH_LIMIT = 500;
const SEARCH_MILLISECONDS = 4000;
const SEARCH_CONCURRENCY = 12;
const MAX_PRIVATE_KEY_BYTES = 1024 * 1024;
const SEARCH_SKIP = new Set([".git", ".cache", ".venv", "venv", "node_modules", "__pycache__"]);
const UNIQUE_NAME_ATTEMPTS = 50;
const PLAN_CONCURRENCY = 8;
const UPLOAD_CHOICES = new Set(["overwrite", "skip", "keep-both"]);

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
  }

  get connected() {
    return Boolean(this.client && this.transport);
  }

  async connect(input) {
    await this.disconnect();
    this.closing = false;
    const targetConfig = this.#connectionConfig(input, "Target");
    const targetIdentity = `${targetConfig.host}:${targetConfig.port}`;
    const protocol = normalizeProtocol(input.protocol);
    let jumpInfo = null;

    try {
      if (input.jump?.enabled) {
        const jumpConfig = this.#connectionConfig(input.jump, "Jump host");
        const jumpIdentity = `${jumpConfig.host}:${jumpConfig.port}`;
        this.jumpClient = await this.#openClient(jumpConfig, jumpIdentity, "Jump host");
        const activeJumpClient = this.jumpClient;
        activeJumpClient.once("close", () => this.#handleUnexpectedClose("jump", activeJumpClient));
        this.jumpStream = await new Promise((resolve, reject) => {
          this.jumpClient.forwardOut(
            "127.0.0.1", 0, targetConfig.host, targetConfig.port,
            (error, stream) => error ? reject(error) : resolve(stream),
          );
        });
        targetConfig.sock = this.jumpStream;
        jumpInfo = { host: jumpConfig.host, port: jumpConfig.port, username: jumpConfig.username };
      }

      this.client = await this.#openClient(targetConfig, targetIdentity, "Destination host");
      const activeClient = this.client;
      activeClient.once("close", () => this.#handleUnexpectedClose("target", activeClient));
      const { transport, sftpError } = await this.#openTransport(protocol);
      this.transport = transport;
      // A disconnect can arrive while the handshake is still in flight — closing the
      // window that asked for this connection does exactly that. Everything opened
      // above is assigned by now, so honouring it here tears the whole thing down
      // instead of leaving a live connection nobody holds a reference to.
      if (this.closing) throw new Error("The connection was closed before it finished opening");
      const home = await this.#call("realpath", ".").catch(() => "/");
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
      const route = jumpInfo ? `${targetIdentity} through ${jumpInfo.host}:${jumpInfo.port}` : targetIdentity;
      const how = transport.kind === "scp"
        ? sftpError ? " over SCP; SFTP was unavailable" : " over SCP"
        : "";
      this.emit("status", { connected: true, message: `Connected to ${route}${how}`, protocol: transport.kind });
      return this.connection;
    } catch (error) {
      await this.disconnect();
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
    if (this.transport) {
      this.transport.close();
      this.transport = null;
    }
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

  async readFile(remoteFile, limit = 2 * 1024 * 1024) {
    this.#requireConnection();
    const target = remotePath(remoteFile);
    const attributes = await this.#call("stat", target);
    if (attributes.size > limit) throw new Error("File is too large to edit here");
    const data = await this.#call("readFile", target);
    if (data.includes(0)) throw new Error("Binary file cannot be edited as text");
    return data.toString("utf8");
  }

  async readBinary(remoteFile, limit = 20 * 1024 * 1024) {
    this.#requireConnection();
    const target = remotePath(remoteFile);
    const attributes = await this.#call("stat", target);
    if (attributes.size > limit) throw new Error("Image is too large to preview here");
    return this.#call("readFile", target);
  }

  async writeFile(remoteFile, contents) {
    this.#requireConnection();
    const target = remotePath(remoteFile);
    const buffer = Buffer.from(String(contents), "utf8");
    if (buffer.length > 2 * 1024 * 1024) throw new Error("File is too large to edit here");
    await this.#call("writeFile", target, buffer);
    return { ok: true };
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
      await this.#call("writeFile", target, data);
      return { path: target, name, bytes: data.length };
    }
    throw new Error("Could not find an unused name for the pasted image");
  }

  async mkdir(directory, name) {
    const target = remoteJoin(directory, name);
    await this.#call("mkdir", target);
    return { path: target };
  }

  async rename(remoteFile, name) {
    const source = remotePath(remoteFile);
    const target = remoteJoin(path.posix.dirname(source), name);
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

  async download(remotePaths, localDirectory, singleFilePath = null) {
    const downloaded = [];
    for (const [index, sourceValue] of remotePaths.entries()) {
      const source = remotePath(sourceValue);
      const destination = singleFilePath && remotePaths.length === 1
        ? singleFilePath
        : uniqueLocalPath(path.join(localDirectory, path.posix.basename(source) || `download-${index + 1}`));
      // Everything written for this item has to stay under the place it was asked to
      // go. Names are already checked as they are read; this is the second lock on
      // the same door, and it is the one that does not depend on getting that right.
      await this.#downloadTree(source, destination, new Set(), path.resolve(path.dirname(destination)));
      downloaded.push(destination);
    }
    return downloaded;
  }

  async startTerminal({ columns = 100, rows = 30 } = {}) {
    this.#requireConnection();
    if (this.terminal) this.terminal.end();
    this.terminal = await new Promise((resolve, reject) => {
      this.client.shell({ term: "xterm-256color", cols: columns, rows }, (error, stream) => {
        if (error) return reject(error);
        resolve(stream);
      });
    });
    this.terminal.on("data", (data) => this.emit("terminal-data", data.toString("utf8")));
    this.terminal.on("close", () => {
      this.terminal = null;
      this.emit("terminal-exit");
    });
    return { ok: true };
  }

  terminalInput(data) {
    if (this.terminal) this.terminal.write(String(data));
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

  async #openClient(config, identity, role) {
    const client = new Client();
    config.hostHash = "sha256";
    config.hostVerifier = (fingerprint, accept) => {
      const known = this.knownHosts.get(identity);
      if (known && known.sha256 === fingerprint) return accept(true);
      this.confirmHost({
        identity,
        role,
        fingerprint: displayFingerprint(fingerprint),
        previousFingerprint: known ? displayFingerprint(known.sha256) : null,
      }).then((decision) => {
        if (decision.remember) this.knownHosts.remember(identity, fingerprint);
        accept(Boolean(decision.accept));
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
      let given = false;
      client.on("keyboard-interactive", (_name, _instructions, _language, prompts, finish) => {
        const asksForOneSecret = !given && prompts.length === 1 && prompts[0]?.echo !== true;
        given = given || asksForOneSecret;
        finish(asksForOneSecret ? [config.password] : prompts.map(() => ""));
      });
    }
    try {
      await new Promise((resolve, reject) => {
        let settled = false;
        const fail = (error) => {
          if (!settled) {
            settled = true;
            reject(error);
          }
        };
        client.once("ready", () => { settled = true; resolve(); });
        client.once("error", fail);
        client.once("close", () => fail(new Error(`${role} connection closed during setup`)));
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
    if (this.transport) {
      this.transport.close();
      this.transport = null;
    }
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
      await this.#call("fastPut", localPath, remoteTarget);
    } else {
      throw new Error(`Unsupported local item: ${path.basename(localPath)}`);
    }
  }

  async #downloadTree(remoteSource, localTarget, ancestors = new Set(), boundary = null) {
    if (boundary) {
      const resolved = path.resolve(localTarget);
      const inside = resolved === boundary || resolved.startsWith(boundary + path.sep);
      if (!inside) {
        throw new Error(`The host offered a name that would write outside the chosen folder: ${path.basename(remoteSource)}`);
      }
    }
    // Writing through a shortcut that is already sitting there would put the file
    // wherever it points, which is not where this download was sent.
    const existing = fs.lstatSync(localTarget, { throwIfNoEntry: false });
    if (existing?.isSymbolicLink()) {
      throw new Error(`${path.basename(localTarget)} already exists here as a shortcut; nothing was written to it`);
    }
    const link = await this.#call("lstat", remoteSource);
    let directory = link.isDirectory() && !link.isSymbolicLink();
    let identity = remoteSource;
    if (link.isSymbolicLink()) {
      // A link to a directory is copied as that directory; a broken link or a
      // link to a file falls through to the single-file transfer below.
      directory = await this.#call("stat", remoteSource)
        .then((target) => target.isDirectory())
        .catch(() => false);
      if (directory) {
        identity = await this.#call("realpath", remoteSource).catch(() => remoteSource);
      }
    }
    if (directory) {
      if (ancestors.has(identity)) return;
      ancestors.add(identity);
      fs.mkdirSync(localTarget, { recursive: true });
      try {
        const { items } = await this.#readEntries(remoteSource, { strict: true });
        for (const child of items) {
          await this.#downloadTree(
            path.posix.join(remoteSource, child.filename),
            path.join(localTarget, child.filename),
            ancestors,
            boundary,
          );
        }
      } finally {
        ancestors.delete(identity);
      }
    } else {
      fs.mkdirSync(path.dirname(localTarget), { recursive: true });
      await this.#call("fastGet", remoteSource, localTarget);
    }
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

module.exports = { SshManager, modeString };

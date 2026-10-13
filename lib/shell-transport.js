"use strict";

// Everything the file pane does reaches the remote host through one narrow set of
// calls — the SFTP method names. This transport answers that same set over an
// ordinary shell and `scp`, so a host with the SFTP subsystem switched off can
// still be browsed and transferred to. It is the slower of the two: each call is
// its own exec channel and a round trip, and directory listings are parsed from
// `ls` output rather than read as structured attributes.

const fs = require("node:fs");
const path = require("node:path");

const COMMAND_TIMEOUT = 60000;
const MAX_COMMAND_OUTPUT = 32 * 1024 * 1024;
// OpenSSH allows ten channels per connection by default and the terminal holds one
// of them, so metadata reads stay well below that.
const CONCURRENT_READS = 4;

const MONTHS = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

const TYPE_BITS = {
  "-": 0o100000, d: 0o040000, l: 0o120000,
  b: 0o060000, c: 0o020000, p: 0o010000, s: 0o140000,
};

// `ls -n` keeps the owner and group numeric, which avoids the column ambiguity a
// user name containing a space would otherwise introduce. The size field carries
// "major, minor" for device nodes, hence the optional second number.
const GNU_LINE = /^([-bcdlps?])([-rwxsStT]{9})[.+@]*\s+\d+\s+\S+\s+\S+\s+(\d+)(?:,\s*\d+)?\s+(-?\d+)\s+(.*)$/;
const LEGACY_LINE = /^([-bcdlps?])([-rwxsStT]{9})[.+@]*\s+\d+\s+\S+\s+\S+\s+(\d+)(?:,\s*\d+)?\s+(\S+\s+\S+\s+\S+)\s+(.*)$/;

const OPERATIONS = new Set([
  "realpath", "stat", "lstat", "readdir", "readFile", "writeFile",
  "mkdir", "rmdir", "unlink", "rename", "fastPut", "fastGet",
]);

function quote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

// Quoting carries a name safely into a shell command, and there are two places in
// this transport where quoting is not what the name has to survive. A listing is
// read back a line at a time, and the scp header that announces a file is one line
// with the name on the end of it -- so a name holding a line ending cannot be told
// apart from the syntax around it in either direction.
//
// Reading such a name is impossible anyway; it never comes back out of `ls` whole.
// What matters is not creating one, because that leaves something on the host this
// transport can neither list nor reach afterwards. SFTP has no such limit and is not
// asked to pretend otherwise: this is the shell's problem and it is refused here.
function representable(target, action) {
  const name = path.posix.basename(String(target)) || String(target);
  if (/[\r\n]/.test(name)) {
    throw new Error(`${name.replace(/[\r\n]+/g, " ")} cannot be ${action} over SCP: its name contains a line break`);
  }
  return target;
}

function modeFromListing(type, flags) {
  let mode = TYPE_BITS[type] ?? 0o100000;
  const bits = [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001];
  for (let index = 0; index < 9; index += 1) {
    const flag = flags[index];
    // An upper-case s or t marks setuid, setgid, or sticky *without* the execute
    // bit; the lower-case form means both are set.
    if (flag !== "-" && flag !== "S" && flag !== "T") mode |= bits[index];
  }
  if (flags[2] === "s" || flags[2] === "S") mode |= 0o4000;
  if (flags[5] === "s" || flags[5] === "S") mode |= 0o2000;
  if (flags[8] === "t" || flags[8] === "T") mode |= 0o1000;
  return mode;
}

function makeAttributes(mode, size, mtime) {
  return {
    mode,
    size,
    mtime,
    atime: mtime,
    uid: 0,
    gid: 0,
    isDirectory: () => (mode & 0o170000) === 0o040000,
    isSymbolicLink: () => (mode & 0o170000) === 0o120000,
    isFile: () => (mode & 0o170000) === 0o100000,
  };
}

// `ls` prints a year instead of a clock time once a file is old enough, so a
// timestamp with a clock belongs to the last twelve months. This is the client's
// idea of those months rather than the server's, which is why the epoch format is
// asked for first and this is only the fallback.
function legacyTime(text, now = Date.now()) {
  const parts = String(text).trim().split(/\s+/);
  if (parts.length !== 3) return 0;
  const [monthName, dayText, last] = parts;
  const month = MONTHS[monthName];
  const day = Number(dayText);
  if (month === undefined || !Number.isInteger(day)) return 0;
  const reference = new Date(now);
  if (/^\d{4}$/.test(last)) {
    return Math.floor(new Date(Number(last), month, day).getTime() / 1000);
  }
  const clock = /^(\d{1,2}):(\d{2})/.exec(last);
  if (!clock) return 0;
  let year = reference.getFullYear();
  const at = (value) => new Date(value, month, day, Number(clock[1]), Number(clock[2])).getTime();
  // A day of slack: a file written moments ago on a host an hour ahead is still
  // this year, not last year.
  if (at(year) > now + 86400000) year -= 1;
  return Math.floor(at(year) / 1000);
}

// A name is whatever follows the timestamp, so it may contain spaces. A symlink
// line carries " -> target" after the name, which is removed. A name containing a
// literal " -> ", or a newline, cannot be told apart from that syntax; SFTP has no
// such ambiguity, which is one reason it is still preferred.
function parseListing(text, { epoch = true, now = Date.now() } = {}) {
  const entries = [];
  for (const line of String(text).split("\n")) {
    if (!line.trim() || /^total\s/.test(line)) continue;
    const match = (epoch ? GNU_LINE : LEGACY_LINE).exec(line);
    if (!match) continue;
    const [, type, flags, sizeText, timeText, rest] = match;
    let name = rest;
    if (type === "l") {
      const arrow = name.indexOf(" -> ");
      if (arrow >= 0) name = name.slice(0, arrow);
    }
    if (!name || name === "." || name === "..") continue;
    const mtime = epoch ? Number(timeText) : legacyTime(timeText, now);
    entries.push({
      filename: name,
      attrs: makeAttributes(modeFromListing(type, flags), Number(sizeText), Number.isFinite(mtime) ? mtime : 0),
    });
  }
  return entries;
}

function notFound(message) {
  const error = new Error(message);
  error.code = "ENOENT";
  return error;
}

function failure(action, stderr, code) {
  const text = String(stderr || "").split("\n").map((line) => line.trim()).filter(Boolean)[0] || "";
  const detail = text.replace(/^(?:ls|scp|cat|mv|rm|rmdir|mkdir|sh|bash):\s*/, "");
  if (/no such file|not found/i.test(detail) && code !== 127) return notFound(detail || `${action} failed`);
  const error = new Error(detail ? `${action}: ${detail}` : `${action} failed (exit ${code})`);
  if (code === 127) error.missingCommand = true;
  return error;
}

// Reads an exec channel a piece at a time. The SCP protocol is a conversation —
// send a header, wait for a single acknowledgement byte, send the bytes — so the
// stream has to be consumed on demand rather than collected.
class ChannelReader {
  constructor(stream) {
    this.buffer = Buffer.alloc(0);
    this.ended = false;
    this.failure = null;
    this.waiter = null;
    stream.on("data", (chunk) => {
      this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;
      this.#settle();
    });
    stream.once("close", () => { this.ended = true; this.#settle(); });
    stream.once("error", (error) => { this.failure = error; this.#settle(); });
  }

  #settle() {
    if (!this.waiter) return;
    const { want, resolve, reject } = this.waiter;
    if (this.failure) {
      this.waiter = null;
      reject(this.failure);
      return;
    }
    const taken = want(this.buffer);
    if (taken > 0) {
      const value = this.buffer.subarray(0, taken);
      this.buffer = this.buffer.subarray(taken);
      this.waiter = null;
      resolve(value);
      return;
    }
    if (this.ended) {
      this.waiter = null;
      reject(new Error("The remote command closed before it finished replying"));
    }
  }

  #take(want) {
    if (this.waiter) return Promise.reject(new Error("Two reads on one channel"));
    return new Promise((resolve, reject) => {
      this.waiter = { want, resolve, reject };
      this.#settle();
    });
  }

  bytes(count) {
    return this.#take((buffer) => (buffer.length >= count ? count : 0));
  }

  // Whatever has arrived, up to a ceiling: the body of a file is read this way so
  // that a large transfer moves in whole network reads rather than byte by byte.
  some(limit) {
    return this.#take((buffer) => Math.min(buffer.length, limit));
  }

  line() {
    return this.#take((buffer) => {
      const end = buffer.indexOf(0x0a);
      return end < 0 ? 0 : end + 1;
    }).then((value) => value.subarray(0, value.length - 1).toString("utf8"));
  }
}

class ShellTransport {
  constructor(client) {
    this.client = client;
    this.kind = "scp";
    this.concurrencyLimit = CONCURRENT_READS;
    this.epochListing = true;
    this.home = "/";
    this.closed = false;
  }

  // One exec settles the three things worth knowing before the pane opens: where
  // the shell starts, whether `ls` understands --time-style, and whether scp is
  // installed at all. A missing scp is worth saying plainly and immediately
  // rather than at the first transfer.
  async probe() {
    const script = [
      "LC_ALL=C ls -lAn --time-style=+%s -- . >/dev/null 2>&1 && echo listing=epoch || echo listing=legacy",
      "command -v scp >/dev/null 2>&1 && echo scp=yes || echo scp=no",
      "pwd",
    ].join("; ");
    const { code, stdout, stderr } = await this.#run(script, { timeout: 20000 });
    if (code !== 0 && !stdout.length) {
      throw new Error(`the remote shell could not be used${stderr ? `: ${stderr.split("\n")[0]}` : ""}`);
    }
    const lines = stdout.toString("utf8").split("\n").map((line) => line.trim()).filter(Boolean);
    this.epochListing = !lines.includes("listing=legacy");
    if (lines.includes("scp=no")) {
      throw new Error("scp is not installed on the destination host, and its SFTP subsystem is unavailable");
    }
    const workingDirectory = lines[lines.length - 1] || "";
    this.home = workingDirectory.startsWith("/") ? workingDirectory : "/";
    return { home: this.home, epochListing: this.epochListing };
  }

  call(method, args) {
    if (!OPERATIONS.has(method)) throw new Error(`${method} is not available in SCP mode`);
    return this[method](...args);
  }

  close() {
    this.closed = true;
  }

  /* ------------------------------------------- the SFTP method surface, in shell */

  async realpath(target) {
    if (!target || target === ".") return this.home;
    // `readlink -f` is the one-line answer where it exists; where it does not, the
    // path the caller gave is a better answer than an error, because realpath is
    // used to recognise a link that points back up a tree, not to reach the file.
    const stdout = await this.#run(`readlink -f -- ${quote(target)} 2>/dev/null || printf '%s\\n' ${quote(target)}`)
      .then((result) => result.stdout);
    return stdout.toString("utf8").split("\n")[0].trim() || String(target);
  }

  stat(target) {
    return this.#listingLine(target, true);
  }

  lstat(target) {
    return this.#listingLine(target, false);
  }

  async readdir(directory) {
    const style = this.epochListing ? " --time-style=+%s" : "";
    const stdout = await this.#expect("Listing the folder", `LC_ALL=C ls -lAn${style} -- ${quote(directory)}`);
    return parseListing(stdout.toString("utf8"), { epoch: this.epochListing });
  }

  async readFile(target) {
    const pieces = [];
    await this.#receive(target, { write: (chunk) => { pieces.push(chunk); } });
    return Buffer.concat(pieces);
  }

  writeFile(target, data) {
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");
    return this.#send(target, {
      size: buffer.length,
      mode: 0o644,
      produce: (write) => write(buffer),
    });
  }

  async mkdir(target) {
    await this.#expect("Creating the folder", `mkdir -- ${quote(representable(target, "created"))}`);
    return { ok: true };
  }

  async rmdir(target) {
    await this.#expect("Deleting the folder", `rmdir -- ${quote(target)}`);
    return { ok: true };
  }

  async unlink(target) {
    await this.#expect("Deleting the file", `rm -f -- ${quote(target)}`);
    return { ok: true };
  }

  async rename(source, target) {
    await this.#expect("Renaming", `mv -- ${quote(source)} ${quote(representable(target, "renamed to"))}`);
    return { ok: true };
  }

  async fastPut(localPath, remoteTarget) {
    const stats = fs.statSync(localPath);
    return this.#send(remoteTarget, {
      size: stats.size,
      mode: stats.mode & 0o777,
      // Awaiting each write is what applies backpressure: the next chunk is read
      // only once the previous one has been handed to the channel.
      produce: async (write) => {
        for await (const chunk of fs.createReadStream(localPath)) await write(chunk);
      },
    });
  }

  async fastGet(remoteSource, localPath) {
    const sink = fs.createWriteStream(localPath);
    try {
      await this.#receive(remoteSource, {
        write: (chunk) => new Promise((resolve, reject) => {
          sink.write(chunk, (error) => (error ? reject(error) : resolve()));
        }),
      });
    } catch (error) {
      sink.destroy();
      throw error;
    }
    await new Promise((resolve, reject) => {
      sink.once("error", reject);
      sink.end(resolve);
    });
    return { ok: true };
  }

  /* ------------------------------------------------------------------ internals */

  #open(command) {
    if (this.closed) return Promise.reject(new Error("Not connected to an SSH server"));
    return new Promise((resolve, reject) => {
      this.client.exec(command, (error, stream) => (error ? reject(error) : resolve(stream)));
    });
  }

  // Metadata commands are small: run to completion, keep both streams, and give up
  // after a while so a wedged host cannot hold the interface open for ever.
  async #run(command, { timeout = COMMAND_TIMEOUT } = {}) {
    const stream = await this.#open(command);
    return new Promise((resolve, reject) => {
      const out = [];
      const err = [];
      let size = 0;
      let code = null;
      let settled = false;
      const timer = timeout
        ? setTimeout(() => {
          if (settled) return;
          settled = true;
          try { stream.close(); } catch { /* already gone */ }
          reject(new Error("The remote command did not finish in time"));
        }, timeout)
        : null;
      const finish = (run) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        run();
      };
      stream.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_COMMAND_OUTPUT) {
          try { stream.close(); } catch { /* already gone */ }
          finish(() => reject(new Error("The remote command produced too much output")));
          return;
        }
        out.push(chunk);
      });
      stream.stderr.on("data", (chunk) => err.push(chunk));
      stream.once("exit", (value) => { code = value; });
      stream.once("close", () => finish(() => resolve({
        code: code === null ? 0 : code,
        stdout: Buffer.concat(out),
        stderr: Buffer.concat(err).toString("utf8"),
      })));
      stream.once("error", (error) => finish(() => reject(error)));
    });
  }

  async #expect(action, command, options) {
    const result = await this.#run(command, options);
    if (result.code !== 0) throw failure(action, result.stderr, result.code);
    return result.stdout;
  }

  async #listingLine(target, dereference) {
    const flags = `-ldn${dereference ? "L" : ""}`;
    const style = this.epochListing ? " --time-style=+%s" : "";
    const stdout = await this.#expect(
      "Reading the item",
      `LC_ALL=C ls ${flags}${style} -- ${quote(target)}`,
    );
    const line = stdout.toString("utf8").split("\n").find((value) => value.trim());
    const match = (this.epochListing ? GNU_LINE : LEGACY_LINE).exec(line || "");
    if (!match) throw new Error(`The listing for ${path.posix.basename(target) || target} could not be read`);
    const [, type, flagText, sizeText, timeText] = match;
    const mtime = this.epochListing ? Number(timeText) : legacyTime(timeText);
    return makeAttributes(modeFromListing(type, flagText), Number(sizeText), Number.isFinite(mtime) ? mtime : 0);
  }

  // The sink side of the protocol: announce one file, then send exactly the bytes
  // announced. `scp -t` is asked for the parent folder and the name travels in the
  // header, which is how the command-line client copies into a directory.
  async #send(remoteTarget, { produce, size, mode }) {
    const name = path.posix.basename(remoteTarget);
    if (!name) throw new Error("A file needs a name to be copied");
    representable(remoteTarget, "copied");
    const directory = path.posix.dirname(remoteTarget) || "/";
    const stream = await this.#open(`scp -t -- ${quote(directory)}`);
    const reader = new ChannelReader(stream);
    const errors = [];
    stream.stderr.on("data", (chunk) => errors.push(chunk));
    const stderr = () => Buffer.concat(errors).toString("utf8");
    const exit = new Promise((resolve) => {
      let code = null;
      stream.once("exit", (value) => { code = value; });
      stream.once("close", () => resolve(code === null ? 0 : code));
    });

    // The header announces a length and the protocol has no way to correct it, so a
    // file that changes size underneath the copy has to fail rather than write a
    // truncated or run-together file at the far end.
    let sent = 0;
    const write = (chunk) => new Promise((resolve, reject) => {
      if (sent + chunk.length > size) {
        reject(new Error(`${path.posix.basename(remoteTarget)} grew while it was being copied; try again`));
        return;
      }
      sent += chunk.length;
      stream.write(chunk, (error) => (error ? reject(error) : resolve()));
    });

    try {
      await this.#acknowledge(reader, stderr);
      stream.write(`C${(mode & 0o7777).toString(8).padStart(4, "0")} ${size} ${name}\n`);
      await this.#acknowledge(reader, stderr);
      await produce(write);
      if (sent !== size) {
        throw new Error(`${path.posix.basename(remoteTarget)} shrank while it was being copied; try again`);
      }
      stream.write(Buffer.from([0]));
      await this.#acknowledge(reader, stderr);
      stream.end();
      const code = await exit;
      if (code !== 0) throw failure("Copying to the host", stderr(), code);
    } catch (error) {
      try { stream.close(); } catch { /* already gone */ }
      throw error;
    }
    return { ok: true };
  }

  // The source side: ask for one file, read the header it offers, then read exactly
  // that many bytes. Anything other than a single file header is refused rather
  // than guessed at.
  async #receive(remoteSource, { write }) {
    const stream = await this.#open(`scp -f -- ${quote(remoteSource)}`);
    const reader = new ChannelReader(stream);
    const errors = [];
    stream.stderr.on("data", (chunk) => errors.push(chunk));
    const stderr = () => Buffer.concat(errors).toString("utf8");
    const exit = new Promise((resolve) => {
      let code = null;
      stream.once("exit", (value) => { code = value; });
      stream.once("close", () => resolve(code === null ? 0 : code));
    });

    try {
      stream.write(Buffer.from([0]));
      let header = await reader.line();
      // A timestamp record precedes the file when the far end was asked to keep
      // times; accept and step over it.
      while (header.startsWith("T")) {
        stream.write(Buffer.from([0]));
        header = await reader.line();
      }
      if (header.charCodeAt(0) === 1 || header.charCodeAt(0) === 2) {
        throw failure("Copying from the host", header.slice(1) || stderr(), 1);
      }
      const match = /^C([0-7]{3,5})\s+(\d+)\s+(.*)$/.exec(header);
      if (!match) {
        if (header.startsWith("D")) throw new Error("That item is a folder, not a file");
        throw new Error("The host answered scp with something unexpected");
      }
      const size = Number(match[2]);
      stream.write(Buffer.from([0]));
      let remaining = size;
      while (remaining > 0) {
        const piece = await reader.some(remaining);
        await write(piece);
        remaining -= piece.length;
      }
      const status = await reader.bytes(1);
      if (status[0] !== 0) {
        const message = await reader.line().catch(() => "");
        throw failure("Copying from the host", message || stderr(), 1);
      }
      stream.write(Buffer.from([0]));
      stream.end();
      const code = await exit;
      if (code !== 0) throw failure("Copying from the host", stderr(), code);
      return { ok: true };
    } catch (error) {
      try { stream.close(); } catch { /* already gone */ }
      throw error;
    }
  }

  async #acknowledge(reader, stderr) {
    const [byte] = await reader.bytes(1);
    if (byte === 0) return;
    const message = await reader.line().catch(() => "");
    throw failure("Copying to the host", message || stderr(), byte === 2 ? 2 : 1);
  }
}

module.exports = { ShellTransport, parseListing, quote, representable };

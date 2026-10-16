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
// How much of a file body may sit in memory ahead of the local disk. Past the high
// mark the channel is paused, which stops the SSH window being reopened, which stops
// the far end sending; below the low mark it flows again.
const READ_HIGH_WATER = 1024 * 1024;
const READ_LOW_WATER = 256 * 1024;
// An scp header or an acknowledgement line is a few dozen bytes. A far end that
// sends this much without a line ending is not speaking the protocol.
const MAX_LINE = 64 * 1024;

// Every command runs under /bin/sh whatever the login shell is. sshd hands the
// command line to the user's own shell, and csh, tcsh and fish do not read POSIX sh:
// fish treats a backslash inside single quotes as an escape, csh has its own idea of
// quoting altogether. So the login shell is given only this -- one pair of single
// quotes with no backslash and no quote inside it, which every one of them passes
// through unchanged -- and the real command line follows on standard input, where
// no login shell ever looks at it. POSIX requires `read` to stop at the newline
// rather than read ahead, so for scp everything after that line is still the
// protocol, untouched.
const WRAPPER = "exec /bin/sh -c 'IFS= read -r line && eval \"$line\"'";

const MONTHS = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

const TYPE_BITS = {
  "-": 0o100000, d: 0o040000, l: 0o120000,
  b: 0o060000, c: 0o020000, p: 0o010000, s: 0o140000,
};

// `ls -n` keeps the owner and group numeric, which avoids the column ambiguity a
// user name containing a space would otherwise introduce, and gives the ids an
// overwrite needs to keep a file's owner. The size field carries "major, minor" for
// device nodes, hence the optional second number.
//
// Exactly one space separates the time from the name. Anything more belongs to the
// name: " notes.txt" and "notes.txt" are two different files, and swallowing the
// space made an action on the first land on the second.
const GNU_LINE = /^([-bcdlps?])([-rwxsStT]{9})[.+@]*\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)(?:,\s*\d+)?\s+(-?\d+) (.*)$/;
const LEGACY_LINE = /^([-bcdlps?])([-rwxsStT]{9})[.+@]*\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)(?:,\s*\d+)?\s+(\S+\s+\S+\s+\S+) (.*)$/;

const OPERATIONS = new Set([
  "realpath", "stat", "lstat", "readdir", "readFile", "writeFile",
  "mkdir", "rmdir", "unlink", "rename", "fastPut", "fastGet",
  "readCapped", "replace", "setstat",
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

// The owner and group are numbers because the listing was asked for with -n; a
// listing that somehow printed names leaves them unknown rather than wrong.
function makeAttributes(mode, size, mtime, uid, gid) {
  const id = (text) => (/^\d+$/.test(String(text ?? "")) ? Number(text) : undefined);
  return {
    mode,
    size,
    mtime,
    atime: mtime,
    uid: id(uid),
    gid: id(gid),
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
    const [, type, flags, uid, gid, sizeText, timeText, rest] = match;
    let name = rest;
    if (type === "l") {
      const arrow = name.indexOf(" -> ");
      if (arrow >= 0) name = name.slice(0, arrow);
    }
    if (!name || name === "." || name === "..") continue;
    const mtime = epoch ? Number(timeText) : legacyTime(timeText, now);
    entries.push({
      filename: name,
      attrs: makeAttributes(modeFromListing(type, flags), Number(sizeText), Number.isFinite(mtime) ? mtime : 0, uid, gid),
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
  const detail = text.replace(/^(?:ls|scp|cat|mv|rm|rmdir|mkdir|chmod|chown|sh|bash):\s*/, "");
  if (/no such file|not found/i.test(detail) && code !== 127) return notFound(detail || `${action} failed`);
  const how = code === null ? "it was stopped before it finished" : `exit ${code}`;
  const error = new Error(detail ? `${action}: ${detail}` : `${action} failed (${how})`);
  if (code === 127) error.missingCommand = true;
  return error;
}

// A file larger than the caller is prepared to hold. The manager turns this into
// its own wording, which differs between the editor and the image preview.
function tooLarge(limit) {
  const error = new Error(`The file is larger than ${limit} bytes`);
  error.tooLarge = true;
  return error;
}

// GNU ls exits 1 for a "minor problem", and the commonest one is an entry that
// vanished between reading the folder and describing it -- in /proc, a spool or a
// log directory that is every other listing. What it did print is still the folder.
// A folder that could not be read at all prints nothing on standard output (not even
// the "total" line), and that is still a failure.
function partialListing(result) {
  if (result.code !== 1 || !result.stdout.length) return false;
  const complaints = result.stderr.split("\n").map((line) => line.trim()).filter(Boolean);
  return complaints.every((line) => /cannot access|no such file or directory/i.test(line));
}

// Reads an exec channel a piece at a time. The SCP protocol is a conversation —
// send a header, wait for a single acknowledgement byte, send the bytes — so the
// stream has to be consumed on demand rather than collected.
//
// What has arrived is kept as the list of chunks it came in, not one buffer grown
// by concatenation on every read: that copied the whole backlog each time. And the
// backlog is bounded. A local disk slower than the network -- a USB stick, a share
// -- used to let an entire download pile up in memory; past the high-water mark the
// channel is paused, so ssh2 stops reopening the window and the far end waits.
class ChannelReader {
  constructor(stream) {
    this.stream = stream;
    this.chunks = [];
    this.length = 0;
    this.paused = false;
    this.ended = false;
    this.failure = null;
    this.waiter = null;
    stream.on("data", (chunk) => {
      if (!chunk.length) return;
      this.chunks.push(chunk);
      this.length += chunk.length;
      if (!this.paused && this.length >= READ_HIGH_WATER) {
        this.paused = true;
        stream.pause();
      }
      this.#settle();
    });
    stream.once("close", () => { this.ended = true; this.#settle(); });
    stream.once("error", (error) => { this.failure = error; this.#settle(); });
  }

  // Removes and returns the first `count` bytes. A read that fits in the first chunk
  // is a view of it rather than a copy, which is what a file body almost always is.
  #consume(count) {
    let value;
    const first = this.chunks[0];
    if (first.length >= count) {
      value = first.subarray(0, count);
      if (first.length === count) this.chunks.shift();
      else this.chunks[0] = first.subarray(count);
    } else {
      const parts = [];
      let needed = count;
      while (needed > 0) {
        const chunk = this.chunks[0];
        if (chunk.length <= needed) {
          parts.push(chunk);
          this.chunks.shift();
          needed -= chunk.length;
        } else {
          parts.push(chunk.subarray(0, needed));
          this.chunks[0] = chunk.subarray(needed);
          needed = 0;
        }
      }
      value = Buffer.concat(parts, count);
    }
    this.length -= count;
    if (this.paused && this.length <= READ_LOW_WATER) {
      this.paused = false;
      this.stream.resume();
    }
    return value;
  }

  #settle() {
    if (!this.waiter) return;
    const { want, resolve, reject } = this.waiter;
    if (this.failure) {
      this.waiter = null;
      reject(this.failure);
      return;
    }
    let taken;
    try {
      taken = this.length ? want() : 0;
    } catch (error) {
      this.waiter = null;
      reject(error);
      return;
    }
    if (taken > 0) {
      this.waiter = null;
      resolve(this.#consume(taken));
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
    return this.#take(() => (this.length >= count ? count : 0));
  }

  // Whatever has arrived, up to a ceiling: the body of a file is read this way so
  // that a large transfer moves in whole network reads rather than byte by byte.
  // Only the first chunk is offered, so nothing is copied to answer it.
  some(limit) {
    return this.#take(() => Math.min(this.chunks[0].length, limit));
  }

  line() {
    return this.#take(() => {
      let offset = 0;
      for (const chunk of this.chunks) {
        const end = chunk.indexOf(0x0a);
        if (end >= 0) return offset + end + 1;
        offset += chunk.length;
        if (offset > MAX_LINE) throw new Error("The host answered scp with something unexpected");
      }
      return 0;
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
    // Whether command lines travel to /bin/sh on standard input (see WRAPPER). The
    // probe settles it: a host whose login "shell" lets only named commands through
    // -- a ForceCommand wrapper, rssh -- refuses `exec /bin/sh` but may still run
    // the commands themselves, and is then spoken to the way it always was.
    this.wrapped = true;
    // Whether the host reports an exit status at all. OpenSSH always does, and then
    // a command that ends without one -- killed by a signal, its channel torn down
    // -- has not succeeded: a listing cut short is not a complete listing. A host
    // that never reports one is recognised by the probe, and its silence is taken as
    // success there, since nothing else could ever be.
    this.reportsExit = true;
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
    const attempt = async () => {
      try {
        const result = await this.#run(script, { timeout: 20000 });
        const text = result.stdout.toString("utf8");
        if (/listing=/.test(text) && /scp=/.test(text)) return { result };
        return { reason: result.stderr.split("\n").find((line) => line.trim()) || "" };
      } catch (error) {
        return { reason: error.message };
      }
    };
    let outcome = await attempt();
    if (!outcome.result) {
      this.wrapped = false;
      const bare = await attempt();
      if (!bare.result) {
        this.wrapped = true;
        throw new Error(`the remote shell could not be used${outcome.reason ? `: ${outcome.reason}` : ""}`);
      }
      outcome = bare;
    }
    const { result } = outcome;
    if (result.code === null && !result.signal) this.reportsExit = false;
    const lines = result.stdout.toString("utf8").split("\n").map((line) => line.trim()).filter(Boolean);
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

  // What a path really is, links resolved. It is used to recognise a link that
  // points back up a tree, or out of it, so an answer that is merely the path given
  // back would defeat exactly the check that asked. `readlink -f` is the one-line
  // answer where it exists; old macOS and some BusyBox builds lack it, and for a
  // folder `cd -P` and `pwd -P` are POSIX and say the same. Failing both is a
  // failure, not a guess.
  async realpath(target) {
    if (!target || target === ".") return this.home;
    const quoted = quote(target);
    const result = await this.#run(`readlink -f -- ${quoted} 2>/dev/null || (cd -P -- ${quoted} 2>/dev/null && pwd -P)`);
    const resolved = result.stdout.toString("utf8").split("\n")[0];
    if (!this.#succeeded(result) || !resolved.startsWith("/")) {
      throw notFound(`${path.posix.basename(String(target)) || target} could not be resolved`);
    }
    return resolved;
  }

  stat(target) {
    return this.#listingLine(target, true);
  }

  lstat(target) {
    return this.#listingLine(target, false);
  }

  // The trailing slash matters. `ls -l link` describes the link itself, so a linked
  // folder opened empty and could not be downloaded; `ls -l link/` lists what it
  // points at, exactly as SFTP's opendir does. It also stops a file being "listed" as
  // a folder holding itself.
  async readdir(directory) {
    const style = this.epochListing ? " --time-style=+%s" : "";
    const listed = String(directory).endsWith("/") ? String(directory) : `${directory}/`;
    const result = await this.#run(`LC_ALL=C ls -lAn${style} -- ${quote(listed)}`);
    if (!this.#succeeded(result) && !partialListing(result)) {
      throw failure("Listing the folder", result.stderr, result.code);
    }
    return parseListing(result.stdout.toString("utf8"), { epoch: this.epochListing });
  }

  async readFile(target) {
    const pieces = [];
    await this.#receive(target, { write: (chunk) => { pieces.push(chunk); } });
    return Buffer.concat(pieces);
  }

  // A read that refuses, from the scp header and before any of the body has moved,
  // a file larger than `limit`. The size in the header is what scp is about to
  // send, so this is a cap on the bytes rather than on what a listing claimed.
  async readCapped(target, limit) {
    const pieces = [];
    await this.#receive(target, { limit, write: (chunk) => { pieces.push(chunk); } });
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

  // `mv` onto a file that exists replaces it, and onto a folder that exists moves
  // the item inside it -- while the pane reports the new name. SFTP refuses both,
  // and so does this. The test and the move are two steps, so a name that appears
  // in the instant between them can still be overwritten; `mv -n` would close that
  // but is not POSIX, and `mv -T` (which stops the move-inside) is GNU only. The
  // manager has looked before asking, so this is the second check, not the first.
  async rename(source, target) {
    const to = quote(representable(target, "renamed to"));
    const result = await this.#run(`test ! -e ${to} && test ! -h ${to} && mv -- ${quote(source)} ${to}`);
    if (this.#succeeded(result)) return { ok: true };
    if (result.code === 1 && !result.stderr.trim()) {
      const error = new Error(`Renaming: something named ${path.posix.basename(String(target))} is already there`);
      error.code = "EEXIST";
      throw error;
    }
    throw failure("Renaming", result.stderr, result.code);
  }

  // The last step of an overwrite: the finished temporary copy takes the name in one
  // rename, so the name always holds either the old file or the whole new one. Over a
  // folder `mv` would move the file inside instead, which the test refuses.
  async replace(source, target) {
    const to = quote(target);
    await this.#expect("Replacing the file", `test ! -d ${to} && mv -f -- ${quote(source)} ${to}`);
    return { ok: true };
  }

  // The subset of SFTP's setstat an overwrite needs: the owner and group first,
  // because changing the owner clears the setuid and setgid bits, then the mode.
  async setstat(target, { mode, uid, gid } = {}) {
    const quoted = quote(target);
    const steps = [];
    if (Number.isInteger(uid) && Number.isInteger(gid)) steps.push(`chown -- ${uid}:${gid} ${quoted}`);
    if (Number.isInteger(mode)) steps.push(`chmod -- ${(mode & 0o7777).toString(8)} ${quoted}`);
    if (steps.length) await this.#expect("Setting permissions", steps.join(" && "));
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
    // A local failure -- a read-only folder, a full disk, a file another program
    // holds open -- arrives as an event, and the stream raises it while opening,
    // before any byte has come over. With no listener that is an uncaught exception,
    // and in the main process that is every window, not one download. It is caught
    // from the start and becomes this download's failure.
    let localError = null;
    const failed = new Promise((_resolve, reject) => {
      sink.once("error", (error) => { localError = error; reject(error); });
    });
    failed.catch(() => undefined);
    try {
      await this.#receive(remoteSource, {
        write: (chunk) => Promise.race([failed, new Promise((resolve, reject) => {
          sink.write(chunk, (error) => (error ? reject(error) : resolve()));
        })]),
      });
      await Promise.race([failed, new Promise((resolve) => sink.end(resolve))]);
    } catch (error) {
      sink.destroy();
      throw localError || error;
    }
    return { ok: true };
  }

  /* ------------------------------------------------------------------ internals */

  async #open(command) {
    if (this.closed) throw new Error("Not connected to an SSH server");
    // `read` takes one line, so a line break inside the command would cut it in
    // two. Names holding one cannot come out of a listing whole in any case.
    if (this.wrapped && command.includes("\n")) {
      throw new Error("That item cannot be reached over SCP: its name contains a line break");
    }
    const stream = await new Promise((resolve, reject) => {
      this.client.exec(this.wrapped ? WRAPPER : command, (error, channel) => (error ? reject(error) : resolve(channel)));
    });
    if (this.wrapped) stream.write(`${command}\n`);
    return stream;
  }

  // What the far end said about how the command ended. ssh2 reports an exit status
  // as `exit(code)` and a signal as `exit(null, name)`; a channel closed without
  // either leaves both unset.
  #exitOf(stream) {
    return new Promise((resolve) => {
      let code = null;
      let signal = null;
      stream.once("exit", (value, signalName) => {
        code = value ?? null;
        signal = signalName ?? null;
      });
      stream.once("close", () => resolve({ code, signal }));
    });
  }

  #succeeded({ code, signal }) {
    return code === 0 || (code === null && !signal && !this.reportsExit);
  }

  // Metadata commands are small: run to completion, keep both streams, and give up
  // after a while so a wedged host cannot hold the interface open for ever.
  async #run(command, { timeout = COMMAND_TIMEOUT } = {}) {
    const stream = await this.#open(command);
    // Nothing more is sent, so a command that reads its input finds it empty rather
    // than waiting on it.
    stream.end();
    const ended = this.#exitOf(stream);
    return new Promise((resolve, reject) => {
      const out = [];
      const err = [];
      let size = 0;
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
      ended.then(({ code, signal }) => finish(() => resolve({
        code,
        signal,
        stdout: Buffer.concat(out),
        stderr: Buffer.concat(err).toString("utf8"),
      })));
      stream.once("error", (error) => finish(() => reject(error)));
    });
  }

  async #expect(action, command, options) {
    const result = await this.#run(command, options);
    if (!this.#succeeded(result)) throw failure(action, result.stderr, result.code);
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
    const [, type, flagText, uid, gid, sizeText, timeText] = match;
    const mtime = this.epochListing ? Number(timeText) : legacyTime(timeText);
    return makeAttributes(modeFromListing(type, flagText), Number(sizeText), Number.isFinite(mtime) ? mtime : 0, uid, gid);
  }

  // A promise that fails when the channel goes away. A write waiting on a channel
  // whose connection has dropped is never called back, so every wait in a transfer
  // also races this; otherwise the transfer stays pending for ever, and with it the
  // manager's count of work in progress, which a later switch of user waits on.
  #lost(stream) {
    const lost = new Promise((_resolve, reject) => {
      stream.once("close", () => reject(new Error("The connection closed before the copy finished")));
      stream.once("error", (error) => reject(error));
    });
    lost.catch(() => undefined);
    return lost;
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
    const exit = this.#exitOf(stream);
    const lost = this.#lost(stream);

    // The header announces a length and the protocol has no way to correct it, so a
    // file that changes size underneath the copy has to fail rather than write a
    // truncated or run-together file at the far end.
    let sent = 0;
    const write = (chunk) => {
      if (sent + chunk.length > size) {
        return Promise.reject(new Error(`${path.posix.basename(remoteTarget)} grew while it was being copied; try again`));
      }
      sent += chunk.length;
      return Promise.race([lost, new Promise((resolve, reject) => {
        stream.write(chunk, (error) => (error ? reject(error) : resolve()));
      })]);
    };

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
      const ended = await exit;
      if (!this.#succeeded(ended)) throw failure("Copying to the host", stderr(), ended.code);
    } catch (error) {
      try { stream.close(); } catch { /* already gone */ }
      throw error;
    }
    return { ok: true };
  }

  // The source side: ask for one file, read the header it offers, then read exactly
  // that many bytes. Anything other than a single file header is refused rather
  // than guessed at. `limit`, when given, refuses a larger file from its header.
  async #receive(remoteSource, { write, limit }) {
    const stream = await this.#open(`scp -f -- ${quote(remoteSource)}`);
    const reader = new ChannelReader(stream);
    const errors = [];
    stream.stderr.on("data", (chunk) => errors.push(chunk));
    const stderr = () => Buffer.concat(errors).toString("utf8");
    const exit = this.#exitOf(stream);
    const lost = this.#lost(stream);

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
      if (limit !== undefined && size > limit) throw tooLarge(limit);
      stream.write(Buffer.from([0]));
      let remaining = size;
      while (remaining > 0) {
        const piece = await reader.some(remaining);
        await Promise.race([lost, write(piece)]);
        remaining -= piece.length;
      }
      const status = await reader.bytes(1);
      if (status[0] !== 0) {
        const message = await reader.line().catch(() => "");
        throw failure("Copying from the host", message || stderr(), 1);
      }
      stream.write(Buffer.from([0]));
      stream.end();
      const ended = await exit;
      if (!this.#succeeded(ended)) throw failure("Copying from the host", stderr(), ended.code);
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

module.exports = { ShellTransport, parseListing, quote, representable, WRAPPER };

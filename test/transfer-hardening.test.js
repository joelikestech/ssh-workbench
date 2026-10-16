"use strict";

// Regression tests for the 0.12.0 transport and transfer audit: what happens to a
// transfer that fails part way, to names and files that are not what they seem, to
// the editor's bytes, and to the shell transport when the host misbehaves.
//
// Three kinds of server are used. The in-process mock (test/helpers) is fast and
// covers both transports. A scripted stand-in for ssh2's client drives the shell
// transport through failures no real server produces on demand -- a channel that
// dies mid-write, an exit status that never comes. And a real unprivileged OpenSSH
// covers what only the real tools can show: a named pipe that blocks sftp-server, a
// device that never ends, posix-rename.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const { execFileSync } = require("node:child_process");
const { SshManager, editOptions } = require("../lib/ssh-manager");
const { ShellTransport, parseListing, WRAPPER } = require("../lib/shell-transport");
const { localName, safeRemoteName, temporaryName } = require("../lib/remote-path");
const { startTestServer } = require("./helpers/ssh-test-server");
const { withRealServer, unavailable, sftpUnavailable } = require("./helpers/real-sshd");

function temporaryDirectory(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `ssh-workbench-${label}-`));
}

// Both transports against the mock server: "sftp", and "scp" with the subsystem
// refused, which is the configuration SCP mode exists for.
async function withMock(protocol, run, serverOptions = {}) {
  const remoteRoot = temporaryDirectory("hardening-remote");
  const localRoot = temporaryDirectory("hardening-local");
  const server = await startTestServer({ root: remoteRoot, refuseSftp: protocol === "scp", ...serverOptions });
  const manager = new SshManager({
    knownHostsPath: path.join(localRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  try {
    await manager.connect({
      host: server.host,
      port: server.port,
      username: server.username,
      authType: "password",
      password: server.password,
      protocol: protocol === "scp" ? "scp" : "sftp",
    });
    return await run({ manager, server, remoteRoot, localRoot });
  } finally {
    await manager.disconnect();
    await server.close();
    try { execFileSync("chmod", ["-R", "u+rwx", remoteRoot, localRoot]); } catch { /* best effort */ }
    fs.rmSync(remoteRoot, { recursive: true, force: true });
    fs.rmSync(localRoot, { recursive: true, force: true });
  }
}

const BOTH = ["sftp", "scp"];

// Nothing that a transfer writes on the way should be left behind beside the real
// names, on either side.
function leftovers(directory) {
  return fs.readdirSync(directory).filter((name) => /\.swb-[0-9a-f]{8}\.(part|old)$/.test(name));
}

/* ------------------------------------------- a scripted stand-in for ssh2's client */

// One exec channel. The test decides what the far end says; `written` is what the
// transport sent on standard input after the wrapped command line.
class FakeChannel extends EventEmitter {
  constructor({ holdWrites = false } = {}) {
    super();
    this.stderr = new EventEmitter();
    this.input = Buffer.alloc(0);
    this.holdWrites = holdWrites;
    this.paused = false;
    this.pauses = 0;
    this.closed = false;
  }

  write(data, callback) {
    const chunk = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
    this.input = Buffer.concat([this.input, chunk]);
    this.emit("input", chunk);
    // A write on a channel whose connection has gone is never called back by ssh2.
    if (callback && !this.holdWrites) setImmediate(callback);
    return true;
  }

  end() { this.emit("input-end"); }
  pause() { this.paused = true; this.pauses += 1; this.emit("paused"); }
  resume() { this.paused = false; this.emit("resumed"); }

  close() {
    if (this.closed) return;
    this.closed = true;
    setImmediate(() => this.emit("close"));
  }

  // A whole reply to a metadata command.
  reply({ stdout = "", stderr = "", code = 0, signal = null, noExit = false } = {}) {
    setImmediate(() => {
      if (stdout) this.emit("data", Buffer.from(stdout));
      if (stderr) this.stderr.emit("data", Buffer.from(stderr));
      if (!noExit) {
        if (signal) this.emit("exit", null, signal);
        else this.emit("exit", code);
      }
      this.close();
    });
  }
}

// `respond(command, channel, wrapped)` is called once the transport's command line
// is known: straight away for a bare exec, or once the first line has arrived on
// standard input behind the wrapper.
function fakeClient(respond) {
  const execs = [];
  const client = {
    execs,
    exec(command, callback) {
      const channel = new FakeChannel();
      execs.push(command);
      setImmediate(() => {
        callback(null, channel);
        if (command !== WRAPPER) {
          respond(command, channel, false);
          return;
        }
        const waitForLine = () => {
          const end = channel.input.indexOf(0x0a);
          if (end < 0) return;
          channel.removeListener("input", waitForLine);
          const line = channel.input.subarray(0, end).toString("utf8");
          channel.input = channel.input.subarray(end + 1);
          respond(line, channel, true);
        };
        channel.on("input", waitForLine);
        waitForLine();
      });
    },
  };
  return client;
}

const PROBE_REPLY = "listing=epoch\nscp=yes\n/home/someone\n";

/* -------------------------------------------------------- the shell transport */

test("SCP commands reach /bin/sh on standard input, past any login shell", async () => {
  const seen = [];
  const client = fakeClient((line, channel, wrapped) => {
    seen.push({ line, wrapped });
    if (line.includes("listing=")) return channel.reply({ stdout: PROBE_REPLY });
    return channel.reply({ stdout: "total 0\n" });
  });
  const transport = new ShellTransport(client);
  await transport.probe();
  await transport.readdir("/srv/it's a \"quoted\" \\ name");
  assert.ok(client.execs.every((command) => command === WRAPPER),
    "the login shell only ever sees the fixed wrapper");
  assert.doesNotMatch(WRAPPER.slice(WRAPPER.indexOf("'") + 1, WRAPPER.lastIndexOf("'")), /['\\]/,
    "which has no quote or backslash inside its quotes, so csh and fish leave it alone");
  assert.ok(seen.every((entry) => entry.wrapped));
  assert.match(seen[1].line, /^LC_ALL=C ls -lAn --time-style=\+%s -- '\/srv\/it'\\''s a "quoted" \\ name\/'$/);
});

test("a host that refuses /bin/sh is still spoken to the way it always was", async () => {
  await withMock("scp", async ({ manager, server, remoteRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "plain.txt"), "plain");
    const listing = await manager.list(remoteRoot);
    assert.deepEqual(listing.entries.map((entry) => entry.name), ["plain.txt"]);
    assert.equal(manager.transport.wrapped, false, "the probe fell back to bare commands");
    assert.ok(server.commands().some((command) => command.startsWith("LC_ALL=C ls")));
  }, { wrapper: false });
});

test("a command that ends without an exit status has not succeeded", async () => {
  const replies = [];
  const client = fakeClient((line, channel) => {
    if (line.includes("listing=")) return channel.reply({ stdout: PROBE_REPLY });
    return channel.reply(replies.shift());
  });
  const transport = new ShellTransport(client);
  await transport.probe();
  replies.push({ stdout: "total 0\n-rw-r--r-- 1 0 0 1 1700000000 half\n", signal: "KILL" });
  await assert.rejects(() => transport.readdir("/var/log"), /stopped before it finished/,
    "a listing cut short by a signal is not a complete listing");
  replies.push({ stdout: "total 0\n", noExit: true });
  await assert.rejects(() => transport.readdir("/var/log"), /stopped before it finished/,
    "and neither is one whose channel closed with no status at all");
});

test("a host that never reports exit statuses is recognised and still works", async () => {
  const client = fakeClient((line, channel) => {
    if (line.includes("listing=")) return channel.reply({ stdout: PROBE_REPLY, noExit: true });
    return channel.reply({ stdout: "total 0\n-rw-r--r-- 1 0 0 1 1700000000 kept\n", noExit: true });
  });
  const transport = new ShellTransport(client);
  await transport.probe();
  assert.equal(transport.reportsExit, false);
  assert.deepEqual((await transport.readdir("/srv")).map((entry) => entry.filename), ["kept"]);
});

test("a listing is kept when an entry vanished while ls was reading it", async () => {
  const replies = [];
  const client = fakeClient((line, channel) => {
    if (line.includes("listing=")) return channel.reply({ stdout: PROBE_REPLY });
    return channel.reply(replies.shift());
  });
  const transport = new ShellTransport(client);
  await transport.probe();
  replies.push({
    stdout: "total 0\ndr-xr-xr-x 9 0 0 0 1700000000 1\ndr-xr-xr-x 9 0 0 0 1700000000 self\n",
    stderr: "ls: cannot access '/proc/4242': No such file or directory\n",
    code: 1,
  });
  assert.deepEqual((await transport.readdir("/proc")).map((entry) => entry.filename), ["1", "self"]);
  replies.push({ stderr: "ls: cannot open directory '/root/': Permission denied\n", code: 2 });
  await assert.rejects(() => transport.readdir("/root"), /Permission denied/,
    "a folder that could not be read at all is still a failure");
  replies.push({ stdout: "total 0\n", stderr: "ls: reading directory '/mnt/': Input/output error\n", code: 1 });
  await assert.rejects(() => transport.readdir("/mnt"), /Input\/output error/,
    "and so is one whose reading broke off for another reason");
});

test("realpath fails rather than handing back the path it was given", async () => {
  const client = fakeClient((line, channel) => {
    if (line.includes("listing=")) return channel.reply({ stdout: PROBE_REPLY });
    return channel.reply({ code: 127, stderr: "sh: readlink: not found\n" });
  });
  const transport = new ShellTransport(client);
  await transport.probe();
  await assert.rejects(() => transport.realpath("/srv/loop"), (error) => error.code === "ENOENT");
});

test("an SCP upload settles when the connection drops part way", async () => {
  let channelOfCopy = null;
  const client = fakeClient((line, channel) => {
    if (line.includes("listing=")) return channel.reply({ stdout: PROBE_REPLY });
    channelOfCopy = channel;
    channel.holdWrites = false;
    channel.write = function write(data, callback) {
      FakeChannel.prototype.write.call(this, data, null);
      const text = Buffer.isBuffer(data) ? data.toString("latin1") : String(data);
      if (text.startsWith("C")) {
        setImmediate(() => this.emit("data", Buffer.from([0])));
        return true;
      }
      // Body bytes: the first is taken, and then the network goes away, so the
      // second write is never called back.
      if (this.input.length > 64 && !this.dropped) {
        this.dropped = true;
        setTimeout(() => { this.closed = true; this.emit("close"); }, 20);
        return false;
      }
      if (callback) setImmediate(callback);
      return true;
    };
    setImmediate(() => channel.emit("data", Buffer.from([0])));
    return undefined;
  });
  const transport = new ShellTransport(client);
  await transport.probe();
  const localRoot = temporaryDirectory("hardening-drop");
  try {
    const source = path.join(localRoot, "archive.bin");
    fs.writeFileSync(source, Buffer.alloc(4 * 1024 * 1024, 7));
    const outcome = await Promise.race([
      transport.fastPut(source, "/srv/archive.bin").then(() => "finished", (error) => error.message),
      new Promise((resolve) => setTimeout(() => resolve("still pending"), 5000)),
    ]);
    assert.ok(channelOfCopy);
    assert.match(outcome, /connection closed/i, `the upload failed rather than hanging: ${outcome}`);
  } finally {
    fs.rmSync(localRoot, { recursive: true, force: true });
  }
});

test("an SCP download holds only a bounded backlog ahead of a slow disk", async () => {
  const total = 8 * 1024 * 1024;
  const chunk = 64 * 1024;
  let largestBurst = 0;
  let channelOfCopy = null;
  const client = fakeClient((line, channel) => {
    if (line.includes("listing=")) return channel.reply({ stdout: PROBE_REPLY });
    channelOfCopy = channel;
    let stage = 0;
    let sent = 0;
    // Sends as fast as the transport lets it: everything until it pauses the channel.
    const pump = () => {
      let burst = 0;
      while (!channel.paused && sent < total) {
        channel.emit("data", Buffer.alloc(chunk, sent / chunk));
        sent += chunk;
        burst += chunk;
      }
      largestBurst = Math.max(largestBurst, burst);
      if (sent >= total) channel.emit("data", Buffer.from([0]));
    };
    channel.on("resumed", () => setImmediate(pump));
    channel.on("input", () => {
      stage += 1;
      if (stage === 1) channel.emit("data", Buffer.from(`C0644 ${total} disk.img\n`));
      else if (stage === 2) setImmediate(pump);
      else { channel.emit("exit", 0); channel.close(); }
    });
    if (channel.input.length) channel.emit("input", channel.input);
    return undefined;
  });
  const transport = new ShellTransport(client);
  await transport.probe();
  const localRoot = temporaryDirectory("hardening-slow");
  try {
    const target = path.join(localRoot, "disk.img");
    await transport.fastGet("/srv/disk.img", target);
    assert.ok(channelOfCopy.pauses > 0, "the channel was paused while the disk caught up");
    assert.ok(largestBurst <= 2 * 1024 * 1024, `at most about a megabyte ran ahead (${largestBurst} bytes)`);
    const written = fs.readFileSync(target);
    assert.equal(written.length, total);
    assert.equal(written[total - 1], total / chunk - 1, "and every byte arrived, in order");
  } finally {
    fs.rmSync(localRoot, { recursive: true, force: true });
  }
});

test("a name with a leading space is its own file in SCP mode", async () => {
  const parsed = parseListing("total 8\n-rw-r--r-- 1 1000 1000 5 1700000000  notes.txt\n-rw-r--r-- 1 1000 1000 5 1700000000 notes.txt\n");
  assert.deepEqual(parsed.map((entry) => entry.filename), [" notes.txt", "notes.txt"]);
  await withMock("scp", async ({ manager, remoteRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, " notes.txt"), "leading space\n");
    fs.writeFileSync(path.join(remoteRoot, "notes.txt"), "keep me\n");
    const listing = await manager.list(remoteRoot);
    const spaced = listing.entries.find((entry) => entry.name === " notes.txt");
    assert.ok(spaced, "the leading space survives the listing");
    await manager.delete([spaced.path]);
    assert.equal(fs.readFileSync(path.join(remoteRoot, "notes.txt"), "utf8"), "keep me\n",
      "and deleting it leaves the other file alone");
    assert.equal(fs.existsSync(path.join(remoteRoot, " notes.txt")), false);
  });
});

test("a symlinked folder opens and downloads in SCP mode", async () => {
  await withMock("scp", async ({ manager, remoteRoot, localRoot }) => {
    fs.mkdirSync(path.join(remoteRoot, "real-folder"));
    fs.writeFileSync(path.join(remoteRoot, "real-folder", "inside.txt"), "hello\n");
    fs.symlinkSync(path.join(remoteRoot, "real-folder"), path.join(remoteRoot, "linked-folder"));
    const listing = await manager.list(path.posix.join(remoteRoot, "linked-folder"));
    assert.deepEqual(listing.entries.map((entry) => entry.name), ["inside.txt"]);
    const [saved] = await manager.download([path.posix.join(remoteRoot, "linked-folder")], localRoot);
    assert.equal(fs.readFileSync(path.join(saved, "inside.txt"), "utf8"), "hello\n");
  });
});

test("an SCP download into a folder that cannot be written fails cleanly", async () => {
  await withMock("scp", async ({ manager, remoteRoot, localRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "report.pdf"), "pdf");
    const locked = path.join(localRoot, "read-only");
    fs.mkdirSync(locked);
    fs.chmodSync(locked, 0o555);
    if (process.getuid?.() === 0) return; // root writes anyway; nothing to check
    await assert.rejects(
      () => manager.download([path.posix.join(remoteRoot, "report.pdf")], locked),
      (error) => /EACCES|permission/i.test(error.message) && !/\.swb-/.test(error.message),
    );
  });
});

/* ------------------------------------------------------------ renaming */

for (const protocol of BOTH) {
  test(`${protocol}: renaming never replaces a file or moves into a folder`, async () => {
    await withMock(protocol, async ({ manager, remoteRoot }) => {
      fs.writeFileSync(path.join(remoteRoot, "draft.txt"), "new draft\n");
      fs.writeFileSync(path.join(remoteRoot, "final.txt"), "the only copy\n");
      await assert.rejects(() => manager.rename(path.posix.join(remoteRoot, "draft.txt"), "final.txt"),
        /already here/);
      assert.equal(fs.readFileSync(path.join(remoteRoot, "final.txt"), "utf8"), "the only copy\n");

      fs.mkdirSync(path.join(remoteRoot, "alpha"));
      fs.mkdirSync(path.join(remoteRoot, "beta"));
      await assert.rejects(() => manager.rename(path.posix.join(remoteRoot, "alpha"), "beta"), /already here/);
      assert.equal(fs.existsSync(path.join(remoteRoot, "beta", "alpha")), false);

      const renamed = await manager.rename(path.posix.join(remoteRoot, "alpha"), "gamma");
      assert.equal(renamed.path, path.posix.join(remoteRoot, "gamma"));
      assert.equal(fs.statSync(path.join(remoteRoot, "gamma")).isDirectory(), true);
    });
  });
}

test("scp: the transport itself refuses a rename onto a taken name", async () => {
  await withMock("scp", async ({ manager, remoteRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "a.txt"), "a");
    fs.writeFileSync(path.join(remoteRoot, "b.txt"), "b");
    // Straight to the transport, as if the name had appeared after the manager looked.
    await assert.rejects(
      () => manager.transport.call("rename", [path.posix.join(remoteRoot, "a.txt"), path.posix.join(remoteRoot, "b.txt")]),
      /already there/,
    );
    assert.equal(fs.readFileSync(path.join(remoteRoot, "b.txt"), "utf8"), "b");
  });
});

/* ---------------------------------------------- backslashes and odd names */

test("a backslash is an ordinary character in a remote name", () => {
  assert.equal(safeRemoteName("mnt-data\\x2dbackup.mount"), true);
  assert.equal(localName("mnt-data\\x2dbackup.mount", "/"), "mnt-data\\x2dbackup.mount", "kept as is off Windows");
  assert.equal(localName("mnt-data\\x2dbackup.mount", "\\"), "mnt-data_x2dbackup.mount", "a separator on Windows");
  assert.equal(localName("..\\..\\evil.bat", "\\"), ".._.._evil.bat", "which is how a name tried to climb out");
  assert.equal(localName("C:evil", "\\"), "C_evil", "a colon would name a drive or a stream");
  assert.equal(localName("..", "/"), null);
});

for (const protocol of BOTH) {
  test(`${protocol}: a backslash in a name neither hides it nor blocks its folder`, async () => {
    await withMock(protocol, async ({ manager, remoteRoot, localRoot }) => {
      const units = path.join(remoteRoot, "units");
      fs.mkdirSync(units);
      fs.writeFileSync(path.join(units, "mnt-data\\x2dbackup.mount"), "[Mount]\n");
      fs.writeFileSync(path.join(units, "app.service"), "[Service]\n");
      const listing = await manager.list(units);
      assert.deepEqual(listing.entries.map((entry) => entry.name).sort(), ["app.service", "mnt-data\\x2dbackup.mount"]);
      const [saved] = await manager.download([units], localRoot);
      assert.equal(fs.readFileSync(path.join(saved, "mnt-data\\x2dbackup.mount"), "utf8"), "[Mount]\n");
      assert.deepEqual(await manager.delete([units]), { deleted: 1, failures: [] });

      const tree = path.join(localRoot, "config");
      fs.mkdirSync(tree);
      fs.writeFileSync(path.join(tree, "a-first.conf"), "1");
      fs.writeFileSync(path.join(tree, "b\\escaped.conf"), "2");
      fs.writeFileSync(path.join(tree, "c-last.conf"), "3");
      await manager.upload([tree], remoteRoot);
      assert.deepEqual(fs.readdirSync(path.join(remoteRoot, "config")).sort(),
        ["a-first.conf", "b\\escaped.conf", "c-last.conf"]);
    });
  });
}

/* ------------------------------------------------- partial transfers */

// Makes one transport operation write part of its file and then fail, the way a
// dropped connection or a full disk does.
function breakPartWay(manager, method) {
  const transport = manager.transport;
  const original = transport.call.bind(transport);
  const targets = [];
  transport.call = async (name, args) => {
    if (name !== method) return original(name, args);
    if (method === "fastGet") {
      targets.push(args[1]);
      fs.writeFileSync(args[1], "half of it");
    } else {
      targets.push(args[1]);
      await original("writeFile", [args[1], Buffer.from("half of it")]);
    }
    throw new Error("The connection closed before the copy finished");
  };
  return targets;
}

for (const protocol of BOTH) {
  test(`${protocol}: a download that fails part way leaves nothing under the real name`, async () => {
    await withMock(protocol, async ({ manager, remoteRoot, localRoot }) => {
      fs.writeFileSync(path.join(remoteRoot, "backup.tar"), "the whole archive");
      const targets = breakPartWay(manager, "fastGet");
      await assert.rejects(() => manager.download([path.posix.join(remoteRoot, "backup.tar")], localRoot),
        /connection closed/);
      assert.notEqual(path.basename(targets[0]), "backup.tar", "the bytes went to a temporary name");
      assert.deepEqual(fs.readdirSync(localRoot).filter((name) => name !== "known-hosts.json"), [],
        "and neither a truncated file nor the temporary one is left");
    });
  });

  test(`${protocol}: an overwrite that fails part way keeps the original`, async () => {
    await withMock(protocol, async ({ manager, remoteRoot, localRoot }) => {
      fs.writeFileSync(path.join(remoteRoot, "database.sqlite"), "the original");
      fs.writeFileSync(path.join(localRoot, "database.sqlite"), "a newer version");
      breakPartWay(manager, "fastPut");
      await assert.rejects(
        () => manager.upload([path.join(localRoot, "database.sqlite")], remoteRoot, { "database.sqlite": "overwrite" }),
        /connection closed/,
      );
      assert.equal(fs.readFileSync(path.join(remoteRoot, "database.sqlite"), "utf8"), "the original");
      assert.deepEqual(leftovers(remoteRoot), [], "the temporary copy was removed");
    });
  });

  test(`${protocol}: an overwrite keeps the old file's mode and a shortcut stays a shortcut`, async () => {
    await withMock(protocol, async ({ manager, remoteRoot, localRoot }) => {
      const real = path.join(remoteRoot, "deploy.sh");
      fs.writeFileSync(real, "#!/bin/sh\necho old\n");
      fs.chmodSync(real, 0o750);
      fs.symlinkSync(real, path.join(remoteRoot, "current.sh"));
      fs.writeFileSync(path.join(localRoot, "current.sh"), "#!/bin/sh\necho new\n");
      await manager.upload([path.join(localRoot, "current.sh")], remoteRoot, { "current.sh": "overwrite" });
      assert.equal(fs.lstatSync(path.join(remoteRoot, "current.sh")).isSymbolicLink(), true);
      assert.equal(fs.readFileSync(real, "utf8"), "#!/bin/sh\necho new\n", "what the shortcut points at was replaced");
      assert.equal(fs.statSync(real).mode & 0o777, 0o750);
      assert.deepEqual(leftovers(remoteRoot), []);
    });
  });
}

/* ------------------------------------------------- the editor's contract */

for (const protocol of BOTH) {
  test(`${protocol}: the editor gets text, its line ending and a stamp`, async () => {
    await withMock(protocol, async ({ manager, remoteRoot }) => {
      const file = path.join(remoteRoot, "settings.ini");
      fs.writeFileSync(file, "\ufeffname=one\r\nlimit=10\r\n");
      const opened = await manager.readFile(file);
      assert.equal(opened.text, "\ufeffname=one\nlimit=10\n", "CRLF becomes LF and the byte order mark stays");
      assert.equal(opened.eol, "\r\n");
      const stats = fs.statSync(file);
      assert.deepEqual(opened.stamp, { size: stats.size, mtime: Math.floor(stats.mtimeMs / 1000) });

      fs.chmodSync(file, 0o640);
      const saved = await manager.writeFile(file, `${opened.text}extra=yes\n`, { eol: opened.eol, expect: opened.stamp });
      assert.equal(saved.ok, true);
      assert.deepEqual(fs.readFileSync(file), Buffer.from("\ufeffname=one\r\nlimit=10\r\nextra=yes\r\n"),
        "saved with CRLF throughout, the mark written back as it was");
      assert.equal(fs.statSync(file).mode & 0o777, 0o640, "the mode survives the save");
      assert.deepEqual(saved.stamp.size, fs.statSync(file).size);
      assert.deepEqual(leftovers(remoteRoot), []);

      assert.equal((await manager.readFile(file)).eol, "\r\n");
      fs.writeFileSync(path.join(remoteRoot, "unix.txt"), "a\nb\r\nc\n");
      assert.equal((await manager.readFile(path.join(remoteRoot, "unix.txt"))).eol, "\n", "the majority ending wins");
    });
  });

  test(`${protocol}: a save does not overwrite a change made on the host`, async () => {
    await withMock(protocol, async ({ manager, remoteRoot }) => {
      const file = path.join(remoteRoot, "notes.txt");
      fs.writeFileSync(file, "first\n");
      const opened = await manager.readFile(file);
      fs.writeFileSync(file, "someone else's edit\n");
      const result = await manager.writeFile(file, "mine\n", { eol: opened.eol, expect: opened.stamp });
      assert.equal(result.ok, false);
      assert.equal(result.changed, true);
      assert.equal(result.stamp.size, Buffer.byteLength("someone else's edit\n"));
      assert.equal(fs.readFileSync(file, "utf8"), "someone else's edit\n", "nothing was written");

      fs.rmSync(file);
      const gone = await manager.writeFile(file, "mine\n", { expect: result.stamp });
      assert.deepEqual(gone, { ok: false, changed: true, stamp: null }, "a file that has gone counts as changed");
      assert.equal(fs.existsSync(file), false);

      const fresh = await manager.writeFile(file, "mine\n");
      assert.equal(fresh.ok, true, "without a stamp the save just happens");
      assert.equal(fs.readFileSync(file, "utf8"), "mine\n");
    });
  });

  test(`${protocol}: the editor refuses what it cannot round-trip`, async () => {
    await withMock(protocol, async ({ manager, remoteRoot }) => {
      const latin1 = path.join(remoteRoot, "latin1.conf");
      fs.writeFileSync(latin1, Buffer.from("name=Jos\xe9\n", "latin1"));
      await assert.rejects(() => manager.readFile(latin1), /not UTF-8/);
      fs.writeFileSync(path.join(remoteRoot, "nul.bin"), Buffer.from([0x41, 0, 0x42]));
      await assert.rejects(() => manager.readFile(path.join(remoteRoot, "nul.bin")), /Binary file/);
      fs.mkdirSync(path.join(remoteRoot, "folder"));
      await assert.rejects(() => manager.readFile(path.join(remoteRoot, "folder")), /not an ordinary file/);
      fs.writeFileSync(path.join(remoteRoot, "big.txt"), Buffer.alloc(64, 0x61));
      await assert.rejects(() => manager.readFile(path.join(remoteRoot, "big.txt"), 10), /too large/);
    });
  });

  test(`${protocol}: a capped read stops at the cap whatever the size claimed`, async () => {
    await withMock(protocol, async ({ manager, remoteRoot }) => {
      const file = path.join(remoteRoot, "growing.log");
      fs.writeFileSync(file, Buffer.alloc(200 * 1024, 0x61));
      await assert.rejects(() => manager.transport.call("readCapped", [file, 100 * 1024]),
        (error) => error.tooLarge === true);
      const whole = await manager.transport.call("readCapped", [file, 200 * 1024]);
      assert.equal(whole.length, 200 * 1024);
    });
  });

  test(`${protocol}: a folder that takes no new files is saved in place`, async () => {
    if (process.getuid?.() === 0) return;
    await withMock(protocol, async ({ manager, remoteRoot }) => {
      const folder = path.join(remoteRoot, "locked");
      fs.mkdirSync(folder);
      const file = path.join(folder, "app.conf");
      fs.writeFileSync(file, "old\n");
      fs.chmodSync(file, 0o666);
      fs.chmodSync(folder, 0o555);
      const saved = await manager.writeFile(file, "new\n");
      assert.equal(saved.ok, true);
      assert.equal(fs.readFileSync(file, "utf8"), "new\n");
    });
  });
}

test("the save options are checked", () => {
  assert.deepEqual(editOptions(undefined), { eol: "\n", expect: null });
  assert.deepEqual(editOptions({ eol: "\r\n", expect: { size: 3, mtime: 1700000000 } }),
    { eol: "\r\n", expect: { size: 3, mtime: 1700000000 } });
  assert.throws(() => editOptions({ eol: "\r" }), /line ending/);
  assert.throws(() => editOptions({ expect: { size: "3", mtime: 1 } }), /stamp/);
  assert.throws(() => editOptions("crlf"), /not valid/);
});

/* ------------------------------------------- what a recursive download follows */

for (const protocol of BOTH) {
  test(`${protocol}: a recursive download stays inside the folder that was chosen`, async () => {
    await withMock(protocol, async ({ manager, remoteRoot, localRoot }) => {
      const project = path.join(remoteRoot, "shared-project");
      fs.mkdirSync(path.join(project, "src"), { recursive: true });
      fs.writeFileSync(path.join(project, "readme.txt"), "the file that was meant\n");
      fs.writeFileSync(path.join(project, "src", "main.c"), "int main;\n");
      fs.writeFileSync(path.join(remoteRoot, "outside-secret.txt"), "not part of it\n");
      fs.symlinkSync("/", path.join(project, "docs"));
      fs.symlinkSync(path.join(remoteRoot, "outside-secret.txt"), path.join(project, "secret.txt"));
      fs.symlinkSync(path.join(project, "src"), path.join(project, "source"));
      fs.symlinkSync(path.join(project, "readme.txt"), path.join(project, "README"));
      fs.symlinkSync(path.join(project, "missing"), path.join(project, "dangling"));
      fs.symlinkSync(project, path.join(project, "src", "loop"));

      const destination = path.join(localRoot, "download");
      fs.mkdirSync(destination);
      const error = await manager.download([project], destination).then(() => null, (caught) => caught);
      assert.ok(error, "what was left out is reported");
      assert.match(error.message, /Downloaded 1 item, but left out 3/);
      assert.match(error.message, /docs is a shortcut that leads outside/);
      assert.match(error.message, /secret\.txt is a shortcut that leads outside/);
      assert.match(error.message, /dangling is a shortcut to something that is not there/);
      const saved = path.join(destination, "shared-project");
      assert.deepEqual(fs.readdirSync(saved).sort(), ["README", "readme.txt", "source", "src"],
        "everything inside was still copied, links within the folder included");
      assert.equal(fs.readFileSync(path.join(saved, "source", "main.c"), "utf8"), "int main;\n");
      assert.equal(fs.existsSync(path.join(saved, "src", "loop")), false, "a link back up is not followed");
    });
  });
}

test("a link chosen on purpose is followed wherever it leads", async () => {
  await withMock("sftp", async ({ manager, remoteRoot, localRoot }) => {
    fs.mkdirSync(path.join(remoteRoot, "elsewhere"));
    fs.writeFileSync(path.join(remoteRoot, "elsewhere", "data.txt"), "data\n");
    fs.mkdirSync(path.join(remoteRoot, "here"));
    fs.symlinkSync(path.join(remoteRoot, "elsewhere"), path.join(remoteRoot, "here", "link"));
    const [saved] = await manager.download([path.posix.join(remoteRoot, "here", "link")], localRoot);
    assert.equal(fs.readFileSync(path.join(saved, "data.txt"), "utf8"), "data\n");
  });
});

/* ---------------------------------------------------------- the terminal */

test("⟳ Restart closes the old shell and its late close leaves the new one alone", async () => {
  await withMock("sftp", async ({ manager, server }) => {
    const exits = [];
    manager.on("terminal-exit", () => exits.push(Date.now()));
    await manager.startTerminal();
    const old = server.shells[server.shells.length - 1];
    const oldClosed = new Promise((resolve) => old.once("close", resolve));
    await manager.startTerminal();
    const fresh = server.shells[server.shells.length - 1];
    assert.notEqual(old, fresh);
    await Promise.race([oldClosed, new Promise((_resolve, reject) => setTimeout(() => reject(new Error("old shell was never closed")), 3000))]);
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.deepEqual(exits, [], "no [remote shell closed] for the shell that was replaced");
    assert.ok(manager.terminal, "the new shell is still the terminal");
    const echoed = new Promise((resolve) => fresh.on("data", (chunk) => { if (String(chunk).includes("probe")) resolve(); }));
    manager.terminalInput("probe");
    await echoed;
  });
});

test("a character split across two packets reaches the terminal whole", async () => {
  await withMock("sftp", async ({ manager, server }) => {
    const output = [];
    manager.on("terminal-data", (text) => output.push(text));
    await manager.startTerminal();
    const shell = server.shells[server.shells.length - 1];
    const bytes = Buffer.from("MARK 日本語 ok\r\n", "utf8");
    const cut = bytes.indexOf(Buffer.from("日")) + 1;
    shell.write(bytes.subarray(0, cut));
    await new Promise((resolve) => setTimeout(resolve, 100));
    shell.write(bytes.subarray(cut));
    const deadline = Date.now() + 3000;
    while (!output.join("").includes("ok") && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.match(output.join(""), /MARK 日本語 ok/);
    assert.doesNotMatch(output.join(""), /\ufffd/);
  });
});

test("temporary names are hidden, tagged and short enough for any filesystem", () => {
  const name = temporaryName("report.pdf");
  assert.match(name, /^\.report\.pdf\.swb-[0-9a-f]{8}\.part$/);
  assert.ok(Buffer.byteLength(temporaryName("é".repeat(300))) < 255);
});

/* ------------------------------------------------- against real OpenSSH */

test("real SFTP: a named pipe is refused without wedging the session", { skip: sftpUnavailable }, async () => {
  await withRealServer({ protocol: "sftp" }, async ({ manager, remote, localRoot }) => {
    const pipe = path.join(remote, "app.pipe");
    execFileSync("mkfifo", [pipe]);
    fs.mkdirSync(path.join(remote, "tree"));
    execFileSync("mkfifo", [path.join(remote, "tree", "inner.pipe")]);
    fs.writeFileSync(path.join(remote, "tree", "kept.txt"), "kept\n");
    try {
      await assert.rejects(() => manager.download([pipe], localRoot), /app\.pipe is not an ordinary file/);
      await assert.rejects(() => manager.readFile(pipe), /not an ordinary file/);
      await assert.rejects(() => manager.readBinary(pipe), /not an ordinary file/);
      const error = await manager.download([path.join(remote, "tree")], localRoot).then(() => null, (caught) => caught);
      assert.match(String(error?.message), /inner\.pipe is not an ordinary file/);
      assert.equal(fs.readFileSync(path.join(localRoot, "tree", "kept.txt"), "utf8"), "kept\n");
      const listing = await manager.list(remote);
      assert.ok(listing.entries.some((entry) => entry.name === "app.pipe"), "and the session still answers");
    } finally {
      for (const fifo of [pipe, path.join(remote, "tree", "inner.pipe")]) {
        try { fs.closeSync(fs.openSync(fifo, fs.constants.O_WRONLY | fs.constants.O_NONBLOCK)); } catch { /* nobody waiting */ }
      }
    }
  });
});

for (const protocol of ["sftp", "scp"]) {
  test(`real ${protocol}: a device that never ends is not read`, { skip: protocol === "sftp" ? sftpUnavailable : unavailable }, async () => {
    await withRealServer({ protocol }, async ({ manager, remote }) => {
      fs.symlinkSync("/dev/zero", path.join(remote, "notes.txt"));
      await assert.rejects(() => manager.readFile("/dev/zero"), /not an ordinary file/);
      await assert.rejects(() => manager.readFile(path.join(remote, "notes.txt")), /not an ordinary file/,
        "nor through a shortcut to it");
      await assert.rejects(() => manager.readBinary("/dev/urandom"), /not an ordinary file/);
    });
  });

  test(`real ${protocol}: an overwrite replaces the file whole and keeps its mode`, { skip: protocol === "sftp" ? sftpUnavailable : unavailable }, async () => {
    await withRealServer({ protocol }, async ({ manager, remote, localRoot }) => {
      const target = path.join(remote, "service.conf");
      fs.writeFileSync(target, "old\r\nline\r\n");
      fs.chmodSync(target, 0o604);
      const opened = await manager.readFile(target);
      assert.equal(opened.eol, "\r\n");
      const before = fs.statSync(target).ino;
      const saved = await manager.writeFile(target, "new\nline\n", { eol: opened.eol, expect: opened.stamp });
      assert.equal(saved.ok, true);
      assert.equal(fs.readFileSync(target, "utf8"), "new\r\nline\r\n");
      assert.equal(fs.statSync(target).mode & 0o777, 0o604);
      assert.notEqual(fs.statSync(target).ino, before, "a new file took the name; the old one was never truncated");
      fs.writeFileSync(path.join(localRoot, "service.conf"), "uploaded\n");
      await manager.upload([path.join(localRoot, "service.conf")], remote, { "service.conf": "overwrite" });
      assert.equal(fs.readFileSync(target, "utf8"), "uploaded\n");
      assert.equal(fs.statSync(target).mode & 0o777, 0o604);
      assert.deepEqual(leftovers(remote), []);
    });
  });
}

test("real scp: a leading space, a linked folder and a taken name", { skip: unavailable }, async () => {
  await withRealServer({ protocol: "scp" }, async ({ manager, remote, localRoot }) => {
    fs.writeFileSync(path.join(remote, " notes.txt"), "leading\n");
    fs.writeFileSync(path.join(remote, "notes.txt"), "plain\n");
    fs.mkdirSync(path.join(remote, "real-folder"));
    fs.writeFileSync(path.join(remote, "real-folder", "inside.txt"), "inside\n");
    fs.symlinkSync(path.join(remote, "real-folder"), path.join(remote, "linked-folder"));
    const names = (await manager.list(remote)).entries.map((entry) => entry.name);
    assert.ok(names.includes(" notes.txt") && names.includes("notes.txt"));
    assert.deepEqual((await manager.list(path.join(remote, "linked-folder"))).entries.map((entry) => entry.name), ["inside.txt"]);
    const [saved] = await manager.download([path.join(remote, "linked-folder")], localRoot);
    assert.equal(fs.readFileSync(path.join(saved, "inside.txt"), "utf8"), "inside\n");
    await assert.rejects(() => manager.rename(path.join(remote, " notes.txt"), "notes.txt"), /already here/);
    await assert.rejects(
      () => manager.transport.call("rename", [path.join(remote, " notes.txt"), path.join(remote, "notes.txt")]),
      /already there/,
    );
    assert.equal(fs.readFileSync(path.join(remote, "notes.txt"), "utf8"), "plain\n");
  });
});

"use strict";

// A minimal in-process SSH server with a filesystem-backed SFTP subsystem and an
// echoing shell. It exists so the SFTP and terminal code paths can be exercised
// without a real remote machine. It is a test double, not a hardened server.

const fs = require("node:fs");
const path = require("node:path");
const { Server, utils } = require("ssh2");
const { ShellEmulator } = require("./shell-emulator");

const { OPEN_MODE, STATUS_CODE } = utils.sftp;

function attributes(stats) {
  return {
    mode: stats.mode,
    uid: stats.uid,
    gid: stats.gid,
    size: stats.size,
    atime: Math.floor(stats.atimeMs / 1000),
    mtime: Math.floor(stats.mtimeMs / 1000),
  };
}

function longName(name, stats) {
  const type = stats.isDirectory() ? "d" : stats.isSymbolicLink() ? "l" : "-";
  return `${type}rw-r--r--   1 tester tester ${String(stats.size).padStart(8)} Jan  1 00:00 ${name}`;
}

function statusFor(error) {
  if (!error) return STATUS_CODE.FAILURE;
  if (error.code === "ENOENT") return STATUS_CODE.NO_SUCH_FILE;
  if (error.code === "EACCES" || error.code === "EPERM") return STATUS_CODE.PERMISSION_DENIED;
  return STATUS_CODE.FAILURE;
}

function attachSftp(sftp, root, latency) {
  const handles = new Map();
  let nextHandle = 0;

  const open = (value) => {
    const id = nextHandle++;
    handles.set(id, value);
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(id, 0);
    return buffer;
  };
  const lookup = (buffer) => (buffer && buffer.length === 4 ? handles.get(buffer.readUInt32BE(0)) : undefined);
  const release = (buffer) => { if (buffer && buffer.length === 4) handles.delete(buffer.readUInt32BE(0)); };

  const guard = (reqid, run) => {
    try { run(); } catch (error) { sftp.status(reqid, statusFor(error)); }
  };

  // Directory listings can be delayed to imitate a link where the round trip, not
  // the server, is what a recursive search waits on.
  const slowly = (run) => (latency ? setTimeout(run, latency) : run());

  // Links are resolved, as OpenSSH's realpath does; the download code relies on it
  // to tell a link that stays inside a folder from one that leads out of it.
  sftp.on("REALPATH", (reqid, requested) => guard(reqid, () => {
    let target = requested === "." || requested === "" ? root : path.posix.resolve(root, requested);
    try { target = fs.realpathSync(target); } catch { /* a path that does not exist yet */ }
    sftp.name(reqid, [{ filename: target, longname: target, attrs: {} }]);
  }));

  sftp.on("STAT", (reqid, target) => guard(reqid, () => sftp.attrs(reqid, attributes(fs.statSync(target)))));
  sftp.on("LSTAT", (reqid, target) => guard(reqid, () => sftp.attrs(reqid, attributes(fs.lstatSync(target)))));
  sftp.on("READLINK", (reqid, target) => guard(reqid, () => {
    const resolved = fs.readlinkSync(target);
    sftp.name(reqid, [{ filename: resolved, longname: resolved, attrs: {} }]);
  }));

  sftp.on("OPENDIR", (reqid, target) => guard(reqid, () => {
    const entries = fs.readdirSync(target);
    sftp.handle(reqid, open({ type: "dir", directory: target, entries, index: 0 }));
  }));

  sftp.on("READDIR", (reqid, handle) => slowly(() => guard(reqid, () => {
    const state = lookup(handle);
    if (!state || state.type !== "dir") return sftp.status(reqid, STATUS_CODE.FAILURE);
    if (state.index >= state.entries.length) return sftp.status(reqid, STATUS_CODE.EOF);
    const batch = [];
    for (const name of state.entries.slice(state.index)) {
      try {
        const stats = fs.lstatSync(path.join(state.directory, name));
        batch.push({ filename: name, longname: longName(name, stats), attrs: attributes(stats) });
      } catch { /* vanished between readdir and lstat */ }
    }
    state.index = state.entries.length;
    return sftp.name(reqid, batch);
  })));

  sftp.on("OPEN", (reqid, target, flags) => guard(reqid, () => {
    let mode = "r";
    if (flags & OPEN_MODE.APPEND) mode = "a";
    else if (flags & OPEN_MODE.WRITE && flags & OPEN_MODE.TRUNC) mode = "w";
    else if (flags & OPEN_MODE.WRITE && flags & OPEN_MODE.CREAT) mode = "w";
    else if (flags & OPEN_MODE.WRITE) mode = "r+";
    const descriptor = fs.openSync(target, mode);
    sftp.handle(reqid, open({ type: "file", descriptor, path: target }));
  }));

  sftp.on("FSTAT", (reqid, handle) => guard(reqid, () => {
    const state = lookup(handle);
    if (!state) return sftp.status(reqid, STATUS_CODE.FAILURE);
    const stats = state.type === "file" ? fs.fstatSync(state.descriptor) : fs.statSync(state.directory);
    return sftp.attrs(reqid, attributes(stats));
  }));

  sftp.on("READ", (reqid, handle, offset, length) => guard(reqid, () => {
    const state = lookup(handle);
    if (!state || state.type !== "file") return sftp.status(reqid, STATUS_CODE.FAILURE);
    const buffer = Buffer.alloc(length);
    const read = fs.readSync(state.descriptor, buffer, 0, length, offset);
    if (!read) return sftp.status(reqid, STATUS_CODE.EOF);
    return sftp.data(reqid, buffer.subarray(0, read));
  }));

  sftp.on("WRITE", (reqid, handle, offset, data) => guard(reqid, () => {
    const state = lookup(handle);
    if (!state || state.type !== "file") return sftp.status(reqid, STATUS_CODE.FAILURE);
    fs.writeSync(state.descriptor, data, 0, data.length, offset);
    return sftp.status(reqid, STATUS_CODE.OK);
  }));

  sftp.on("CLOSE", (reqid, handle) => guard(reqid, () => {
    const state = lookup(handle);
    if (state?.type === "file") fs.closeSync(state.descriptor);
    release(handle);
    sftp.status(reqid, STATUS_CODE.OK);
  }));

  sftp.on("MKDIR", (reqid, target) => guard(reqid, () => {
    fs.mkdirSync(target);
    sftp.status(reqid, STATUS_CODE.OK);
  }));
  sftp.on("RMDIR", (reqid, target) => guard(reqid, () => {
    fs.rmdirSync(target);
    sftp.status(reqid, STATUS_CODE.OK);
  }));
  sftp.on("REMOVE", (reqid, target) => guard(reqid, () => {
    fs.unlinkSync(target);
    sftp.status(reqid, STATUS_CODE.OK);
  }));
  sftp.on("RENAME", (reqid, source, target) => guard(reqid, () => {
    fs.renameSync(source, target);
    sftp.status(reqid, STATUS_CODE.OK);
  }));
  // The mode is applied, because an overwrite sets it on its temporary copy and the
  // tests check that it survives. Owner changes are accepted and ignored: the tests
  // run as one user, so there is never a different owner to keep.
  sftp.on("SETSTAT", (reqid, target, attrs) => guard(reqid, () => {
    if (typeof attrs?.mode === "number") fs.chmodSync(target, attrs.mode & 0o7777);
    sftp.status(reqid, STATUS_CODE.OK);
  }));
  sftp.on("FSETSTAT", (reqid) => sftp.status(reqid, STATUS_CODE.OK));
  sftp.on("SYMLINK", (reqid, target, linkPath) => guard(reqid, () => {
    fs.symlinkSync(target, linkPath);
    sftp.status(reqid, STATUS_CODE.OK);
  }));
}

// ssh2 occasionally emits a private key that its own parser rejects — about one in
// two hundred — which showed up as a rare unexplained test failure. Generating a
// key is cheap, so check it before handing it to the server.
function generateHostKey() {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const pair = utils.generateKeyPairSync("ed25519");
    if (!(utils.parseKey(pair.private) instanceof Error)) return pair;
  }
  throw new Error("Could not generate a parseable host key");
}

// `refuseSftp` makes the server behave like a host with the subsystem switched off,
// which is the configuration the SCP fallback exists for. `scp` and `timeStyle`
// describe how sparse the remote tools are.
// `keyboardInteractive` makes the server ask over that method instead of accepting
// the password method outright, which is what a host that only offers challenges
// looks like. It describes the rounds to ask for: each is a list of prompts, and
// what the client answered is recorded so a test can see what it was told.
function startTestServer({
  root, username = "tester", password = "secret", latency = 0, authDelay = 0,
  refuseSftp = false, scp = true, timeStyle = true, keyboardInteractive = null, wrapper = true,
}) {
  const hostKeyPair = generateHostKey();
  const hostKey = hostKeyPair.private;
  const shells = [];
  const received = [];
  const commands = [];
  const shell = new ShellEmulator(root, { scp, timeStyle, wrapper });
  // Mutable so a test can switch the subsystem off on a host it has already
  // trusted, which is what exercises the fallback without a second host key.
  const sftpEnabled = { value: !refuseSftp };
  const clients = new Set();
  const answers = [];
  const server = new Server({ hostKeys: [hostKey] }, (client) => {
    clients.add(client);
    client.on("close", () => clients.delete(client));
    client.on("authentication", (context) => {
      if (keyboardInteractive) {
        if (context.method !== "keyboard-interactive") return context.reject(["keyboard-interactive"]);
        // Each round is another prompt inside the same authentication, which is what
        // a server asking a follow-up question actually does -- rejecting and asking
        // again would be a fresh attempt, and a client will not retry a method it has
        // already been refused on.
        const given = [];
        const ask = (index) => {
          const asking = keyboardInteractive[index];
          if (!asking) {
            // Every round has to have been answered with the password. A host that
            // keeps asking does not get in, and the point of the test is what it was
            // told on the way there.
            const satisfied = given.length === keyboardInteractive.length
              && given.every((round) => round[0] === password);
            return satisfied ? context.accept() : context.reject();
          }
          return context.prompt(asking, "", "", (replies) => {
            given.push(replies.slice());
            answers.push(replies.slice());
            ask(index + 1);
          });
        };
        return ask(0);
      }
      if (context.method === "password" && context.username === username && context.password === password) {
        // Held open so a test can act while the handshake is still in flight.
        if (authDelay) return setTimeout(() => context.accept(), authDelay);
        return context.accept();
      }
      if (context.method === "none") return context.reject(["password"]);
      return context.reject();
    });
    client.on("session", (accept) => {
      const session = accept();
      session.on("pty", (ptyAccept) => ptyAccept && ptyAccept());
      session.on("window-change", (changeAccept) => changeAccept && changeAccept());
      session.on("sftp", (sftpAccept, sftpReject) => {
        if (!sftpEnabled.value) return sftpReject();
        return attachSftp(sftpAccept(), root, latency);
      });
      session.on("shell", (shellAccept) => {
        const stream = shellAccept();
        shells.push(stream);
        stream.write("test-shell-ready\r\n");
        stream.on("data", (chunk) => {
          received.push(Buffer.from(chunk));
          stream.write(chunk);
        });
      });
      session.on("exec", (execAccept, _reject, info) => {
        const stream = execAccept();
        try {
          shell.run(String(info.command), stream, (line) => commands.push(line));
        } catch (error) {
          stream.stderr.write(`sh: ${error.message}\n`);
          stream.exit(1);
          stream.end();
        }
      });
    });
    client.on("error", () => { /* the test client tears connections down abruptly */ });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        host: "127.0.0.1",
        port: server.address().port,
        username,
        password,
        shells,
        hostPublicKey: hostKeyPair.public,
        // Everything the shell has been sent, so the test can see what the
        // terminal decided to forward.
        received: () => Buffer.concat(received).toString("binary"),
        // Mouse tracking, exactly as vim, tmux, or less would ask for it.
        setMouseReporting: (on) => {
          for (const stream of shells) stream.write(on ? "\u001b[?1000h" : "\u001b[?1000l");
        },
        clientCount: () => clients.size,
        // What the client answered each keyboard-interactive round with, so a test
        // can see whether the password was handed over and how often.
        keyboardAnswers: () => answers.map((round) => round.slice()),
        // Every command line the exec channel was asked to run, so a test can check
        // what the transport actually sent rather than only what came back.
        commands: () => [...commands],
        setSftp: (enabled) => { sftpEnabled.value = Boolean(enabled); },
        mouseReports: () => (Buffer.concat(received).toString("binary").match(/\u001b\[M/g) || []).length,
        // Simulates the far end vanishing while the listener stays available.
        dropClients: () => {
          for (const client of clients) { try { client.end(); } catch { /* already closed */ } }
          clients.clear();
        },
        close: () => new Promise((done) => {
          for (const stream of shells) { try { stream.end(); } catch { /* already closed */ } }
          for (const client of clients) { try { client.end(); } catch { /* already closed */ } }
          clients.clear();
          server.close(() => done());
        }),
      });
    });
  });
}

module.exports = { startTestServer };

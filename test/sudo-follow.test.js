"use strict";

// The file pane following the terminal to root. The process-table reading is pure
// and tested against hand-built tables for each way a shell can change user. The
// rest runs against a real OpenSSH server, so the probe meets the real `ps` and the
// real process tree sshd builds, and the sudo-started sftp-server is a real one.
//
// The tests cannot become root, so `sudo` here is a stand-in that asks for and
// checks a password the way `sudo -n` and `sudo -S` do and then runs the command as
// the same user; and `ps` is wrapped so that, while a marker file exists, the
// terminal's shells report uid 0. Everything between those two edges is the code
// that ships.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");
const { SshManager } = require("../lib/ssh-manager");
const { PROBE_COMMAND, parseProbe, terminalUser } = require("../lib/terminal-user");
const { EventEmitter } = require("node:events");
const { openSudoSftp, sudoCommand } = require("../lib/sudo-sftp");
const { startTestServer } = require("./helpers/ssh-test-server");

/* ------------------------------------------------------- the process table */

const SHELLS = ["sh", "bash", "dash", "zsh"];

// pid, ppid, pgid, tpgid, ruid, tty, comm
function table(rows) {
  return {
    sshd: 100,
    uid: 1000,
    shells: SHELLS,
    processes: rows.map(([pid, ppid, pgid, tpgid, ruid, tty, comm, args = comm]) => ({ pid, ppid, pgid, tpgid, ruid, tty, comm, args })),
  };
}

test("the login shell at its prompt is the login user", () => {
  assert.equal(terminalUser(table([
    [200, 100, 200, 200, 1000, "pts/0", "bash"],
    [300, 100, 300, -1, 1000, "?", "sh"],
    [301, 300, 300, -1, 1000, "?", "ps"],
  ])), 1000);
});

test("sudo su, with sudo running su on the same terminal, is root", () => {
  assert.equal(terminalUser(table([
    [200, 100, 200, 400, 1000, "pts/0", "bash"],
    [210, 200, 210, 400, 1000, "pts/0", "sudo"],
    [211, 210, 210, 400, 0, "pts/0", "su"],
    [400, 211, 400, 400, 0, "pts/0", "bash"],
  ])), 0);
});

test("sudo su, with sudo giving su a pty of its own (use_pty), is root", () => {
  assert.equal(terminalUser(table([
    [200, 100, 200, 210, 1000, "pts/0", "bash"],
    [210, 200, 210, 210, 1000, "pts/0", "sudo"],
    [212, 210, 212, 500, 0, "pts/5", "sudo"],
    [213, 212, 213, 500, 0, "pts/5", "su"],
    [500, 213, 500, 500, 0, "pts/5", "bash"],
  ])), 0);
});

test("sudo vim is no answer; the pane stays where it is", () => {
  assert.equal(terminalUser(table([
    [200, 100, 200, 210, 1000, "pts/0", "bash"],
    [210, 200, 210, 210, 1000, "pts/0", "sudo"],
    [211, 210, 210, 210, 0, "pts/0", "vim"],
  ])), null);
});

test("a command running in the root shell is no answer; the pane stays at root", () => {
  assert.equal(terminalUser(table([
    [200, 100, 200, 600, 1000, "pts/0", "bash"],
    [210, 200, 210, 600, 1000, "pts/0", "sudo"],
    [211, 210, 210, 600, 0, "pts/0", "su"],
    [400, 211, 400, 600, 0, "pts/0", "bash"],
    [600, 400, 600, 600, 0, "pts/0", "apt"],
  ])), null);
});

test("a root shell that is only running a command is not followed, with or without sudo's pty", () => {
  // sudo sh -c 'apt update' -- sudo in the same terminal
  assert.equal(terminalUser(table([
    [200, 100, 200, 210, 1000, "pts/0", "bash"],
    [210, 200, 210, 210, 1000, "pts/0", "sudo"],
    [211, 210, 210, 210, 0, "pts/0", "sh"],
    [212, 211, 210, 210, 0, "pts/0", "apt"],
  ])), null);
  // the same with use_pty, the default since sudo 1.9.14
  assert.equal(terminalUser(table([
    [200, 100, 200, 210, 1000, "pts/0", "bash"],
    [210, 200, 210, 210, 1000, "pts/0", "sudo"],
    [212, 210, 212, 213, 0, "pts/5", "sudo"],
    [213, 212, 213, 213, 0, "pts/5", "sh"],
    [214, 213, 213, 213, 0, "pts/5", "apt"],
  ])), null);
});

test("a root shell running a script or -c is not a prompt", () => {
  const withRootShell = (args) => terminalUser(table([
    [200, 100, 200, 210, 1000, "pts/0", "bash"],
    [210, 200, 210, 210, 1000, "pts/0", "sudo"],
    [212, 210, 212, 213, 0, "pts/5", "sudo"],
    [213, 212, 213, 213, 0, "pts/5", "bash", args],
  ]));
  assert.equal(withRootShell("bash ./install.sh"), null);
  assert.equal(withRootShell("bash -c while true; do :; done"), null);
  assert.equal(withRootShell("bash -ec true"), null);
  assert.equal(withRootShell("-bash"), 0, "sudo -i");
  assert.equal(withRootShell("/bin/bash"), 0, "sudo -s");
  assert.equal(withRootShell("bash --login"), 0);
  assert.equal(withRootShell(null), null, "arguments that were not read are no answer");
});

test("a background job that happens to be a root shell is not followed", () => {
  assert.equal(terminalUser(table([
    [200, 100, 200, 200, 1000, "pts/0", "bash"],
    [210, 200, 210, 200, 0, "pts/0", "bash"],
  ])), 1000);
});

test("nothing is decided when the terminal cannot be found unambiguously", () => {
  assert.equal(terminalUser(table([])), null);
  assert.equal(terminalUser(table([
    [200, 100, 200, 200, 1000, "pts/0", "bash"],
    [201, 100, 201, 201, 0, "pts/1", "bash"],
  ])), null);
  assert.equal(terminalUser(table([
    [200, 100, 200, 200, 1000, "pts/0", "fish-not-listed"],
  ])), null, "a login shell missing from /etc/shells is not guessed at");
});

test("probe output parses, including macOS-style paths and login-shell dashes", () => {
  const probe = parseProbe([
    "sshd 100", "uid 501", "processes",
    "  200   100   200   200   501 ttys001  -bash",
    "  300   100   300     0   501 ??       /bin/sh",
    "arguments",
    "  200 -bash",
    "  300 /bin/sh -c echo hi",
    "shells", "# comment", "/bin/bash", "/usr/local/bin/zsh", "",
  ].join("\n"));
  assert.equal(probe.sshd, 100);
  assert.equal(probe.uid, 501);
  assert.deepEqual(probe.shells, ["bash", "zsh"]);
  assert.equal(probe.processes[0].comm, "bash");
  assert.equal(probe.processes[0].args, "-bash");
  assert.equal(probe.processes[1].args, "/bin/sh -c echo hi");
  assert.equal(terminalUser(probe), 501);
});

test("the sudo command carries no single quote or backslash inside its script", () => {
  for (const command of [sudoCommand(0, {}), sudoCommand(33, { password: "x" })]) {
    const script = command.slice(command.indexOf("'") + 1, command.lastIndexOf("'"));
    assert.doesNotMatch(script, /['\\]/);
  }
  assert.match(sudoCommand(33, {}), /^env LC_ALL=C sudo -n -u "#33" -- /);
  assert.match(sudoCommand(0, { password: "x" }), /^env LC_ALL=C sudo -S -p "[^"]+" -- /);
});

/* ------------------------------------------------- sudo, against a stand-in */

// An exec channel whose far end is scripted: `onOpen(stream, command)` decides what
// sudo says, and `written` collects what was sent to it.
function scriptedClient(onOpen, onWrite = null) {
  const written = [];
  return {
    written,
    _protocol: { _remoteIdentRaw: "SSH-2.0-OpenSSH_9.6" },
    exec: (command, cb) => {
      const stream = new EventEmitter();
      stream.stderr = new EventEmitter();
      stream.close = () => setImmediate(() => stream.emit("close"));
      stream.write = (data) => {
        written.push(Buffer.from(data));
        if (onWrite) return onWrite(stream, command, data);
        // sftp-server's VERSION reply to the client's INIT
        if (Buffer.isBuffer(data) && data[4] === 1) setImmediate(() => stream.emit("data", Buffer.from([0, 0, 0, 5, 2, 0, 0, 0, 3])));
        return true;
      };
      cb(null, stream);
      setImmediate(() => onOpen(stream, command));
    },
  };
}

test("the user name is read whole when the ready line arrives in pieces", async () => {
  const client = scriptedClient((stream) => {
    stream.stderr.emit("data", Buffer.from("SSH-WORKBENCH-SUDO-READY ro"));
    setTimeout(() => stream.stderr.emit("data", Buffer.from("ot\n")), 20);
  });
  const { user, transport } = await openSudoSftp(client, 0);
  transport.close();
  assert.equal(user, "root");
});

test("the password reaches sudo whatever prompt it shows", async () => {
  const client = scriptedClient((stream, command) => {
    if (command.includes("sudo -n")) {
      stream.stderr.emit("data", Buffer.from("sudo: a password is required\n"));
      return stream.emit("close");
    }
    // An LDAP/SSSD prompt instead of the one passed with -p.
    stream.stderr.emit("data", Buffer.from("Password for alice@EXAMPLE.COM: "));
    setTimeout(() => stream.stderr.emit("data", Buffer.from("SSH-WORKBENCH-SUDO-READY root\n")), 20);
  });
  const { transport } = await openSudoSftp(client, 0, "hunter2");
  transport.close();
  assert.ok(client.written.some((chunk) => chunk.toString() === "hunter2\n"), "the password was written");
});

test("a refused password is reported as rejected, and is sent only once", async () => {
  const client = scriptedClient((stream, command) => {
    if (command.includes("sudo -n")) {
      stream.stderr.emit("data", Buffer.from("sudo: a password is required\n"));
      return stream.emit("close");
    }
    stream.stderr.emit("data", Buffer.from("[sudo] password for alice: "));
    setTimeout(() => stream.stderr.emit("data", Buffer.from("Sorry, try again.\n[sudo] password for alice: ")), 20);
  });
  await assert.rejects(openSudoSftp(client, 0, "wrong"), (error) => error.rejected === true);
  assert.equal(client.written.filter((chunk) => chunk.toString() === "wrong\n").length, 1);
});

test("a password sudo refused is not offered again at the next switch to root", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-refused-"));
  const server = await startTestServer({ root, username: "tester", password: "login-pw" });
  const manager = new SshManager({ knownHostsPath: path.join(root, "kh.json"), confirmHost: async () => ({ accept: true }) });
  try {
    await manager.connect({ host: server.host, port: server.port, username: "tester", authType: "password", password: "login-pw", protocol: "sftp" });
    await manager.startTerminal();
    let terminalIsRoot = false;
    let offered = 0;
    manager.client.exec = scriptedClient((stream, command) => {
      if (command === PROBE_COMMAND) {
        const ruid = terminalIsRoot ? 0 : 1000;
        stream.emit("data", Buffer.from(`sshd 100\nuid 1000\nprocesses\n 200 100 200 200 ${ruid} pts/0 bash\narguments\n 200 -bash\nshells\n/bin/bash\n`));
        return stream.emit("close");
      }
      if (command.includes("sudo -n")) {
        stream.stderr.emit("data", Buffer.from("sudo: a password is required\n"));
        return stream.emit("close");
      }
    }, (stream, _command, data) => {
      if (String(data).startsWith("login-pw")) offered += 1;
      setImmediate(() => stream.stderr.emit("data", Buffer.from("Sorry, try again.\n")));
      return true;
    }).exec;
    for (let round = 0; round < 3; round += 1) {
      terminalIsRoot = true;
      manager.terminalInput("\r");
      const asked = await nextEvent(manager, "browse-user");
      assert.equal(asked.needsPassword, true);
      manager.declineFollow();
      terminalIsRoot = false;
      manager.terminalInput("\r");
      await delay(600);
    }
    assert.equal(offered, 1, "the login password was offered once, refused, and then forgotten");
  } finally {
    await manager.disconnect();
    await server.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

/* -------------------------------------------------------- a real OpenSSH host */

function locate(command, extraPaths = []) {
  for (const candidate of [...extraPaths, ...(process.env.PATH || "").split(path.delimiter)]) {
    const full = path.join(candidate, command);
    try {
      fs.accessSync(full, fs.constants.X_OK);
      return full;
    } catch { /* keep looking */ }
  }
  return null;
}

const sshdBinary = locate("sshd", ["/usr/sbin", "/usr/local/sbin", "/sbin"]);
const keygenBinary = locate("ssh-keygen");
const psBinary = locate("ps", ["/bin", "/usr/bin"]);
const sftpServer = ["/usr/lib/openssh/sftp-server", "/usr/libexec/openssh/sftp-server", "/usr/lib/ssh/sftp-server"]
  .find((candidate) => fs.existsSync(candidate));
const unavailable = process.platform === "win32" ? "not applicable on Windows"
  : !sshdBinary ? "no sshd binary on this machine"
    : !keygenBinary ? "no ssh-keygen on this machine"
      : !psBinary ? "no ps on this machine"
        : !sftpServer ? "no sftp-server on this machine"
          : undefined;

const PASSWORD = "correct horse";

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.on("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

function waitForPort(port, deadline) {
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const socket = net.connect(port, "127.0.0.1");
      socket.once("connect", () => { socket.destroy(); resolve(); });
      socket.once("error", () => {
        socket.destroy();
        if (Date.now() > deadline) reject(new Error("sshd never started listening"));
        else setTimeout(attempt, 100);
      });
    };
    attempt();
  });
}

function write(file, text) {
  fs.writeFileSync(file, text);
  fs.chmodSync(file, 0o755);
}

async function startServer() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-sudo-"));
  const remote = path.join(root, "remote");
  const bin = path.join(root, "bin");
  fs.mkdirSync(remote);
  fs.mkdirSync(bin);
  const hostKey = path.join(root, "host_key");
  const clientKey = path.join(root, "client_key");
  execFileSync(keygenBinary, ["-q", "-t", "ed25519", "-f", hostKey, "-N", ""]);
  execFileSync(keygenBinary, ["-q", "-t", "ed25519", "-f", clientKey, "-N", ""]);
  const authorized = path.join(root, "authorized_keys");
  fs.copyFileSync(`${clientKey}.pub`, authorized);
  fs.chmodSync(authorized, 0o600);
  fs.chmodSync(hostKey, 0o600);

  // sudo -n refuses without a password unless `nopasswd` exists; sudo -S prompts on
  // stderr, reads one line, and allows three attempts.
  write(path.join(bin, "sudo"), [
    "#!/bin/sh",
    "mode=; prompt=Password:",
    "while [ $# -gt 0 ]; do case \"$1\" in",
    "  -n) mode=n; shift;; -S) mode=S; shift;; -p) prompt=\"$2\"; shift 2;; -u) shift 2;;",
    "  --) shift; break;; *) break;; esac; done",
    `[ -f ${root}/nopasswd ] && exec "$@"`,
    "if [ \"$mode\" = n ]; then echo 'sudo: a password is required' >&2; exit 1; fi",
    "tries=0",
    "while [ $tries -lt 3 ]; do",
    "  printf '%s' \"$prompt\" >&2",
    "  IFS= read -r answer || exit 1",
    `  [ "$answer" = '${PASSWORD}' ] && exec "$@"`,
    "  echo 'Sorry, try again.' >&2; tries=$((tries+1))",
    "done",
    "exit 1",
    "",
  ].join("\n"));
  // While `as-root` exists, every process with a terminal reports uid 0.
  write(path.join(bin, "ps"), [
    "#!/bin/sh",
    `if [ -f ${root}/as-root ]; then`,
    `  ${psBinary} "$@" | awk '$6 != "?" && NF >= 7 { $5 = 0 } { print }'`,
    "else",
    `  exec ${psBinary} "$@"`,
    "fi",
    "",
  ].join("\n"));

  const port = await freePort();
  const configPath = path.join(root, "sshd_config");
  fs.writeFileSync(configPath, [
    `Port ${port}`,
    "ListenAddress 127.0.0.1",
    `HostKey ${hostKey}`,
    `AuthorizedKeysFile ${authorized}`,
    `PidFile ${path.join(root, "sshd.pid")}`,
    "StrictModes no",
    "UsePAM no",
    "PasswordAuthentication no",
    "KbdInteractiveAuthentication no",
    "PubkeyAuthentication yes",
    "PermitRootLogin no",
    "PrintMotd no",
    "X11Forwarding no",
    `Subsystem sftp ${sftpServer}`,
    `SetEnv PATH=${bin}:/usr/local/bin:/usr/bin:/bin`,
    "",
  ].join("\n"));

  const logPath = path.join(root, "sshd.log");
  const daemon = spawn(sshdBinary, ["-D", "-f", configPath, "-E", logPath], { stdio: "ignore" });
  const stop = () => {
    try { daemon.kill("SIGTERM"); } catch { /* already gone */ }
    fs.rmSync(root, { recursive: true, force: true });
  };
  try {
    await waitForPort(port, Date.now() + 8000);
  } catch (error) {
    const log = fs.existsSync(logPath) ? fs.readFileSync(logPath, "utf8") : "";
    stop();
    throw new Error(`${error.message}\n${log}`);
  }
  return { port, root, remote, clientKey, username: os.userInfo().username, stop };
}

async function withServer(run) {
  const server = await startServer();
  const localRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-sudo-local-"));
  const manager = new SshManager({
    knownHostsPath: path.join(localRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  try {
    await manager.connect({
      host: "127.0.0.1",
      port: server.port,
      username: server.username,
      authType: "key",
      keyPath: server.clientKey,
      protocol: "sftp",
    });
    await run({ manager, server });
  } finally {
    await manager.disconnect();
    server.stop();
    fs.rmSync(localRoot, { recursive: true, force: true });
  }
}

function exec(client, command) {
  return new Promise((resolve, reject) => {
    client.exec(command, (error, stream) => {
      if (error) return reject(error);
      const out = [];
      stream.on("data", (chunk) => out.push(chunk));
      stream.stderr.on("data", () => {});
      stream.once("close", () => resolve(Buffer.concat(out).toString("utf8")));
    });
  });
}

function nextEvent(manager, name, timeout = 8000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no ${name} event`)), timeout);
    manager.once(name, (value) => { clearTimeout(timer); resolve(value); });
  });
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("the probe finds this connection's terminal in the real process table", { skip: unavailable }, async () => {
  await withServer(async ({ manager }) => {
    await manager.startTerminal();
    await delay(500);
    const probe = parseProbe(await exec(manager.client, PROBE_COMMAND));
    assert.equal(probe.uid, process.getuid(), "id -u is the login user");
    assert.ok(probe.processes.length > 0, "ps output was read");
    assert.equal(terminalUser(probe), process.getuid(), "the terminal's shell was found and is the login user");
  });
});

test("sudo sftp: no password is refused, the right one opens a working session", { skip: unavailable }, async () => {
  await withServer(async ({ manager, server }) => {
    await assert.rejects(openSudoSftp(manager.client, 0, null), (error) => error.sudoPasswordNeeded === true);
    await assert.rejects(openSudoSftp(manager.client, 0, "wrong"), (error) => error.sudoPasswordNeeded === true);

    const { transport, user } = await openSudoSftp(manager.client, 0, PASSWORD);
    try {
      assert.equal(user, server.username, "the stand-in sudo does not change user, and says so");
      await transport.call("writeFile", [path.join(server.remote, "made.txt"), "over sudo"]);
      const names = (await transport.call("readdir", [server.remote])).map((item) => item.filename);
      assert.deepEqual(names, ["made.txt"]);
      assert.equal(fs.readFileSync(path.join(server.remote, "made.txt"), "utf8"), "over sudo");
      const big = Buffer.alloc(3 * 1024 * 1024, 7);
      await transport.call("writeFile", [path.join(server.remote, "big.bin"), big]);
      const back = await transport.call("readFile", [path.join(server.remote, "big.bin")]);
      assert.ok(back.equals(big), "a multi-megabyte file survives the round trip");
    } finally {
      transport.close();
    }

    fs.writeFileSync(path.join(server.root, "nopasswd"), "");
    const free = await openSudoSftp(manager.client, 0, null);
    free.transport.close();
  });
});

test("Enter in the terminal follows it to root and back", { skip: unavailable }, async () => {
  await withServer(async ({ manager, server }) => {
    await manager.startTerminal();
    await delay(500);
    const marker = path.join(server.root, "as-root");

    fs.writeFileSync(marker, "");
    manager.terminalInput("true\r");
    const asked = await nextEvent(manager, "browse-user");
    assert.equal(asked.needsPassword, true, "a key login has no password to offer sudo, so it asks");
    assert.equal(asked.wanted, 0);

    const followed = nextEvent(manager, "browse-user");
    await manager.followWithPassword(PASSWORD);
    const state = await followed;
    assert.equal(state.elevated, true);
    assert.equal(state.user, server.username);
    fs.writeFileSync(path.join(server.remote, "seen.txt"), "x");
    const listing = await manager.list(server.remote);
    assert.deepEqual(listing.entries.map((entry) => entry.name), ["seen.txt"], "listing goes through the sudo session");

    fs.rmSync(marker);
    manager.terminalInput("\r");
    const back = await nextEvent(manager, "browse-user");
    assert.equal(back.elevated, false, "exit from the root shell returns the pane to the login user");

    // Root again: the password given earlier is reused, not asked for twice.
    fs.writeFileSync(marker, "");
    manager.terminalInput("\r");
    const again = await nextEvent(manager, "browse-user");
    assert.equal(again.elevated, true);
    assert.ok(!again.needsPassword);
  });
});

test("a transfer running as root finishes before the pane leaves root", { skip: unavailable }, async () => {
  await withServer(async ({ manager, server }) => {
    await manager.startTerminal();
    await delay(500);
    const marker = path.join(server.root, "as-root");
    fs.writeFileSync(marker, "");
    manager.terminalInput("\r");
    await nextEvent(manager, "browse-user");
    const switched = nextEvent(manager, "browse-user");
    await manager.followWithPassword(PASSWORD);
    assert.equal((await switched).elevated, true);
    const big = path.join(server.remote, "big.bin");
    fs.writeFileSync(big, Buffer.alloc(200 * 1024 * 1024, 1));
    const local = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-dl-"));
    try {
      const download = manager.download([big], local, path.join(local, "big.bin")).then(() => "finished", (error) => `failed: ${error.message}`);
      await delay(150);
      fs.rmSync(marker);
      const left = nextEvent(manager, "browse-user", 60000);
      manager.terminalInput("\r");
      assert.equal(await download, "finished");
      assert.equal(fs.statSync(path.join(local, "big.bin")).size, 200 * 1024 * 1024);
      assert.equal((await left).elevated, false, "and then the pane does leave root");
    } finally {
      fs.rmSync(local, { recursive: true, force: true });
    }
  });
});

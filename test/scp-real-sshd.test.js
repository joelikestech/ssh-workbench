"use strict";

// The SCP transport against a real OpenSSH server with no SFTP subsystem — the
// configuration the fallback exists for. Every other SCP test runs against this
// project's own emulator, which can only ever confirm that the code agrees with
// itself; this one confirms it agrees with `sshd`, `ls` and `scp` as shipped.
//
// It needs an sshd binary and ssh-keygen on the machine running the tests, and runs
// unprivileged on a high port with its own host key, its own authorized_keys, and a
// throwaway directory. Where those tools are absent — a Windows or macOS build host,
// a stripped container — it skips rather than failing.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");
const { SshManager } = require("../lib/ssh-manager");

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
// Undefined rather than null on purpose: the test runner skips on any value that is
// not false or undefined, so a null here would skip everywhere, silently.
const unavailable = process.platform === "win32" ? "not applicable on Windows"
  : !sshdBinary ? "no sshd binary on this machine"
    : !keygenBinary ? "no ssh-keygen on this machine"
      : undefined;

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

// A server with no `Subsystem sftp` line at all, which is what makes an SFTP channel
// request fail the way a hardened host makes it fail.
async function startRealServer() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-sshd-"));
  const remote = path.join(root, "remote");
  fs.mkdirSync(remote);
  const hostKey = path.join(root, "host_key");
  const clientKey = path.join(root, "client_key");
  execFileSync(keygenBinary, ["-q", "-t", "ed25519", "-f", hostKey, "-N", ""]);
  execFileSync(keygenBinary, ["-q", "-t", "ed25519", "-f", clientKey, "-N", ""]);
  const authorized = path.join(root, "authorized_keys");
  fs.copyFileSync(`${clientKey}.pub`, authorized);
  fs.chmodSync(authorized, 0o600);
  fs.chmodSync(hostKey, 0o600);

  const port = await freePort();
  const configPath = path.join(root, "sshd_config");
  fs.writeFileSync(configPath, [
    `Port ${port}`,
    "ListenAddress 127.0.0.1",
    `HostKey ${hostKey}`,
    `AuthorizedKeysFile ${authorized}`,
    `PidFile ${path.join(root, "sshd.pid")}`,
    // The tree lives under a world-readable temporary directory, which strict mode
    // would refuse; and there is no privileged user here to own it.
    "StrictModes no",
    "UsePAM no",
    "PasswordAuthentication no",
    "KbdInteractiveAuthentication no",
    "PubkeyAuthentication yes",
    "PermitRootLogin no",
    "PrintMotd no",
    "X11Forwarding no",
    // Deliberately no Subsystem line: SFTP is unavailable on this host.
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
  return { port, remote, clientKey, username: os.userInfo().username, root, logPath, stop };
}

async function withRealServer(run) {
  const server = await startRealServer();
  const localRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-real-local-"));
  const manager = new SshManager({
    knownHostsPath: path.join(localRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  try {
    const connection = await manager.connect({
      host: "127.0.0.1",
      port: server.port,
      username: server.username,
      authType: "key",
      keyPath: server.clientKey,
      protocol: "sftp-scp",
    });
    await run({ manager, server, connection, remote: server.remote, localRoot });
  } finally {
    await manager.disconnect();
    server.stop();
    fs.rmSync(localRoot, { recursive: true, force: true });
  }
}

test("a real OpenSSH host with no SFTP subsystem falls back to SCP", { skip: unavailable }, async () => {
  await withRealServer(async ({ connection }) => {
    assert.equal(connection.protocol, "scp", "SFTP was refused, so scp carries the session");
    assert.match(String(connection.sftpUnavailable), /subsystem|fail|refus/i,
      `the refusal should be reported: ${connection.sftpUnavailable}`);
    assert.ok(connection.home.startsWith("/"), `the shell's working directory: ${connection.home}`);
  });
});

test("real ls output parses: spaces, quotes, links, hidden files, sizes and times", { skip: unavailable }, async () => {
  await withRealServer(async ({ manager, remote }) => {
    fs.writeFileSync(path.join(remote, "plain.txt"), "0123456789");
    fs.writeFileSync(path.join(remote, "a file with spaces.log"), "x");
    fs.writeFileSync(path.join(remote, "it's a \"quoted\" $(name).txt"), "y");
    fs.writeFileSync(path.join(remote, ".hidden"), "z");
    fs.mkdirSync(path.join(remote, "a folder"));
    fs.symlinkSync(path.join(remote, "plain.txt"), path.join(remote, "link to plain"));

    const listing = await manager.list(remote);
    const byName = new Map(listing.entries.map((entry) => [entry.name, entry]));
    assert.deepEqual([...byName.keys()].sort(), [
      ".hidden", "a file with spaces.log", "a folder", "it's a \"quoted\" $(name).txt",
      "link to plain", "plain.txt",
    ], "every name real ls printed came back intact");

    assert.equal(byName.get("plain.txt").size, 10, "the size column is read correctly");
    assert.equal(byName.get("a folder").directory, true);
    assert.equal(byName.get("link to plain").symlink, true);
    assert.equal(byName.get("link to plain").name, "link to plain", "the link target is not part of the name");
    assert.match(byName.get("plain.txt").mode, /^-rw/, "and so is the mode string");

    // Written moments ago, so the timestamp real ls printed has to land near now.
    const written = new Date(byName.get("plain.txt").modified).getTime();
    assert.ok(Math.abs(Date.now() - written) < 5 * 60 * 1000,
      `the modified time should be recent, got ${byName.get("plain.txt").modified}`);
  });
});

test("real scp carries bytes exactly, in both directions", { skip: unavailable }, async () => {
  await withRealServer(async ({ manager, remote, localRoot }) => {
    // Binary, and big enough to cross several network reads.
    const payload = Buffer.alloc(300_000);
    for (let index = 0; index < payload.length; index += 1) payload[index] = index % 256;
    const source = path.join(localRoot, "payload with space.bin");
    fs.writeFileSync(source, payload);
    fs.writeFileSync(path.join(localRoot, "empty.dat"), "");

    await manager.upload([source, path.join(localRoot, "empty.dat")], remote);
    assert.deepEqual(fs.readFileSync(path.join(remote, "payload with space.bin")), payload,
      "every byte survived the upload");
    assert.equal(fs.statSync(path.join(remote, "empty.dat")).size, 0, "including a file with no bytes at all");

    const destination = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-real-down-"));
    try {
      const [returned] = await manager.download([path.posix.join(remote, "payload with space.bin")], destination);
      assert.deepEqual(fs.readFileSync(returned), payload, "and again on the way back");
    } finally {
      fs.rmSync(destination, { recursive: true, force: true });
    }
  });
});

test("real folders: created, filled, renamed, walked, searched and removed", { skip: unavailable }, async () => {
  await withRealServer(async ({ manager, remote, localRoot }) => {
    const created = await manager.mkdir(remote, "made on the host");
    assert.equal(fs.statSync(path.join(remote, "made on the host")).isDirectory(), true);

    const tree = path.join(localRoot, "project");
    fs.mkdirSync(path.join(tree, "src", "deep"), { recursive: true });
    fs.writeFileSync(path.join(tree, "README.md"), "# real\n");
    fs.writeFileSync(path.join(tree, "src", "deep", "target-file.txt"), "found me\n");
    await manager.upload([tree], created.path);
    assert.equal(fs.readFileSync(path.join(created.path, "project", "src", "deep", "target-file.txt"), "utf8"),
      "found me\n", "a recursive upload built the whole tree");

    const found = await manager.search(remote, "target-file", true);
    assert.deepEqual(found.entries.map((entry) => entry.name), ["target-file.txt"],
      "and a recursive search over real ls output finds it");

    const renamed = await manager.rename(path.posix.join(created.path, "project"), "renamed project");
    assert.equal(fs.existsSync(path.join(created.path, "renamed project")), true);
    assert.equal(renamed.path, path.posix.join(created.path, "renamed project"));

    const editable = path.posix.join(created.path, "notes.ini");
    await manager.writeFile(editable, "mode=first\n");
    assert.equal((await manager.readFile(editable)).text, "mode=first\n");
    await manager.writeFile(editable, "mode=second\n");
    assert.equal(fs.readFileSync(editable, "utf8"), "mode=second\n");

    const removal = await manager.delete([created.path]);
    assert.deepEqual(removal, { deleted: 1, failures: [] });
    assert.equal(fs.existsSync(created.path), false, "and the whole tree is gone afterwards");
  });
});

test("real SFTP-only refuses this host instead of falling back", { skip: unavailable }, async () => {
  const server = await startRealServer();
  const localRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-real-strict-"));
  const manager = new SshManager({
    knownHostsPath: path.join(localRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  try {
    await assert.rejects(() => manager.connect({
      host: "127.0.0.1",
      port: server.port,
      username: server.username,
      authType: "key",
      keyPath: server.clientKey,
      protocol: "sftp",
    }), /SFTP is unavailable/);
  } finally {
    await manager.disconnect();
    server.stop();
    fs.rmSync(localRoot, { recursive: true, force: true });
  }
});

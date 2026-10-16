"use strict";

// An unprivileged OpenSSH server on a high port, for tests that have to meet the real
// `sftp-server`, `ls`, `mv` and `scp` rather than this project's emulator: a named
// pipe that blocks sftp-server, a device that never ends, posix-rename. It has its
// own host key, its own authorized_keys and a throwaway directory, listens on
// 127.0.0.1 only, and is stopped and removed by `withRealServer` whatever happens.
// Where sshd or ssh-keygen is missing it reports why, so the tests can skip.

const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");
const { SshManager } = require("../../lib/ssh-manager");

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
const sftpServer = ["/usr/lib/openssh/sftp-server", "/usr/libexec/openssh/sftp-server",
  "/usr/lib/ssh/sftp-server", "/usr/libexec/sftp-server"].find((candidate) => fs.existsSync(candidate)) || null;
// Undefined rather than null: the test runner skips on any value but false/undefined.
const unavailable = process.platform === "win32" ? "not applicable on Windows"
  : !sshdBinary ? "no sshd binary on this machine"
    : !keygenBinary ? "no ssh-keygen on this machine"
      : undefined;
const sftpUnavailable = unavailable || (sftpServer ? undefined : "no sftp-server on this machine");

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

async function startRealServer({ sftp = true } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-hardening-"));
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
    `Port ${port}`, "ListenAddress 127.0.0.1", `HostKey ${hostKey}`,
    `AuthorizedKeysFile ${authorized}`, `PidFile ${path.join(root, "sshd.pid")}`,
    "StrictModes no", "UsePAM no", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
    "PubkeyAuthentication yes", "PermitRootLogin no", "PrintMotd no", "X11Forwarding no",
    sftp ? `Subsystem sftp ${sftpServer}` : "", "",
  ].join("\n"));
  const logPath = path.join(root, "sshd.log");
  const daemon = spawn(sshdBinary, ["-D", "-f", configPath, "-E", logPath], { stdio: "ignore" });
  const stop = () => {
    try { daemon.kill("SIGTERM"); } catch { /* already gone */ }
    try { execFileSync("chmod", ["-R", "u+rwx", root]); } catch { /* best effort */ }
    fs.rmSync(root, { recursive: true, force: true });
  };
  try {
    await waitForPort(port, Date.now() + 8000);
  } catch (error) {
    const log = fs.existsSync(logPath) ? fs.readFileSync(logPath, "utf8") : "";
    stop();
    throw new Error(`${error.message}\n${log}`);
  }
  return { port, remote, clientKey, username: os.userInfo().username, root, stop };
}

// `protocol` is "sftp" or "scp"; SCP mode runs against a server with no subsystem.
async function withRealServer({ protocol = "sftp" } = {}, run) {
  const server = await startRealServer({ sftp: protocol !== "scp" });
  const localRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-hardening-local-"));
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
      protocol,
    });
    return await run({ manager, server, connection, remote: server.remote, localRoot });
  } finally {
    await manager.disconnect().catch(() => undefined);
    server.stop();
    try { execFileSync("chmod", ["-R", "u+rwx", localRoot]); } catch { /* best effort */ }
    fs.rmSync(localRoot, { recursive: true, force: true });
  }
}

module.exports = { withRealServer, unavailable, sftpUnavailable };

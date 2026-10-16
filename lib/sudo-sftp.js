"use strict";

// An SFTP session that runs as another user: the host's own sftp-server, started
// through sudo on an ordinary exec channel, with ssh2's SFTP client speaking to it.
// Everything the file pane does then happens as that user, exactly as it would over
// the SFTP subsystem, which always runs as the user who logged in.
//
// ssh2 builds its SFTP client only on top of a subsystem request, so the client is
// constructed here directly and given the exec channel to read and write. It needs
// four things from its channel -- something to write packets to, something to close,
// the server's identification string, and to be fed what arrives -- and those are
// all it gets.

const { SFTP } = require("ssh2/lib/protocol/SFTP.js");
const { SftpTransport } = require("./sftp-transport");

const OPEN_TIMEOUT = 20000;
const READY = "SSH-WORKBENCH-SUDO-READY";
const PROMPT = "SSH-WORKBENCH-SUDO-PASSWORD:";

// Where the common systems install it: Debian and Ubuntu, Red Hat and Fedora, Arch,
// and the BSDs and macOS.
const SFTP_SERVERS = [
  "/usr/lib/openssh/sftp-server",
  "/usr/libexec/openssh/sftp-server",
  "/usr/lib/ssh/sftp-server",
  "/usr/libexec/sftp-server",
  "/usr/lib/sftp-server",
  "/usr/local/libexec/sftp-server",
];

// `rejected` tells a wrong password apart from a missing one: a password sudo has
// refused must never be offered again, because every refusal is a failed login on
// the host and enough of them lock the account.
class SudoPasswordNeeded extends Error {
  constructor(message, { rejected = false } = {}) {
    super(message);
    this.sudoPasswordNeeded = true;
    this.rejected = rejected;
  }
}

// The script runs as the target user once sudo has let it through. Saying so on
// stderr before anything else is how the far end's answer is told apart from sudo's
// own: until the marker arrives, nothing may be written that sftp-server would
// read. It holds no single quote and no backslash, so one pair of single quotes
// carries it through any login shell, fish included.
function sudoCommand(uid, { password }) {
  const script = [
    `echo "${READY} $(id -un)" >&2`,
    `for p in ${SFTP_SERVERS.join(" ")}; do if [ -x "$p" ]; then exec "$p"; fi; done`,
    "echo \"sftp-server was not found on this host\" >&2",
    "exit 127",
  ].join("; ");
  const as = uid === 0 ? "" : ` -u "#${Number(uid)}"`;
  const how = password ? `-S -p "${PROMPT}"` : "-n";
  // sudo's own messages in English, so a refusal can be recognised by its words.
  return `env LC_ALL=C sudo ${how}${as} -- /bin/sh -c '${script}'`;
}

function openOnce(client, uid, password) {
  return new Promise((resolve, reject) => {
    client.exec(sudoCommand(uid, { password }), (error, stream) => {
      if (error) return reject(error);
      let stderr = "";
      let sftp = null;
      let settled = false;
      const timer = setTimeout(() => fail(new Error("sudo did not answer")), OPEN_TIMEOUT);
      const fail = (failure) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { stream.close(); } catch { /* already gone */ }
        reject(failure);
      };
      const succeed = (user) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ transport: new SftpTransport(sftp), user });
      };

      // The password goes in straight away rather than in answer to the prompt.
      // This attempt is only made once `sudo -n` has said a password is needed, and
      // the prompt sudo shows is not always the one asked for: a PAM module with its
      // own wording (LDAP, SSSD, Kerberos), or `passprompt_override`, replaces it.
      // sudo -S reads the line from standard input whatever the prompt said.
      if (password) stream.write(`${password}\n`);

      stream.stderr.on("data", (chunk) => {
        if (sftp) return;
        stderr += chunk.toString("utf8");
        // Asked again means the answer was wrong. sudo would read the next thing
        // written as another attempt, so nothing more is.
        if (stderr.split(PROMPT).length > 2 || /Sorry, try again|incorrect password/i.test(stderr)) {
          return fail(new SudoPasswordNeeded("sudo did not accept the password", { rejected: true }));
        }
        // The whole line, so a name split across two reads is not cut short.
        const ready = new RegExp(`${READY} (\\S*)\\r?\\n`).exec(stderr);
        if (ready) start(ready[1]);
      });

      const start = (user) => {
        sftp = sftpOverStream(stream, client._protocol?._remoteIdentRaw);
        sftp.once("ready", () => succeed(user));
        sftp.once("error", (failure) => fail(failure));
        sftp._init();
      };

      stream.once("close", () => {
        if (sftp) {
          sftp.push(null);
          sftp.outgoing.state = "closed";
          sftp.emit("close");
        }
        if (settled) return;
        const said = stderr.split("\n").map((line) => line.trim())
          .filter((line) => line && !line.includes(PROMPT) && !line.includes(READY));
        if (said.some((line) => /password is required|a terminal is required/i.test(line))) {
          return fail(new SudoPasswordNeeded("sudo needs a password"));
        }
        fail(new Error(said[said.length - 1] || "sudo refused"));
      });
      stream.on("data", (chunk) => { if (sftp) sftp.push(chunk); });
    });
  });
}

function sftpOverStream(stream, remoteIdentRaw) {
  const channel = {
    _protocol: {
      _remoteIdentRaw: remoteIdentRaw,
      channelData: (_id, data) => stream.write(data),
      channelClose: () => { try { stream.close(); } catch { /* already gone */ } },
    },
  };
  // The exec channel does its own flow control underneath, so this layer's window
  // is unlimited; packets are cut at the size ssh2 would use for a subsystem.
  return new SFTP(channel, {
    type: "session",
    incoming: { id: 0, window: Infinity, packetSize: 32768, state: "open" },
    outgoing: { id: 0, window: Infinity, packetSize: 32768, state: "open" },
  });
}

// Without a password first: a host that lets this user sudo freely should never be
// sent one. With the password only when sudo says it needs it.
async function openSudoSftp(client, uid, password = null) {
  try {
    return await openOnce(client, uid, null);
  } catch (error) {
    if (!error.sudoPasswordNeeded || !password) throw error;
  }
  return openOnce(client, uid, password);
}

module.exports = { openSudoSftp, sudoCommand, SudoPasswordNeeded, SFTP_SERVERS };

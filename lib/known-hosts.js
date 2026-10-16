"use strict";

const fs = require("node:fs");
const { writeFileAtomic, setAside } = require("./atomic-write");

const STORE_VERSION = 1;

// The name a host is remembered under. DNS names are not case-sensitive and a
// trailing dot names the same host, so "Server.Example.Test." and
// "server.example.test" are one server -- and treating them as two is worse than
// untidy: a changed key reached through the spelling never used before is shown as a
// first connection, with a mild "trust this?" in place of the warning that the key no
// longer matches. Brackets around an IPv6 address are notation, not part of it.
function normalizeHost(host) {
  let text = String(host ?? "").trim().toLowerCase();
  if (text.startsWith("[") && text.endsWith("]")) text = text.slice(1, -1);
  while (text.length > 1 && text.endsWith(".")) text = text.slice(0, -1);
  return text;
}

function hostIdentity(host, port) {
  return `${normalizeHost(host)}:${Number(port || 22)}`;
}

// An identity string as stored or as passed in -- "host:port", where the host may
// itself hold colons -- in the form above.
function normalizeIdentity(identity) {
  const text = String(identity ?? "");
  const split = text.lastIndexOf(":");
  if (split < 1) return normalizeHost(text);
  const port = text.slice(split + 1);
  return /^\d+$/.test(port) ? hostIdentity(text.slice(0, split), port) : normalizeHost(text);
}

function validEntry(entry) {
  return Boolean(entry && typeof entry === "object" && typeof entry.sha256 === "string" && /^[0-9a-f]{64}$/i.test(entry.sha256));
}

class KnownHosts {
  constructor(filePath) {
    this.filePath = filePath;
    this.hosts = {};
    this.loadWarning = null;
    // Set when the file on disk must not be written over; see load().
    this.readOnly = null;
    // Prompts waiting their turn, one queue per host; see exclusive().
    this.queues = new Map();
    this.load();
  }

  load() {
    let raw;
    try {
      raw = fs.readFileSync(this.filePath, "utf8");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      this.hosts = {};
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object" || !parsed.hosts || typeof parsed.hosts !== "object") {
        throw new Error("not a host fingerprint file");
      }
    } catch {
      // An unreadable trust store must not brick the application. Keep the
      // damaged file for inspection and start over, so every host is treated as
      // unseen and confirmed again instead of silently trusted.
      this.hosts = {};
      const kept = setAside(this.filePath, "corrupt", { move: true });
      if (kept) {
        this.loadWarning = `Saved host fingerprints could not be read and were set aside as ${kept}; hosts will be confirmed again.`;
      } else {
        this.readOnly = "Saved host fingerprints could not be read, and no copy of them could be kept, so new ones are not being saved.";
        this.loadWarning = this.readOnly;
      }
      return;
    }

    // A file written by a later build may say things this one cannot, and writing
    // it back in this build's terms would lose them. It is read for what this build
    // understands and left alone.
    if (Number(parsed.version) > STORE_VERSION) {
      this.readOnly = "Saved host fingerprints were written by a newer version of SSH Workbench, so this one is not changing them.";
      this.loadWarning = this.readOnly;
    }

    // Entries written before host names were normalized are brought into the same
    // form, so a key trusted as "Server.Example.Test" is the one compared against
    // when "server.example.test" connects. Two spellings that now fall together keep
    // the most recently trusted key: the other, if it is ever presented again, is
    // then met with the changed-key warning rather than accepted.
    const hosts = {};
    let unrecognised = 0;
    for (const [identity, entry] of Object.entries(parsed.hosts)) {
      if (!validEntry(entry)) {
        unrecognised += 1;
        continue;
      }
      const key = normalizeIdentity(identity);
      const current = hosts[key];
      if (!current || String(entry.trustedAt || "") > String(current.trustedAt || "")) hosts[key] = entry;
    }
    this.hosts = hosts;
    // An entry this build cannot use is not one it may quietly delete: the next
    // remember would rewrite the file without it. A copy is kept first, and the
    // file is not written at all if no copy could be.
    if (unrecognised && !this.readOnly) {
      const kept = setAside(this.filePath, "unrecognised");
      if (kept) {
        this.loadWarning = `${unrecognised} saved host fingerprint${unrecognised === 1 ? " was" : "s were"} not recognised; the file was copied to ${kept} before anything changes.`;
      } else {
        this.readOnly = "Some saved host fingerprints were not recognised and no copy of them could be kept, so new ones are not being saved.";
        this.loadWarning = this.readOnly;
      }
    }
  }

  get(identity) {
    return this.hosts[normalizeIdentity(identity)] || null;
  }

  remember(identity, sha256Hex) {
    if (this.readOnly) throw new Error(this.readOnly);
    this.hosts[normalizeIdentity(identity)] = { sha256: sha256Hex, trustedAt: new Date().toISOString() };
    writeFileAtomic(this.filePath, `${JSON.stringify({ version: STORE_VERSION, hosts: this.hosts }, null, 2)}\n`);
  }

  // Runs `task` once every earlier task for the same host has finished. Two tabs
  // reaching a new host at once would otherwise each be shown a "first connection"
  // prompt built before either was answered, and trusting the second -- a different
  // key, on a different route -- would replace the first with no warning at all. One
  // prompt per host at a time, each reading what is stored only once it is its turn,
  // means the second is asked as what it is: a key that does not match.
  exclusive(identity, task) {
    const key = normalizeIdentity(identity);
    const previous = this.queues.get(key) || Promise.resolve();
    const turn = previous.then(() => task());
    const settled = turn.catch(() => undefined);
    this.queues.set(key, settled);
    settled.then(() => {
      if (this.queues.get(key) === settled) this.queues.delete(key);
    });
    return turn;
  }
}

function displayFingerprint(sha256Hex) {
  return `SHA256:${Buffer.from(sha256Hex, "hex").toString("base64").replace(/=+$/, "")}`;
}

module.exports = { KnownHosts, displayFingerprint, hostIdentity, normalizeHost };

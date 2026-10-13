"use strict";

const fs = require("node:fs");
const { writeFileAtomic } = require("./atomic-write");

class KnownHosts {
  constructor(filePath) {
    this.filePath = filePath;
    this.hosts = {};
    this.loadWarning = null;
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
    try {
      const parsed = JSON.parse(raw);
      this.hosts = parsed && parsed.hosts && typeof parsed.hosts === "object" ? parsed.hosts : {};
    } catch {
      // An unreadable trust store must not brick the application. Keep the
      // damaged file for inspection and start over, so every host is treated as
      // unseen and confirmed again instead of silently trusted.
      this.hosts = {};
      this.loadWarning = "Saved host fingerprints could not be read and were set aside; hosts will be confirmed again.";
      try { fs.renameSync(this.filePath, `${this.filePath}.corrupt`); } catch { /* leave it in place */ }
    }
  }

  get(identity) {
    return this.hosts[identity] || null;
  }

  remember(identity, sha256Hex) {
    this.hosts[identity] = { sha256: sha256Hex, trustedAt: new Date().toISOString() };
    writeFileAtomic(this.filePath, `${JSON.stringify({ version: 1, hosts: this.hosts }, null, 2)}\n`);
  }
}

function displayFingerprint(sha256Hex) {
  return `SHA256:${Buffer.from(sha256Hex, "hex").toString("base64").replace(/=+$/, "")}`;
}

module.exports = { KnownHosts, displayFingerprint };

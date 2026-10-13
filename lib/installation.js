"use strict";

const fs = require("node:fs");
const path = require("node:path");

// The single-instance lock is keyed to the application, not to the folder it was
// installed in, so launching a freshly extracted copy while an older one is still
// running has the older process serve the window: the new build appears to have none
// of its new behaviour. Telling two copies apart needs only their executables'
// paths, resolved, and compared the way the platform compares paths.
function sameInstallation(launchedPath, runningPath) {
  if (!launchedPath || !runningPath) return true;
  const compare = (value) => {
    const resolved = path.resolve(String(value));
    return process.platform === "win32" ? resolved.toLowerCase() : resolved;
  };
  return compare(launchedPath) === compare(runningPath);
}

// Which installation this process belongs to. An AppImage is extracted to a fresh
// mount point on every launch, so its executable path differs from run to run and
// two launches of one file would look like two installations; the path of the file
// itself is what identifies it. The environment override exists for the tests, which
// have to make one build stand in for two.
function installationPath({ env = process.env, execPath = process.execPath } = {}) {
  return env.SSH_WORKBENCH_INSTALLATION || env.APPIMAGE || execPath;
}

// package.json inside an asar archive, read without unpacking it. The format is a
// 16-byte preamble — the last four bytes being the length of the header JSON — then
// the header, then the files, each at an offset from the end of the header pickle.
function readAsarPackage(archivePath) {
  const handle = fs.openSync(archivePath, "r");
  try {
    const preamble = Buffer.alloc(16);
    if (fs.readSync(handle, preamble, 0, 16, 0) < 16) return null;
    const pickleSize = preamble.readUInt32LE(4);
    const headerLength = preamble.readUInt32LE(12);
    if (!headerLength || headerLength > 64 * 1024 * 1024) return null;
    const header = Buffer.alloc(headerLength);
    fs.readSync(handle, header, 0, headerLength, 16);
    const entry = JSON.parse(header.toString("utf8"))?.files?.["package.json"];
    if (!entry || typeof entry.size !== "number") return null;
    const body = Buffer.alloc(entry.size);
    fs.readSync(handle, body, 0, entry.size, 8 + pickleSize + Number(entry.offset));
    return JSON.parse(body.toString("utf8"));
  } finally {
    fs.closeSync(handle);
  }
}

// Which build lives beside an executable. A copy that is already running cannot be
// asked what version it is — every build before 0.11.5 has nothing to ask on, and a
// running process answers no questions — but its own package.json sits next to it in
// the folder it was extracted into, and that is the build that is running.
function installedVersion(execPath) {
  if (!execPath) return null;
  const beside = path.dirname(String(execPath));
  const candidates = [
    path.join(beside, "resources"),
    // A macOS bundle keeps the executable one level deeper, under Contents/MacOS.
    path.join(beside, "..", "Resources"),
  ];
  for (const resources of candidates) {
    try {
      const unpacked = path.join(resources, "app", "package.json");
      if (fs.existsSync(unpacked)) {
        const version = JSON.parse(fs.readFileSync(unpacked, "utf8"))?.version;
        if (version) return String(version);
      }
    } catch { /* an unreadable folder is simply not an answer */ }
    try {
      const archive = path.join(resources, "app.asar");
      if (fs.existsSync(archive)) {
        const version = readAsarPackage(archive)?.version;
        if (version) return String(version);
      }
    } catch { /* nor is a truncated or foreign archive */ }
  }
  return null;
}

module.exports = { sameInstallation, installationPath, installedVersion };

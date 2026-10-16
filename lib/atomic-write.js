"use strict";

// The two files this application cannot afford to lose — the saved connections and
// the trusted host fingerprints — are both rewritten whole rather than appended to,
// and both are written the same way: beside the real file, then renamed over it.
// The rename is what makes a reader see either the old file or the new one and
// never half of either.
//
// The flush before the rename is the part that is easy to leave out and hard to
// notice missing. Without it the rename can reach the disk while the contents it
// points at have not, and a machine that loses power in that window comes back to a
// file of the right name and no length — which, for the connection store, is every
// saved credential gone.

const fs = require("node:fs");
const path = require("node:path");

// The file a write lands in. A store that is a symbolic link -- into a dotfiles
// repository, or a synced folder -- is meant to stay one: renaming a fresh file over
// the link would replace the link itself, and from then on every change would go to a
// private copy while the file the link pointed at quietly stopped hearing about them.
// So the write goes beside the real file and is renamed over that instead. A link
// whose target does not exist yet is followed too, by reading it, so the first save
// creates the file it names rather than replacing it.
function writeTarget(filePath) {
  try {
    return fs.realpathSync(filePath);
  } catch { /* not there yet, or a dangling link */ }
  try {
    const link = fs.readlinkSync(filePath);
    return path.resolve(path.dirname(filePath), link);
  } catch {
    return filePath;
  }
}

function writeFileAtomic(requestedPath, contents, { mode = 0o600 } = {}) {
  const filePath = writeTarget(requestedPath);
  const directory = path.dirname(filePath);
  fs.mkdirSync(directory, { recursive: true });
  const temporary = `${filePath}.tmp`;
  const handle = fs.openSync(temporary, "w", mode);
  try {
    // `open` honours the mode only when it creates the file, and a temporary left
    // behind by an interrupted write is one it did not create. Narrowing it before
    // the contents go in means a stale permissive file is never briefly holding a
    // secret, and that a failure part way through cannot skip the narrowing.
    try { fs.fchmodSync(handle, mode); } catch { /* a platform without POSIX modes */ }
    fs.writeFileSync(handle, contents);
    fs.fsyncSync(handle);
  } finally {
    fs.closeSync(handle);
  }
  fs.renameSync(temporary, filePath);
  // Flushing the file protects its contents; the directory entry that points at
  // them is a separate write, and on POSIX it needs its own flush to survive a
  // power loss. Windows has no directory handle to open and does not need one.
  try {
    const parent = fs.openSync(directory, "r");
    try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
  } catch { /* not a platform where a directory can be flushed */ }
}

// Keeps a copy of a file that is about to stop being trusted -- damaged, or holding
// entries this build cannot read -- under a name nothing else is using. A fixed name
// would let the second such copy replace the first, which is usually the one worth
// having; and a rename that fails, because something is already sitting at that name
// or a scanner is holding the file, would leave the original in place for the next
// save to overwrite while the warning claimed it had been kept.
//
// The copy is made with exclusive creation, so it can never land on top of anything,
// and it is the copy -- not a rename -- that is relied on. Removing the original is
// then optional (`move`), and failing to is harmless: the next write replaces it whole.
// Null means no copy could be made, and the caller must not write over the original.
function setAside(filePath, suffix, { move = false } = {}) {
  const source = writeTarget(filePath);
  for (let attempt = 0; attempt < 1000; attempt += 1) {
    const candidate = attempt ? `${filePath}.${suffix}.${attempt}` : `${filePath}.${suffix}`;
    try {
      fs.copyFileSync(source, candidate, fs.constants.COPYFILE_EXCL);
    } catch (error) {
      if (error?.code === "EEXIST" || error?.code === "EISDIR" || error?.code === "ENOTDIR") continue;
      return null;
    }
    try { fs.chmodSync(candidate, 0o600); } catch { /* a platform without POSIX modes */ }
    if (move) {
      try { fs.unlinkSync(source); } catch { /* the next write replaces it whole */ }
    }
    return candidate;
  }
  return null;
}

module.exports = { writeFileAtomic, setAside };

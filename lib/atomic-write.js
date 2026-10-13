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

function writeFileAtomic(filePath, contents, { mode = 0o600 } = {}) {
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

module.exports = { writeFileAtomic };

"use strict";

const path = require("node:path");
const { temporaryName } = require("./remote-path");

// Reads are issued this many at a time, each the size OpenSSH answers in one packet,
// so a capped read moves at the speed of the link rather than one round trip per
// 32 KB.
const READ_CHUNK = 32768;
const READ_AHEAD = 16;

// Operations this class answers itself, built from the SFTP requests ssh2 offers.
// Everything else goes straight through to the session under its own name.
const OWN = new Set(["readCapped", "replace"]);

function tooLarge(limit) {
  const error = new Error(`The file is larger than ${limit} bytes`);
  error.tooLarge = true;
  return error;
}

// The SFTP session, behind the same two calls the shell transport answers, so the
// rest of the manager does not know or care which one it is talking to.
class SftpTransport {
  constructor(sftp) {
    this.sftp = sftp;
    this.kind = "sftp";
    // A real SFTP session multiplexes requests over one channel, so a recursive
    // search can keep as many reads in flight as it likes.
    this.concurrencyLimit = Infinity;
  }

  call(method, args) {
    if (OWN.has(method)) return this[method](...args);
    return new Promise((resolve, reject) => {
      this.sftp[method](...args, (error, ...values) => {
        if (error) reject(error);
        else resolve(values.length > 1 ? values : values[0]);
      });
    });
  }

  close() {
    try { this.sftp.end(); } catch { /* already closed */ }
  }

  // At most `limit` bytes of a file, or a `tooLarge` failure. ssh2's own readFile
  // reads until the server says end-of-file, and a file whose size is not what it
  // seems -- /dev/zero reports 0 and never ends, a log grows while it is read --
  // was read until the main process ran out of memory. This stops one byte past the
  // limit whatever the far end claims.
  async readCapped(target, limit) {
    const handle = await this.call("open", [target, "r"]);
    const pieces = [];
    let total = 0;
    let queue = [];
    try {
      let next = 0;
      const issue = () => {
        const at = next;
        const size = Math.min(READ_CHUNK, limit + 1 - at);
        next += size;
        const buffer = Buffer.allocUnsafe(size);
        const read = new Promise((resolve, reject) => {
          this.sftp.read(handle, buffer, 0, size, at, (error, count) => (
            error ? reject(error) : resolve({ data: buffer.subarray(0, count || 0), size })
          ));
        });
        read.catch(() => undefined);
        queue.push(read);
      };
      while (total <= limit) {
        while (queue.length < READ_AHEAD && next <= limit) issue();
        if (!queue.length) break;
        const { data, size } = await queue.shift();
        pieces.push(data);
        total += data.length;
        if (data.length < size) {
          // End of file, or a server that answered with less than was asked. The
          // reads already sent assumed full answers, so they are dropped and reading
          // carries on from what actually arrived; at the end that next read is empty.
          await Promise.allSettled(queue);
          queue = [];
          next = total;
          if (!data.length) break;
        }
      }
    } finally {
      await Promise.allSettled(queue);
      await this.call("close", [handle]).catch(() => undefined);
    }
    if (total > limit) throw tooLarge(limit);
    return Buffer.concat(pieces, total);
  }

  // The last step of an overwrite: the finished temporary copy takes the name, so the
  // name always holds the old file or the whole new one. OpenSSH's posix-rename does
  // that in one step. A server without it gets plain SFTP rename, which refuses an
  // existing target, so the old file is first moved aside, the new one put in its
  // place, and only then is the old one removed -- and moved back if the second step
  // fails, so nothing is lost either way.
  async replace(source, target) {
    const posix = await new Promise((resolve, reject) => {
      try {
        this.sftp.ext_openssh_rename(source, target, (error) => (error ? reject(error) : resolve(true)));
      } catch {
        resolve(false); // the server did not offer the extension
      }
    });
    if (posix) return { ok: true };
    const existing = await this.call("lstat", [target]).catch(() => null);
    if (!existing) {
      await this.call("rename", [source, target]);
      return { ok: true };
    }
    const aside = path.posix.join(path.posix.dirname(target), temporaryName(path.posix.basename(target), "old"));
    await this.call("rename", [target, aside]);
    try {
      await this.call("rename", [source, target]);
    } catch (error) {
      await this.call("rename", [aside, target]).catch(() => undefined);
      throw error;
    }
    await this.call("unlink", [aside]).catch(() => undefined);
    return { ok: true };
  }
}

module.exports = { SftpTransport };

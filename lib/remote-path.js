"use strict";

const crypto = require("node:crypto");
const path = require("node:path");

function remotePath(value, fallback = "/") {
  const input = String(value || fallback);
  if (input.includes("\0")) throw new Error("Remote path contains a null byte");
  const absolute = input.startsWith("/") ? input : `/${input}`;
  return path.posix.normalize(absolute);
}

// A single name — never a path. Used for names typed by a person and for names the
// far end sends back, which are data rather than structure: a separator, a dot-dot or
// a null byte would change the meaning of the path they are joined to. No filesystem
// can hold such a name; a hostile or broken server can still claim one.
//
// A backslash is not one of them. On the host it is an ordinary character -- systemd
// spells a dash in a unit name as \x2d, so /etc/systemd/system is full of them --
// and refusing it hid those files and stopped every recursive action on the folder
// holding one. Where it does mean something is a Windows disk, and that is decided
// by `localName` below, at the moment a name is about to become a local file.
function safeRemoteName(name) {
  const text = String(name ?? "");
  return Boolean(text) && text !== "." && text !== ".." && !/[/\0]/.test(text);
}

// What a remote name becomes as a file on this computer. `separator` is the local
// path module's, so the rule follows the disk being written to. On Windows a
// backslash is a separator and a colon names a drive or an alternate data stream,
// so either would put the file somewhere other than the folder that was chosen;
// they are written as underscores instead, which is what keeps `..\..\evil.bat`
// from climbing out. Everywhere else the name is used exactly as the host spells it.
function localName(name, separator = path.sep) {
  const text = String(name ?? "");
  if (!safeRemoteName(text)) return null;
  if (separator !== "\\") return text;
  const written = text.replace(/[\\:]/g, "_");
  return written === "." || written === ".." ? null : written;
}

// A name for the temporary copy that sits beside `name` while it is being written,
// on either side of a transfer. It is hidden, says what wrote it, and cannot collide
// with a real file or with another copy in flight. Most filesystems allow 255 bytes
// in a name, so a long original is shortened -- by whole characters, never through
// the middle of one -- to leave room for the rest.
function temporaryName(name, tag = "part") {
  let base = String(name ?? "");
  while (Buffer.byteLength(base) > 180) base = Array.from(base).slice(0, -1).join("");
  return `.${base}.swb-${crypto.randomBytes(4).toString("hex")}.${tag}`;
}

function remoteJoin(parent, name) {
  if (!safeRemoteName(name)) throw new Error("Invalid file name");
  return path.posix.join(remotePath(parent), name);
}

function remoteParent(value) {
  const normalized = remotePath(value);
  return normalized === "/" ? null : path.posix.dirname(normalized);
}

module.exports = { remotePath, remoteJoin, remoteParent, safeRemoteName, localName, temporaryName };

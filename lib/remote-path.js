"use strict";

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
function safeRemoteName(name) {
  const text = String(name ?? "");
  return Boolean(text) && text !== "." && text !== ".." && !/[/\\\0]/.test(text);
}

function remoteJoin(parent, name) {
  if (!safeRemoteName(name)) throw new Error("Invalid file name");
  return path.posix.join(remotePath(parent), name);
}

function remoteParent(value) {
  const normalized = remotePath(value);
  return normalized === "/" ? null : path.posix.dirname(normalized);
}

module.exports = { remotePath, remoteJoin, remoteParent, safeRemoteName };

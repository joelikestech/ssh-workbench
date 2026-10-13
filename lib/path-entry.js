"use strict";

// A path typed or pasted into the path box, turned into something that can be sent
// to the host. What arrives is rarely clean: Explorer's "Copy as path" wraps the
// result in quotes, a path copied out of a chat message or a log carries a trailing
// newline, and a path someone reads off their own machine is not a path on the host
// at all. Sorting that out here, away from the window, is what makes it testable.
//
// Normalising "." and ".." is deliberately not done here. The manager runs every
// path it is given through `remotePath`, which normalises on the POSIX rules the far
// end actually uses; doing it twice, in two dialects, is how the two would drift.

// POSIX single quotes cannot hold a quote of their own, so a path with one in it is
// written as several quoted runs with an escaped quote between them: /tmp/it's here
// comes out as '/tmp/it'\''s here'. Reading that back means undoing the whole
// construction rather than removing the outer pair, which would leave the escape
// sitting in the middle of the path. `null` means the text is not one of these --
// either it was never quoted, or the quoting was cut off part way.
function unquote(text) {
  let value = "";
  let index = 0;
  while (index < text.length) {
    if (text[index] === "'") {
      const end = text.indexOf("'", index + 1);
      if (end < 0) return null;
      value += text.slice(index + 1, end);
      index = end + 1;
    } else if (text.startsWith("\\'", index)) {
      value += "'";
      index += 2;
    } else {
      return null;
    }
  }
  return value;
}

// Only the first line that has anything on it. A multi-line clipboard is usually one
// path followed by whatever else was selected, and guessing at the rest would be
// worse than ignoring it.
//
// What quotes enclose is the path exactly, spaces at either end included: saying so
// is what the quoting was for. `null` says the line opened a quote and never closed
// it -- a path cut off by the copy that fetched it -- which is worth reporting
// rather than hanging the remains off the folder on screen.
function firstLine(text) {
  const line = (String(text ?? "").replace(/\r/g, "").split("\n").find((value) => value.trim()) || "").trim();
  // Explorer's "Copy as path" wraps its result in double quotes and never escapes
  // anything inside, because no Windows path can hold one.
  const windows = /^"(.*)"$/.exec(line);
  if (windows) return windows[1];
  if (line.startsWith("'")) return unquote(line);
  return line;
}

// A drive letter or a UNC share is a path on the machine the window is running on.
// Sending it would earn a "no such file" from the far end, which is true but says
// nothing about what went wrong.
function looksLocal(value) {
  return /^[A-Za-z]:[\\/]/.test(value) || value.startsWith("\\\\");
}

// "~" is a shell convention that SFTP knows nothing about, and a path with no leading
// slash is read from the folder on screen -- both are what someone typing a path into
// a file manager means by them.
function absolute(value, home, cwd) {
  // The base loses any trailing slash before the join, so hanging a relative path off
  // the root gives "/etc" rather than "//etc" -- a leading double slash is its own
  // thing in POSIX, and there is no reason to hand the far end one.
  const under = (base, rest) => `${base.replace(/\/+$/, "")}/${rest}`;
  if (value === "~") return home;
  if (value.startsWith("~/")) return under(home, value.slice(2));
  if (!value.startsWith("/")) return under(cwd, value);
  return value;
}

// Either `{ path }` to go to, or `{ error }` to put on the status line. A session
// object can be passed straight in, since it carries `home` and `cwd` already.
function pathEntry(text, { home = "/", cwd = "/" } = {}) {
  const value = firstLine(text);
  if (value === null) return { error: "That path opens a quote it never closes; it looks cut off." };
  if (!value) return { error: "There is no path to go to." };
  if (looksLocal(value)) return { error: `${value} is a path on this computer, not on the host.` };
  return { path: absolute(value, home || "/", cwd || "/") };
}

// A path on its way to the clipboard. Explorer's "Copy as path" always wraps its
// result in quotes; a remote path is usually going into a shell, a ticket or a
// message, so it is quoted only when leaving it bare would change what it means.
// The quoting is POSIX single quotes, which the far end is what speaks, and which
// `firstLine` above strips again if the path comes back this way.
const PLAIN_PATH = /^[A-Za-z0-9_@%+=:,./-]+$/;

function pathForClipboard(remotePath) {
  const value = String(remotePath ?? "");
  if (!value || PLAIN_PATH.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

module.exports = { pathEntry, firstLine, looksLocal, pathForClipboard };

"use strict";

// The file pane follows the user the terminal is working as: after `sudo su` or
// `sudo -i` it browses as root, and after `exit` it goes back. Which user that is
// is read from the remote process table rather than from anything typed or
// printed, so a prompt that happens to end in `#`, or a command that merely
// mentions sudo, cannot change it.
//
// One exec channel answers everything. Every channel of a connection is served by
// the same sshd process, so the shell this command runs in has that process as its
// parent, and the terminal's login shell is the one child of it that holds a tty.
// From there the foreground process group is followed down, through a pty that
// sudo may have allocated for the command it runs, to the innermost foreground
// process. Only when that process is a shell listed in /etc/shells, started with
// no script and no -c -- a shell sitting at its prompt, waiting for the next
// command -- is there an answer: its
// user is the one the terminal is working as. `sudo su` gives a root shell at a
// prompt, so the pane moves. While any command is running, including `sudo vim`
// and `sudo sh -c '...'`, the innermost process is that command and there is no
// answer, so the pane stays where it is until the next prompt. A root shell
// running a script, `sudo bash ./install.sh`, is a shell too, but its arguments
// name the script, so it is not taken for a prompt.
//
// `exec /bin/sh` keeps the parent the same whatever the login shell is, and makes
// the rest of the command plain POSIX shell even when the login shell is fish.
const PROBE_COMMAND = "exec /bin/sh -c '"
  + "echo \"sshd $PPID\"; echo \"uid $(id -u)\"; echo processes; "
  + "LC_ALL=C ps -A -o pid= -o ppid= -o pgid= -o tpgid= -o ruid= -o tty= -o comm=; "
  + "echo arguments; LC_ALL=C ps -A -o pid= -o args=; "
  + "echo shells; cat /etc/shells 2>/dev/null"
  + "'";

const PROCESS_LINE = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(-?\d+)\s+(\d+)\s+(\S+)\s+(.*)$/;
const ARGUMENTS_LINE = /^\s*(\d+)\s+(.*)$/;

function parseProbe(text) {
  const result = { sshd: 0, uid: null, processes: [], shells: [] };
  const argumentsByPid = new Map();
  let section = "";
  for (const raw of String(text).split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!section) {
      const header = /^(sshd|uid) (\d+)$/.exec(line.trim());
      if (header) {
        result[header[1]] = Number(header[2]);
        continue;
      }
    }
    if (line === "processes" || line === "arguments" || line === "shells") {
      section = line;
      continue;
    }
    if (section === "processes") {
      const match = PROCESS_LINE.exec(line);
      if (!match) continue;
      result.processes.push({
        pid: Number(match[1]),
        ppid: Number(match[2]),
        pgid: Number(match[3]),
        tpgid: Number(match[4]),
        ruid: Number(match[5]),
        tty: match[6],
        comm: commandName(match[7]),
      });
    } else if (section === "arguments") {
      const match = ARGUMENTS_LINE.exec(line);
      if (match) argumentsByPid.set(Number(match[1]), match[2].trim());
    } else if (section === "shells") {
      const entry = line.trim();
      if (entry.startsWith("/")) result.shells.push(commandName(entry));
    }
  }
  for (const process of result.processes) {
    if (argumentsByPid.has(process.pid)) process.args = argumentsByPid.get(process.pid);
  }
  return result;
}

// A shell at its prompt was started with options at most: `bash`, `-bash`,
// `/bin/bash -l`. A script path, or -c with a command, means it is running
// something rather than waiting. Arguments that were not read -- the process came
// and went between the two listings -- are no answer either.
function atPrompt(process) {
  if (typeof process.args !== "string") return false;
  const operands = process.args.split(/\s+/).slice(1);
  return operands.every((word) => /^-/.test(word) && !/^-[A-Za-z]*c[A-Za-z]*$/.test(word));
}

// macOS prints the whole path and a login shell can show as "-bash"; only the name
// is compared, and the list it is compared with is the host's own /etc/shells.
function commandName(value) {
  const name = String(value).trim().split("/").pop() || "";
  return name.replace(/^-/, "");
}

// "?" on Linux and "??" on BSD and macOS mean the process has no terminal.
function hasTty(process) {
  return Boolean(process.tty) && !/^[?-]+$/.test(process.tty);
}

// The uid of the shell waiting at the terminal's prompt, or null when a command is
// running or the process table does not say so unambiguously -- in which case the
// pane is left as it is.
function terminalUser(probe) {
  const { sshd, processes } = probe || {};
  if (!sshd || !Array.isArray(processes) || !processes.length) return null;
  const shells = new Set(probe.shells || []);
  const children = new Map();
  for (const process of processes) {
    if (!children.has(process.ppid)) children.set(process.ppid, []);
    children.get(process.ppid).push(process);
  }

  const terminals = processes.filter((process) => process.ppid === sshd && hasTty(process));
  if (terminals.length !== 1) return null;

  // Every route from `top` down to a foreground process on its own tty, continued
  // through any child that holds a different tty -- which is what sudo's monitor
  // looks like when sudo runs the command in a pty of its own.
  const routes = (top, seen = new Set()) => {
    if (seen.has(top.pid)) return [[top]];
    seen.add(top.pid);
    const below = [];
    const stack = [top];
    while (stack.length) {
      const node = stack.pop();
      for (const child of children.get(node.pid) || []) {
        if (child.tty === top.tty) {
          below.push(child);
          stack.push(child);
        }
      }
    }
    const foreground = [top, ...below].filter((node) => node.tpgid > 0 && node.pgid === node.tpgid);
    if (!foreground.length) return [[top]];
    const byPid = new Map([top, ...below].map((node) => [node.pid, node]));
    const found = [];
    for (const end of foreground) {
      const path = [];
      for (let node = end; node; node = node.pid === top.pid ? null : byPid.get(node.ppid)) path.unshift(node);
      if (path[0] !== top) continue;
      const nested = path.flatMap((node) => (children.get(node.pid) || [])
        .filter((child) => hasTty(child) && child.tty !== top.tty));
      if (!nested.length) {
        found.push(path);
        continue;
      }
      for (const inner of nested) {
        for (const rest of routes(inner, seen)) found.push([...path, ...rest]);
      }
    }
    return found.length ? found : [[top]];
  };

  const answers = new Set();
  for (const route of routes(terminals[0])) {
    const innermost = route[route.length - 1];
    if (!shells.has(innermost.comm) || !atPrompt(innermost)) return null;
    answers.add(innermost.ruid);
  }
  return answers.size === 1 ? [...answers][0] : null;
}

module.exports = { PROBE_COMMAND, parseProbe, terminalUser };

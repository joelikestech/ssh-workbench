"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { sameInstallation, installedPackage } = require("./installation");

const LIST_TIMEOUT_MILLISECONDS = 4000;
const PACKAGE_NAME = "ssh-workbench";

// Every build before 0.11.5 leaves no record of itself anywhere, so a copy that is
// already running can only be found by looking at what is running. That is a
// subprocess on Windows and a directory read on Linux, and it happens on one path
// only — a launch that has just been refused the lock — so it costs a startup that
// was going to end in a dialog anyway.
function listFromProc(execPath) {
  const wanted = path.basename(String(execPath)).toLowerCase();
  const copies = [];
  for (const entry of fs.readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    let executable;
    try {
      executable = fs.readlinkSync(path.join("/proc", entry, "exe"));
    } catch {
      continue; // another user's process, or one that ended mid-read
    }
    if (path.basename(executable).toLowerCase() !== wanted) continue;
    copies.push({
      pid: Number(entry), path: executable, installation: claimedInstallation(entry), started: processStart(entry),
    });
  }
  return copies;
}

// Which installation a running process belongs to, asked of the process rather than
// of its executable path. An AppImage is extracted to a mount point that exists only
// for that launch, so its path says nothing about which file was launched — and
// without this a copy could not tell its own renderer and GPU processes apart from a
// foreign build, and would close them along with it.
function claimedInstallation(pid) {
  let appImage = null;
  try {
    for (const entry of fs.readFileSync(path.join("/proc", String(pid), "environ"), "utf8").split("\0")) {
      const split = entry.indexOf("=");
      if (split < 1) continue;
      const name = entry.slice(0, split);
      const value = entry.slice(split + 1);
      if (!value) continue;
      // The same precedence installationPath() applies to this process's own.
      if (name === "SSH_WORKBENCH_INSTALLATION") return value;
      if (name === "APPIMAGE") appImage = value;
    }
  } catch { /* another user's process: it cannot be holding this user's profile */ }
  return appImage;
}

// When a process started, in clock ticks since boot: the 22nd field of
// /proc/<pid>/stat, counted after the command name, which is in parentheses and may
// itself hold spaces and parentheses. A process id can be handed to a new process as
// soon as the old one ends, and the pair of id and start time is what cannot be.
function processStart(pid) {
  try {
    const stat = fs.readFileSync(path.join("/proc", String(pid), "stat"), "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    return fields[19] || null;
  } catch {
    return null;
  }
}

// Whether a process id still names the process it named when it was listed. Closing
// another copy can take seconds, and a forced kill sent at the end of that wait to an
// id that has since been reused would land on whatever now holds it. Where the start
// time could not be read -- not Linux, or not this user's process -- the id is all
// there is to go on, and it is taken as it was found.
function sameProcess(pid, started, { readStart = processStart } = {}) {
  if (!started) return true;
  const now = readStart(pid);
  return now !== null && now === started;
}

function runCommand(run, file, args) {
  return new Promise((resolve) => {
    run(file, args, { timeout: LIST_TIMEOUT_MILLISECONDS, windowsHide: true }, (error, stdout) => {
      resolve(error ? "" : String(stdout || ""));
    });
  });
}

// Get-Process is quicker than a CIM query and answers with the two things needed.
// One process comes back as an object and several as an array, so both are flattened.
async function listFromPowerShell(run, execPath) {
  const name = path.basename(String(execPath)).replace(/\.exe$/i, "").replace(/'/g, "''");
  const script = `Get-Process -Name '${name}' -ErrorAction SilentlyContinue `
    + "| Select-Object Id,Path | ConvertTo-Json -Compress";
  const output = await runCommand(run, "powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script]);
  if (!output.trim()) return [];
  try {
    const parsed = JSON.parse(output);
    return (Array.isArray(parsed) ? parsed : [parsed])
      .filter((row) => row && row.Id)
      .map((row) => ({ pid: Number(row.Id), path: row.Path ? String(row.Path) : "", installation: null }));
  } catch {
    return [];
  }
}

async function listFromPs(run) {
  const output = await runCommand(run, "/bin/ps", ["-Ao", "pid=,comm="]);
  return output.split("\n").map((line) => {
    const match = /^\s*(\d+)\s+(.+?)\s*$/.exec(line);
    return match ? { pid: Number(match[1]), path: match[2], installation: null } : null;
  }).filter(Boolean);
}

async function listCopies({ platform = process.platform, execPath = process.execPath, run = execFile } = {}) {
  try {
    if (platform === "win32") return await listFromPowerShell(run, execPath);
    if (platform === "linux") return listFromProc(execPath);
    return await listFromPs(run);
  } catch {
    return [];
  }
}

// A copy of this application, rather than any process that happens to share the
// executable's name: the folder it runs from holds this project's package.json. A
// build whose archive cannot be read falls back to the name, which is what an
// unpackaged development run looks like — there is nothing beside it to identify.
function isThisApplication(candidatePath, execPath, identify) {
  const named = path.basename(String(candidatePath)).toLowerCase()
    === path.basename(String(execPath)).toLowerCase();
  const found = identify(candidatePath);
  if (found?.name) return found.name === PACKAGE_NAME;
  return named;
}

// The running copies that are not this one, grouped by the installation they run
// from: a copy serves several processes — a renderer and a GPU process at least —
// and closing it means closing all of them.
//
// A process says which installation it belongs to where it can, and its executable
// path stands in where it cannot. Both are needed: the path is what identifies a
// Windows installation, and the claim is what keeps a copy from mistaking its own
// helper processes — which run from a mount point, not from the file that was
// launched — for a foreign build sharing the same profile.
function otherInstallations(copies, { installation, pid, execPath = process.execPath, identify = identifyInstallation } = {}) {
  const groups = new Map();
  for (const copy of copies || []) {
    if (!copy?.path || !copy?.pid) continue;
    if (Number(copy.pid) === Number(pid)) continue;
    const claimed = copy.installation || copy.path;
    if (sameInstallation(claimed, installation)) continue;
    // A process that would not say, running the very executable this one runs, is
    // taken to be one of this copy's own rather than a stranger.
    if (!copy.installation && sameInstallation(copy.path, execPath)) continue;
    if (!isThisApplication(copy.path, execPath, identify)) continue;
    const key = process.platform === "win32" ? path.resolve(claimed).toLowerCase() : path.resolve(claimed);
    if (!groups.has(key)) groups.set(key, { path: String(claimed), pids: [] });
    const group = groups.get(key);
    if (!group.pids.includes(Number(copy.pid))) group.pids.push(Number(copy.pid));
    // When each process started, where that could be read, so a signal sent later can
    // be sure it is still reaching the same process (see sameProcess).
    if (copy.started) group.started = { ...group.started, [Number(copy.pid)]: String(copy.started) };
  }
  return [...groups.values()];
}

// What the package.json beside an executable says it is. The name is reported as
// found -- an application that is not this one must not be named as if it were, or
// the check in isThisApplication passes for every Electron application there is. A
// manifest with a version and no name at all is not evidence either way, and leaves
// the executable name to decide, as for an unpackaged run.
function identifyInstallation(candidatePath) {
  const found = installedPackage(candidatePath);
  return found ? { name: found.name, version: found.version } : null;
}

module.exports = { listCopies, otherInstallations, identifyInstallation, sameProcess, processStart, PACKAGE_NAME };

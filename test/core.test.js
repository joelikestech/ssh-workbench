"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { KnownHosts, displayFingerprint } = require("../lib/known-hosts");
const { ProfileStore } = require("../lib/profile-store");
const { remotePath, remoteJoin, remoteParent, safeRemoteName } = require("../lib/remote-path");
const { buildMatcher } = require("../lib/search-match");
const { SshManager, modeString } = require("../lib/ssh-manager");
const { sameInstallation, installationPath, installedVersion } = require("../lib/installation");
const { otherInstallations } = require("../lib/running-copies");
const { cleanCopy, commonMargin } = require("../lib/terminal-copy");
const { pathEntry, pathForClipboard } = require("../lib/path-entry");
const {
  credentialsBoxChecked, credentialsControlEnabled, credentialsUnreadable, afterSave, fillSavedSecrets,
} = require("../lib/saved-credentials");
const { parseListing, quote } = require("../lib/shell-transport");
const { Vault } = require("../lib/vault");

test("normalizes and joins remote POSIX paths", () => {
  assert.equal(remotePath("var/../tmp"), "/tmp");
  assert.equal(remotePath("/home/alice//project"), "/home/alice/project");
  assert.equal(remoteJoin("/home/alice", "notes.txt"), "/home/alice/notes.txt");
  assert.equal(remoteParent("/home/alice"), "/home");
  assert.equal(remoteParent("/"), null);
  assert.throws(() => remoteJoin("/tmp", "../escape"), /Invalid file name/);
  assert.throws(() => remotePath("bad\0path"), /null byte/);
});

test("persists host fingerprints without credential material", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-hosts-"));
  try {
    const file = path.join(directory, "known-hosts.json");
    const hosts = new KnownHosts(file);
    const fingerprint = "a".repeat(64);
    hosts.remember("example.test:22", fingerprint);
    const loaded = new KnownHosts(file);
    assert.equal(loaded.get("example.test:22").sha256, fingerprint);
    assert.match(displayFingerprint(fingerprint), /^SHA256:/);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("interprets search queries as names, paths, or wildcards", () => {
  const name = "notes.txt";
  const relative = "home/alice/notes.txt";
  const full = "/srv/home/alice/notes.txt";

  const plain = buildMatcher("note");
  assert.equal(plain.scope, "name");
  assert.equal(plain.test(name, relative, full), true);
  assert.equal(plain.test("other.txt", "home/alice/other.txt", "/srv/home/alice/other.txt"), false);
  assert.equal(plain.test("NOTES.TXT", relative, full), true, "matching ignores case");
  assert.equal(buildMatcher("alice").test(name, relative, full), false, "a plain query ignores folder names");

  const byPath = buildMatcher("alice/notes");
  assert.equal(byPath.scope, "relative path");
  assert.equal(byPath.test(name, relative, full), true);
  assert.equal(byPath.test(name, "home/bob/notes.txt", "/srv/home/bob/notes.txt"), false);

  const byFullPath = buildMatcher("/srv/home");
  assert.equal(byFullPath.scope, "full path");
  assert.equal(byFullPath.test(name, relative, full), true);
  assert.equal(byFullPath.test(name, relative, "/other/notes.txt"), false);

  const wildcard = buildMatcher("*.txt");
  assert.equal(wildcard.wildcard, true);
  assert.equal(wildcard.test(name, relative, full), true);
  assert.equal(wildcard.test("notes.txt.bak", "x", "y"), false, "a pattern matches the whole value");
  assert.equal(buildMatcher("note?.txt").test("notes.txt", relative, full), true);
  assert.equal(buildMatcher("note?.txt").test("notes2.txt", relative, full), false);
  assert.equal(buildMatcher("alice/*.txt").test(name, relative, full), true,
    "a path pattern may start at any folder boundary");
  assert.equal(buildMatcher("alice/*.txt").test(name, "home/bob/notes.txt", full), false);
  assert.equal(buildMatcher("/srv/*/notes.txt").test(name, relative, full), true,
    "a rooted pattern is matched from the root");
  assert.equal(buildMatcher("/home/*").test(name, relative, full), false,
    "a rooted pattern that does not start at the root does not match");

  assert.equal(buildMatcher("a.b").test("axb", "axb", "/axb"), false, "a dot is not a wildcard");
  assert.equal(buildMatcher("(paren)").test("a (paren) b", "a (paren) b", "/a"), true);
  assert.equal(buildMatcher("").test("anything", "anything", "/anything"), true);

  // A star in the name is an ordinary character and must not satisfy the star in
  // the pattern by looking like it.
  assert.equal(buildMatcher("*x").test("*x", "*x", "/*x"), true);
  assert.equal(buildMatcher("*").test("*x", "*x", "/*x"), true);
  assert.equal(buildMatcher("a*b").test("a*b", "a*b", "/a*b"), true);
  assert.equal(buildMatcher("a*b").test("a*c", "a*c", "/a*c"), false);
});

test("a pattern full of stars is answered rather than ground on", () => {
  // Compiled to a regular expression this took over two minutes, in the main
  // process, with every window waiting on it. The walk gives each star one more
  // character at a time and never goes back, so it cannot behave that way.
  const value = `${"a".repeat(200)}b`;
  const matcher = buildMatcher("*a".repeat(8));
  const started = process.hrtime.bigint();
  assert.equal(matcher.test(value, value, `/${value}`), false);
  const milliseconds = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(milliseconds < 250, `took ${milliseconds.toFixed(1)} ms`);
});

test("reads a path out of whatever the clipboard was holding", () => {
  const at = { home: "/home/tester", cwd: "/var/log" };
  assert.deepEqual(pathEntry("/etc/hosts", at), { path: "/etc/hosts" });
  // Explorer's "Copy as path" quotes; a chat message or a log adds line endings.
  assert.deepEqual(pathEntry('"/etc/hosts"', at), { path: "/etc/hosts" });
  assert.deepEqual(pathEntry("'/etc/hosts'", at), { path: "/etc/hosts" });
  assert.deepEqual(pathEntry("  /etc/hosts  \r\n", at), { path: "/etc/hosts" });
  assert.deepEqual(pathEntry("\n\n/etc/hosts\nand some other text", at), { path: "/etc/hosts" });
  // A quote is only stripped when it wraps the whole line, so a name that merely
  // holds one survives.
  assert.deepEqual(pathEntry(`/tmp/it's here.txt`, at), { path: "/tmp/it's here.txt" });

  assert.deepEqual(pathEntry("~", at), { path: "/home/tester" });
  assert.deepEqual(pathEntry("~/.ssh/config", at), { path: "/home/tester/.ssh/config" });
  assert.deepEqual(pathEntry("nginx/error.log", at), { path: "/var/log/nginx/error.log" });
  // Dot segments are left for the far end's own normalisation rather than done twice.
  assert.deepEqual(pathEntry("../spool", at), { path: "/var/log/../spool" });

  for (const local of ["C:\\Users\\me\\notes.txt", "c:/Users/me", "\\\\server\\share\\file"]) {
    const refused = pathEntry(local, at);
    assert.equal(refused.path, undefined, `${local} must not be sent to the host`);
    assert.match(refused.error, /on this computer/);
  }

  for (const empty of ["", "   ", "\n\n", null, undefined]) {
    assert.match(pathEntry(empty, at).error, /no path/);
  }

  // With nothing to go on, the root is the only sane place to hang a relative path.
  assert.deepEqual(pathEntry("etc", {}), { path: "/etc" });
});

test("quotes a copied path only when leaving it bare would change it", () => {
  // A plain path is what someone wants in a ticket or a message, unadorned.
  assert.equal(pathForClipboard("/var/log/nginx-1.2_3.log"), "/var/log/nginx-1.2_3.log");
  assert.equal(pathForClipboard("/home/tester/.ssh/config"), "/home/tester/.ssh/config");
  // One a shell would read as two words, or as syntax, is quoted the way the far end
  // speaks -- and `firstLine` takes the quotes off again if it comes back this way.
  assert.equal(pathForClipboard("/tmp/my report.txt"), "'/tmp/my report.txt'");
  assert.equal(pathForClipboard("/tmp/a$b"), "'/tmp/a$b'");
  assert.equal(pathForClipboard("/tmp/star*"), "'/tmp/star*'");
  // A single quote inside the name closes and reopens the quoting around itself,
  // which is the only way POSIX single quotes can carry one.
  assert.equal(pathForClipboard("/tmp/it's here.txt"), "'/tmp/it'\\''s here.txt'");
  assert.equal(pathForClipboard(""), "");

  // Every one of them has to survive the trip back, which means undoing the whole
  // construction and not just the outer pair -- a name with an apostrophe in it is
  // an ordinary name, and the quoting is only worth writing if it can be read.
  for (const original of [
    "/var/log/syslog",
    "/tmp/my report.txt",
    "/tmp/it's here.txt",
    "/tmp/don't & won't",
    "/tmp/a''b",
    // The quotes said where the path ends, so a space there is part of the name.
    "/tmp/trailing ",
  ]) {
    assert.equal(pathEntry(pathForClipboard(original), {}).path, original,
      `${original} did not survive Copy as path and back`);
  }

  // A quote that opens and never closes is a path the copy cut short, and saying so
  // beats hanging what is left of it off the folder on screen.
  assert.match(pathEntry("'/tmp/cut off", { cwd: "/var" }).error, /cut off/);
});

test("formats common remote permission modes", () => {
  assert.equal(modeString(0o100644), "-rw-r--r--");
  assert.equal(modeString(0o040755), "drwxr-xr-x");
  assert.equal(modeString(0o120777), "lrwxrwxrwx");
});

test("stores named connection credentials only as encrypted data", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-profiles-"));
  const transform = (value) => Buffer.from(value).map((byte) => byte ^ 0xaa);
  try {
    const file = path.join(directory, "connections.json");
    const profiles = new ProfileStore({
      filePath: file,
      encrypt: (plaintext) => transform(Buffer.from(plaintext, "utf8")),
      decrypt: (encrypted) => transform(encrypted).toString("utf8"),
      canEncrypt: () => true,
    });
    const saved = profiles.save({
      name: "Lab server",
      startPath: "~/project",
      saveCredentials: true,
      connection: {
        host: "server.example.test",
        port: 22,
        username: "operator",
        authType: "password",
        password: "destination-secret",
        passphrase: "unused-target-passphrase",
        jump: {
          enabled: true,
          host: "bastion.example.test",
          port: 2222,
          username: "jump-user",
          authType: "key",
          keyPath: "/keys/jump-key",
          passphrase: "jump-secret",
          password: "unused-jump-password",
        },
      },
    });
    assert.equal(saved.credentialsSaved, true);
    const disk = fs.readFileSync(file, "utf8");
    assert.doesNotMatch(disk, /destination-secret|jump-secret|unused-target-passphrase|unused-jump-password/);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    const loaded = profiles.get(saved.id);
    assert.equal(loaded.connection.password, "destination-secret");
    assert.equal(loaded.connection.passphrase, "");
    assert.equal(loaded.connection.jump.passphrase, "jump-secret");
    assert.equal(loaded.connection.jump.password, "");
    assert.equal(loaded.startPath, "~/project");
    profiles.delete(saved.id);
    assert.deepEqual(profiles.list(), []);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("refuses to persist secrets without secure encryption", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-insecure-"));
  try {
    const profiles = new ProfileStore({
      filePath: path.join(directory, "connections.json"),
      encrypt: () => { throw new Error("must not encrypt"); },
      decrypt: () => "",
      canEncrypt: () => false,
    });
    const input = {
      name: "Server",
      saveCredentials: true,
      connection: {
        host: "server.example.test",
        username: "operator",
        authType: "password",
        password: "secret",
      },
    };
    assert.throws(() => profiles.save(input), /Secure credential storage is unavailable/);
    input.saveCredentials = false;
    const saved = profiles.save(input);
    assert.equal(saved.credentialsSaved, false);
    assert.equal(profiles.get(saved.id).connection.password, "");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("refuses a private-key path that is not a plain file", async () => {
  const { SshManager } = require("../lib/ssh-manager");
  const manager = new SshManager({ knownHostsPath: path.join(os.tmpdir(), "unused-hosts.json"), confirmHost: async () => ({ accept: false }) });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-keypath-"));
  try {
    await assert.rejects(() => manager.connect({
      host: "server.example.test", port: 22, username: "operator", authType: "key", keyPath: directory,
    }), /private key is not a file/);
    await assert.rejects(() => manager.connect({
      host: "server.example.test", port: 22, username: "operator", authType: "key", keyPath: "/dev/zero",
    }), /not a file|too large/, "a character device is refused instead of being read forever");
    await assert.rejects(() => manager.connect({
      host: "server.example.test", port: 22, username: "operator", authType: "key", keyPath: path.join(directory, "absent"),
    }), /could not be read/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

/* ------------------------------------------------- listings parsed from ls */

test("reads a GNU ls listing, including names with spaces and links", () => {
  const listing = [
    "total 24",
    "drwxr-xr-x 2 1000 1000   4096 1755600000 my folder",
    "-rw-r--r-- 1 1000 1000     12 1755600060 notes.txt",
    "lrwxrwxrwx 1 1000 1000      9 1755600120 shortcut -> notes.txt",
    "-rwsr-Sr-T 1    0    0    128 1755600180 odd bits",
    "brw-rw---- 1    0    0   8, 0 1755600240 sda",
    "drwxr-xr-x 5 1000 1000   4096 1755600300 .",
    "drwxr-xr-x 7 1000 1000   4096 1755600360 ..",
  ].join("\n");
  const entries = parseListing(listing);
  assert.deepEqual(entries.map((entry) => entry.filename),
    ["my folder", "notes.txt", "shortcut", "odd bits", "sda"],
    "the total line and the dot entries are not files");

  const [folder, notes, shortcut, odd] = entries;
  assert.equal(folder.attrs.isDirectory(), true);
  assert.equal(notes.attrs.size, 12);
  assert.equal(notes.attrs.mtime, 1755600060);
  assert.equal(shortcut.attrs.isSymbolicLink(), true);
  assert.equal(shortcut.filename, "shortcut", "the arrow and its target are not part of the name");
  // An upper-case S or T marks setuid, setgid or sticky *without* the execute bit,
  // so those two must not come back as executable. The mode column shows the
  // ordinary rwx letters either way, exactly as it does for an SFTP listing.
  assert.equal(modeString(odd.attrs.mode), "-rwxr--r--");
  assert.equal(Boolean(odd.attrs.mode & 0o4000), true, "setuid");
  assert.equal(Boolean(odd.attrs.mode & 0o2000), true, "setgid");
  assert.equal(Boolean(odd.attrs.mode & 0o1000), true, "sticky");
  assert.equal(odd.attrs.mode & 0o010, 0, "an S is not an execute bit");
  assert.equal(odd.attrs.mode & 0o001, 0, "and neither is a T");
});

test("reads a plain ls listing, choosing the year the clock implies", () => {
  const now = Date.UTC(2026, 7, 19, 12, 0, 0);
  const entries = parseListing([
    "-rw-r--r-- 1 1000 1000  7 Aug 18 09:15 recent.txt",
    "-rw-r--r-- 1 1000 1000  9 Dec 30 22:00 december.txt",
    "-rw-r--r-- 1 1000 1000 11 Mar  2  2021 ancient.txt",
  ].join("\n"), { epoch: false, now });

  const [recent, december, ancient] = entries;
  assert.equal(new Date(recent.attrs.mtime * 1000).getFullYear(), 2026);
  assert.equal(new Date(december.attrs.mtime * 1000).getFullYear(), 2025,
    "a clock time in the future belongs to last year, which is what ls means by omitting the year");
  assert.equal(new Date(ancient.attrs.mtime * 1000).getFullYear(), 2021);
});

test("quotes a path so a shell cannot read anything in it as syntax", () => {
  assert.equal(quote("/tmp/plain"), "'/tmp/plain'");
  assert.equal(quote("it's here"), "'it'\\''s here'");
  assert.equal(quote("$(rm -rf /); echo"), "'$(rm -rf /); echo'");
  assert.equal(quote("--rf"), "'--rf'");
});

/* -------------------------------------------- the master password over secrets */

function testVault(clock = { now: 1_700_000_000_000 }) {
  return new Vault({ now: () => clock.now });
}

test("a master password protects a secret and the wrong one does not open it", async () => {
  const vault = testVault();
  vault.adopt(await vault.create("a good long password", { mode: "minutes", minutes: 15 }));
  const sealed = vault.wrap("{\"password\":\"hunter2\"}");
  assert.doesNotMatch(sealed, /hunter2/, "the plaintext is not in the stored form");
  assert.equal(vault.unwrap(sealed), "{\"password\":\"hunter2\"}");

  const reopened = new Vault({ config: vault.toJSON() });
  await assert.rejects(() => reopened.unlock("not the password"), /not correct/);
  await reopened.unlock("a good long password");
  assert.equal(reopened.unwrap(sealed), "{\"password\":\"hunter2\"}");
});

test("a short master password is refused", async () => {
  const vault = testVault();
  await assert.rejects(() => vault.create("short", { mode: "every" }), /at least 6 characters/);
  // Six is the minimum, and six is accepted.
  vault.adopt(await vault.create("sixchr", { mode: "every" }));
  assert.equal(vault.configured, true);
});

test("wrong attempts are rate limited, mildly", async () => {
  const clock = { now: 1_700_000_000_000 };
  const vault = testVault(clock);
  vault.adopt(await vault.create("the right password", { mode: "minutes", minutes: 15 }));

  // Mistyping a few times costs nothing beyond the derivation itself.
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    await assert.rejects(() => vault.keyFor("wrong"), /not correct/, `attempt ${attempt} is answered normally`);
    assert.equal(vault.cooldownSeconds(), 0);
  }
  // The fifth buys a pause, and the pause is what the next attempt is told about.
  await assert.rejects(() => vault.keyFor("wrong"), /not correct/);
  assert.equal(vault.cooldownSeconds(), 15);
  await assert.rejects(() => vault.keyFor("the right password"), /Too many attempts. Try again in 15 seconds/);

  clock.now += 15_000;
  assert.equal(vault.cooldownSeconds(), 0, "and it clears itself once the time has passed");
  const key = await vault.keyFor("the right password");
  assert.equal(key.length, 32);
  assert.equal(vault.cooldownSeconds(), 0, "a correct password puts the counter back");
  await assert.rejects(() => vault.keyFor("wrong"), /not correct/, "so mistyping again is free again");
  assert.equal(vault.cooldownSeconds(), 0);
});

test("the pause grows with each further wrong attempt, up to a minute", async () => {
  const clock = { now: 1_700_000_000_000 };
  const vault = testVault(clock);
  vault.adopt(await vault.create("the right password", { mode: "every" }));
  const waits = [];
  for (let attempt = 1; attempt <= 9; attempt += 1) {
    await vault.keyFor("wrong").catch(() => undefined);
    const waiting = vault.cooldownSeconds();
    if (waiting) waits.push(waiting);
    clock.now += waiting * 1000;
  }
  assert.deepEqual(waits, [15, 30, 45, 60, 60], "four free tries, then a longer pause each time, capped at 60");
});

test("asking every time means the key is gone as soon as it has been used", async () => {
  const vault = testVault();
  vault.adopt(await vault.create("a good long password", { mode: "every" }));
  const sealed = vault.wrap("secret");
  assert.equal(vault.unwrap(sealed), "secret");
  assert.equal(vault.unlocked, false, "one use is one use");
  assert.throws(() => vault.unwrap(sealed), /locked/);
});

test("a timed unlock lasts its minutes, and using it puts the clock back", async () => {
  const clock = { now: 1_700_000_000_000 };
  const vault = testVault(clock);
  vault.adopt(await vault.create("a good long password", { mode: "minutes", minutes: 10 }));
  const sealed = vault.wrap("secret");

  clock.now += 9 * 60_000;
  assert.equal(vault.unwrap(sealed), "secret", "still inside the window");
  clock.now += 9 * 60_000;
  assert.equal(vault.unwrap(sealed), "secret", "the last use moved the window along");
  clock.now += 11 * 60_000;
  assert.equal(vault.unlocked, false);
  assert.throws(() => vault.unwrap(sealed), /locked/);
});

test("shortening the window applies at once rather than at the next unlock", async () => {
  const clock = { now: 1_700_000_000_000 };
  const vault = testVault(clock);
  vault.adopt(await vault.create("a good long password", { mode: "minutes", minutes: 60 }));
  await vault.setPolicy({ mode: "minutes", minutes: 5 });
  clock.now += 6 * 60_000;
  assert.equal(vault.unlocked, false);
});

test("an out-of-range interval is brought back into range", async () => {
  const vault = testVault();
  vault.adopt(await vault.create("a good long password", { mode: "minutes", minutes: 99_999 }));
  assert.equal(vault.policy.minutes, 1440);
  await vault.setPolicy({ mode: "minutes", minutes: 0 });
  assert.equal(vault.policy.minutes, 1);
});

/* -------------------------------------- saved connections under a master password */

function storeFixture({ keyring = true } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-store-"));
  const state = { keyring };
  // A stand-in for safeStorage: reversible, and obviously not the real thing.
  const store = new ProfileStore({
    filePath: path.join(directory, "connections.json"),
    encrypt: (plaintext) => Buffer.from(`keyring:${plaintext}`, "utf8"),
    decrypt: (encrypted) => {
      const text = encrypted.toString("utf8");
      if (!text.startsWith("keyring:")) throw new Error("not keyring ciphertext");
      return text.slice("keyring:".length);
    },
    canEncrypt: () => state.keyring,
  });
  return { store, directory, state, file: path.join(directory, "connections.json") };
}

const CONNECTION = {
  host: "server.example.test",
  port: 22,
  username: "operator",
  authType: "password",
  password: "hunter2",
  keyPath: "",
  passphrase: "",
  jump: { enabled: false, host: "", port: 22, username: "", authType: "agent", keyPath: "" },
};

test("a connection saved before the protocol existed keeps trying SFTP first", () => {
  const { store, file, directory } = storeFixture();
  try {
    const saved = store.save({ name: "Legacy", connection: CONNECTION, saveCredentials: false });
    // Rewrite the file the way version 1 held it: a bare ciphertext string and no
    // protocol at all.
    const raw = JSON.parse(fs.readFileSync(file, "utf8"));
    raw.version = 1;
    delete raw.profiles[0].connection.protocol;
    raw.profiles[0].secret = Buffer.from("keyring:{\"password\":\"hunter2\",\"passphrase\":\"\",\"jumpPassword\":\"\",\"jumpPassphrase\":\"\"}", "utf8").toString("base64");
    fs.writeFileSync(file, JSON.stringify(raw));

    const reloaded = new ProfileStore({
      filePath: file,
      encrypt: (plaintext) => Buffer.from(`keyring:${plaintext}`, "utf8"),
      decrypt: (encrypted) => encrypted.toString("utf8").slice("keyring:".length),
      canEncrypt: () => true,
    });
    const profile = reloaded.get(saved.id);
    assert.equal(profile.connection.protocol, "sftp-scp");
    assert.equal(profile.connection.password, "hunter2", "a version 1 secret is still readable");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("an invalid transfer protocol is refused", () => {
  const { store, directory } = storeFixture();
  try {
    assert.throws(() => store.save({
      name: "Odd", connection: { ...CONNECTION, protocol: "ftp" }, saveCredentials: false,
    }), /protocol is invalid/);
    const saved = store.save({ name: "Fine", connection: { ...CONNECTION, protocol: "scp" }, saveCredentials: false });
    assert.equal(store.get(saved.id).connection.protocol, "scp");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("setting a master password re-encrypts what was already saved", async () => {
  const { store, directory, file } = storeFixture();
  try {
    const saved = store.save({ name: "Production", connection: CONNECTION, saveCredentials: true });
    assert.equal(store.get(saved.id).connection.password, "hunter2");

    const vault = new Vault({});
    store.attachVault(vault);
    const created = await vault.create("a good long password", { mode: "minutes", minutes: 15 });
    store.applyMasterPassword(created);
    vault.adopt(created);

    assert.equal(store.list()[0].masterPassword, true);
    assert.equal(store.get(saved.id).connection.password, "hunter2", "still readable while unlocked");
    assert.doesNotMatch(fs.readFileSync(file, "utf8"), /hunter2/, "and not readable in the file");

    vault.lock();
    const locked = store.get(saved.id);
    assert.equal(locked.needsUnlock, true);
    assert.equal(locked.connection.password, "", "a locked credential is withheld, not guessed at");
    assert.equal(locked.credentialError, null, "being locked is not an error");

    await vault.unlock("a good long password");
    assert.equal(store.get(saved.id).connection.password, "hunter2");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("changing the master password leaves the old one useless and the new one working", async () => {
  const { store, directory } = storeFixture();
  try {
    const saved = store.save({ name: "Production", connection: CONNECTION, saveCredentials: true });
    const vault = new Vault({});
    store.attachVault(vault);
    const first = await vault.create("the first password", { mode: "minutes", minutes: 15 });
    store.applyMasterPassword(first);
    vault.adopt(first);

    const oldKey = await vault.keyFor("the first password");
    const second = await vault.create("the second password", vault.policy);
    store.changeMasterPassword({ oldKey, newKey: second.key, config: second.config });
    vault.adopt(second);
    assert.equal(store.get(saved.id).connection.password, "hunter2");

    const reopened = new Vault({ config: vault.toJSON() });
    await assert.rejects(() => reopened.unlock("the first password"), /not correct/);
    await reopened.unlock("the second password");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("removing the master password hands the secrets back to the keyring", async () => {
  const { store, directory, state } = storeFixture();
  try {
    const saved = store.save({ name: "Production", connection: CONNECTION, saveCredentials: true });
    const vault = new Vault({});
    store.attachVault(vault);
    const created = await vault.create("a good long password", { mode: "every" });
    store.applyMasterPassword(created);
    vault.adopt(created);

    const key = await vault.keyFor("a good long password");
    // With no keyring there is nowhere safe for the secrets to land, so this is
    // refused rather than quietly writing them somewhere weaker.
    state.keyring = false;
    assert.throws(() => store.clearMasterPassword({ key }), /keyring is unavailable/);
    state.keyring = true;

    store.clearMasterPassword({ key });
    vault.clear();
    assert.equal(store.list()[0].masterPassword, false);
    const profile = store.get(saved.id);
    assert.equal(profile.needsUnlock, false);
    assert.equal(profile.connection.password, "hunter2");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("saving a credential while locked is refused rather than silently dropped", async () => {
  const { store, directory } = storeFixture();
  try {
    const vault = new Vault({});
    store.attachVault(vault);
    const created = await vault.create("a good long password", { mode: "every" });
    store.applyMasterPassword(created);
    vault.adopt(created);
    vault.lock();

    assert.throws(() => store.save({ name: "New one", connection: CONNECTION, saveCredentials: true }), /locked/);
    // Without credentials there is nothing to protect, so it saves as usual.
    const saved = store.save({ name: "New one", connection: CONNECTION, saveCredentials: false });
    assert.equal(store.get(saved.id).credentialsSaved, false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("re-saving a connection whose credentials are locked keeps them", async () => {
  const { store, directory } = storeFixture();
  try {
    const vault = new Vault({});
    store.attachVault(vault);
    const created = await vault.create("a good long password", { mode: "minutes", minutes: 15 });
    store.applyMasterPassword(created);
    vault.adopt(created);
    const saved = store.save({ name: "Prod", connection: CONNECTION, saveCredentials: true });
    assert.equal(saved.credentialsSaved, true);

    // Locked, the form is filled from what `get` can show, which is everything
    // except the secrets.
    vault.lock();
    const shown = store.get(saved.id);
    assert.equal(shown.needsUnlock, true);
    assert.equal(shown.connection.password, "", "a locked credential is not handed out");

    // Changing the port and pressing Save must not be a way to lose the password.
    // Nothing about the credential is being touched, so it does not need the key
    // either: this succeeds while the vault is still locked.
    const resaved = store.save({
      id: saved.id, name: "Prod", startPath: shown.startPath, saveCredentials: true,
      connection: { ...shown.connection, port: 2222 },
    });
    assert.equal(resaved.credentialsSaved, true, "the stored credential survived the save");

    await vault.unlock("a good long password");
    const after = store.get(saved.id);
    assert.equal(after.connection.port, 2222, "and the edit that was actually asked for landed");
    assert.equal(after.connection.password, "hunter2");

    // Clearing the tick is the one thing that means "stop saving credentials".
    const cleared = store.save({
      id: saved.id, name: "Prod", startPath: shown.startPath, saveCredentials: false,
      connection: { ...shown.connection, port: 2222 },
    });
    assert.equal(cleared.credentialsSaved, false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

// Four secret fields, filled in every combination the form can actually produce.
// One worked example is what let the all-empty case get fixed while the
// change-one-of-them case stayed broken, so this enumerates instead.
test("changing one saved credential leaves the other alone, in every combination", async () => {
  const { store, directory } = storeFixture();
  try {
    const vault = new Vault({});
    store.attachVault(vault);
    const created = await vault.create("a good long password", { mode: "minutes", minutes: 15 });
    store.applyMasterPassword(created);
    vault.adopt(created);

    // The destination and the jump host each use one authentication type at a time,
    // so the field that carries their secret is whichever one that is.
    const FIELD = { password: "password", key: "passphrase" };
    const JUMP_FIELD = { password: "password", key: "passphrase" };

    for (const targetAuth of ["password", "key"]) {
      for (const jumpAuth of ["password", "key"]) {
        for (const typeTarget of [false, true]) {
          for (const typeJump of [false, true]) {
            for (const locked of [false, true]) {
              const where = `${targetAuth}/${jumpAuth} target=${typeTarget} jump=${typeJump} locked=${locked}`;
              const base = {
                host: "h", port: 22, username: "u", authType: targetAuth, keyPath: "/k",
                [FIELD[targetAuth]]: "stored-target",
                jump: {
                  enabled: true, host: "b", port: 22, username: "j", authType: jumpAuth, keyPath: "/k",
                  [JUMP_FIELD[jumpAuth]]: "stored-jump",
                },
              };
              if (!vault.unlocked) await vault.unlock("a good long password");
              const saved = store.save({ name: where, startPath: "~", saveCredentials: true, connection: base });

              // What the form holds after loading: everything but the secrets, plus
              // whichever ones were typed this time round.
              const edited = {
                ...base,
                password: "", passphrase: "",
                jump: { ...base.jump, password: "", passphrase: "" },
              };
              if (typeTarget) edited[FIELD[targetAuth]] = "typed-target";
              if (typeJump) edited.jump[JUMP_FIELD[jumpAuth]] = "typed-jump";

              if (locked) vault.lock();
              const resave = () => store.save({
                id: saved.id, name: where, startPath: "~", saveCredentials: true, connection: edited,
              });

              if (locked && (typeTarget || typeJump)) {
                // Reading the other three in order to keep them needs the key.
                assert.throws(resave, /locked/i, `${where}: changing one while locked must ask, not guess`);
                await vault.unlock("a good long password");
                continue;
              }
              resave();
              if (!vault.unlocked) await vault.unlock("a good long password");
              const after = store.get(saved.id).connection;
              assert.equal(after[FIELD[targetAuth]], typeTarget ? "typed-target" : "stored-target",
                `${where}: destination secret`);
              assert.equal(after.jump[JUMP_FIELD[jumpAuth]], typeJump ? "typed-jump" : "stored-jump",
                `${where}: jump secret`);
            }
          }
        }
      }
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("a change that cannot be written to disk does not survive in memory", async () => {
  const { store, directory, file } = storeFixture();
  try {
    const vault = new Vault({});
    store.attachVault(vault);
    const created = await vault.create("a good long password", { mode: "minutes", minutes: 15 });
    store.applyMasterPassword(created);
    vault.adopt(created);
    const kept = store.save({ name: "Kept", startPath: "~", saveCredentials: true, connection: CONNECTION });
    const before = JSON.parse(fs.readFileSync(file, "utf8"));

    // An antivirus holding the file across the rename fails a write just like this.
    fs.chmodSync(directory, 0o500);
    try {
      assert.throws(() => store.save({ name: "New one", startPath: "~", saveCredentials: false, connection: CONNECTION }));
      assert.throws(() => store.save({
        id: kept.id, name: "Kept", startPath: "~", saveCredentials: true,
        connection: { ...CONNECTION, host: "somewhere-else" },
      }));
      assert.throws(() => store.delete(kept.id));
      assert.throws(() => store.saveVaultConfig({ ...vault.toJSON() }));
    } finally {
      fs.chmodSync(directory, 0o700);
    }

    // Nothing the interface was told did not happen may be visible afterwards.
    assert.deepEqual(store.list().map((profile) => profile.name), ["Kept"], "no rejected profile was added or removed");
    const still = store.get(kept.id);
    assert.equal(still.connection.host, CONNECTION.host, "the rejected edit is not showing");
    assert.equal(still.connection.password, "hunter2", "and the credential is still readable");
    assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), before, "the file on disk never moved");

    // A later write that does succeed must not carry any of it along.
    store.save({ id: kept.id, name: "Kept", startPath: "/srv", saveCredentials: true, connection: CONNECTION });
    const reloaded = JSON.parse(fs.readFileSync(file, "utf8"));
    assert.equal(reloaded.profiles.length, 1);
    assert.equal(reloaded.profiles[0].connection.host, CONNECTION.host);
    assert.equal(reloaded.profiles[0].startPath, "/srv");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

// A blob nobody can decrypt is not the silent-loss case the merge exists for: there
// is nothing in it left to lose. Refusing to touch it anyway left the connection
// unrepairable, while telling the user to do the thing that had just been refused.
test("credentials that cannot be read can be replaced, but only on purpose", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-damaged-"));
  try {
    const era = { value: "one" };
    const open = () => new ProfileStore({
      filePath: path.join(directory, "connections.json"),
      encrypt: (plaintext) => Buffer.from(`${era.value}:${plaintext}`, "utf8"),
      decrypt: (encrypted) => {
        const text = encrypted.toString("utf8");
        if (!text.startsWith(`${era.value}:`)) throw new Error("not this keyring's ciphertext");
        return text.slice(era.value.length + 1);
      },
      canEncrypt: () => true,
    });
    const store = open();
    const saved = store.save({ name: "Prod", startPath: "~", saveCredentials: true, connection: CONNECTION });

    // The keyring changes underneath it, which is what makes a stored secret
    // permanently unreadable rather than merely locked.
    era.value = "two";
    const loaded = store.get(saved.id);
    assert.match(loaded.credentialError, /could not be decrypted/);
    assert.equal(loaded.credentialsSaved, false, "it cannot be used");
    assert.equal(loaded.credentialsPresent, true, "but it is still there, and still worth keeping");

    const retyped = { ...CONNECTION, password: "typed-again" };
    const resave = (replaceCredentials) => store.save({
      id: saved.id, name: "Prod", startPath: "~", saveCredentials: true, replaceCredentials, connection: retyped,
    });

    // Unasked, it refuses -- and says which of the two things can be done about it,
    // both of which are actually possible.
    try {
      resave(false);
      assert.fail("replacing an unreadable credential must be asked about first");
    } catch (error) {
      assert.equal(error.unreadableCredentials, true, "the caller can tell this apart and offer the choice");
      assert.match(error.message, /replaced with what you have entered|discarded by saving without credentials/);
    }
    assert.equal(store.get(saved.id).credentialError, loaded.credentialError, "and nothing changed on the way");

    // Asked, it replaces them.
    resave(true);
    assert.equal(store.get(saved.id).connection.password, "typed-again");
    assert.equal(store.get(saved.id).credentialError, null);

    // The other way out still works too: discard by saving without credentials.
    era.value = "three";
    store.save({ id: saved.id, name: "Prod", startPath: "~", saveCredentials: false, connection: CONNECTION });
    assert.equal(store.get(saved.id).credentialsSaved, false);
    assert.equal(store.get(saved.id).credentialError, null, "the damaged blob is gone rather than still complaining");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("a master password that could not be stored is not the one in force", async () => {
  const { store, directory, file } = storeFixture();
  try {
    const kept = store.save({ name: "Kept", startPath: "~", saveCredentials: true, connection: CONNECTION });
    const before = JSON.parse(fs.readFileSync(file, "utf8"));
    const vault = new Vault({});
    store.attachVault(vault);
    const created = await vault.create("a good long password", { mode: "every" });

    // Re-protecting every secret is the fourth thing that writes, and the most
    // valuable: it is the whole store at once.
    fs.chmodSync(directory, 0o500);
    try {
      assert.throws(() => store.applyMasterPassword(created));
    } finally {
      fs.chmodSync(directory, 0o700);
    }
    assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), before, "the file never moved");
    assert.equal(store.list().find((profile) => profile.id === kept.id).masterPassword, false,
      "and nothing in memory thinks a master password is protecting it");
    assert.equal(store.get(kept.id).connection.password, "hunter2", "the keyring credential is still readable");

    // A policy that could not be stored must not be the one this process enforces.
    vault.adopt(created);
    store.saveVaultConfig(vault.toJSON());
    assert.equal(vault.policy.mode, "every");
    fs.chmodSync(directory, 0o500);
    try {
      const proposed = vault.configFor({ mode: "minutes", minutes: 60 });
      assert.throws(() => store.saveVaultConfig(proposed));
      // main.js adopts only after the store has taken it, so this never runs.
    } finally {
      fs.chmodSync(directory, 0o700);
    }
    assert.equal(vault.policy.mode, "every", "the refused policy is not in force");
    assert.equal(vault.policy.minutes, 15);
    assert.equal(vault.status().secondsRemaining, 0, "and it did not quietly grant an hour of unlock");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("the form keeps credentials it cannot read, and does not claim to have mended them", () => {
  const secure = { secureStorage: true };
  const readable = { credentialsPresent: true, credentialsSaved: true, needsUnlock: false, credentialError: null };
  const damaged = { credentialsPresent: true, credentialsSaved: false, needsUnlock: false, credentialError: "could not be decrypted" };
  const locked = { credentialsPresent: true, credentialsSaved: false, needsUnlock: true, credentialError: null };
  const none = { credentialsPresent: false, credentialsSaved: false, needsUnlock: false, credentialError: null };

  // The box says whether credentials are being kept, not whether they can be read.
  // Clearing it is what throws them away, and clearing it for someone whose keyring
  // is having a bad day is how the only readable copy would go.
  assert.equal(credentialsBoxChecked(damaged, secure), true, "a damaged blob is still a blob being kept");
  assert.equal(credentialsBoxChecked(readable, secure), true);
  assert.equal(credentialsBoxChecked(locked, secure), true);
  assert.equal(credentialsBoxChecked(none, secure), false);
  // Losing the keyring does not lose the intent to retain a blob already encrypted
  // by it. Carrying that opaque value forward needs no encryption at all.
  assert.equal(credentialsBoxChecked(damaged, { secureStorage: false }), true);
  assert.equal(credentialsControlEnabled(damaged, { secureStorage: false }), true);
  assert.equal(credentialsControlEnabled(none, { secureStorage: false }), false);
  assert.equal(credentialsControlEnabled(none, secure), true);

  // Locked is not damaged: nothing has tried to read it yet.
  assert.equal(credentialsUnreadable(damaged), true);
  assert.equal(credentialsUnreadable(locked), false);
  assert.equal(credentialsUnreadable(readable), false);

  // Replaced, so mended, and it may say so.
  assert.deepEqual(
    afterSave({ name: "Prod", damaged: true, replaced: true, keepingCredentials: true, credentialsSaved: true }),
    { damaged: false, message: "Saved “Prod” with encrypted credentials" },
  );
  // Nothing was entered, so the unreadable blob was carried across untouched. This
  // is the save that used to report a repair that had not happened.
  assert.deepEqual(
    afterSave({ name: "Prod", damaged: true, replaced: false, keepingCredentials: true, credentialsSaved: true }),
    { damaged: true, message: "Saved “Prod”. Its saved credentials still cannot be read" },
  );
  // Unticked, so discarded outright: there is nothing left to be unreadable.
  assert.deepEqual(
    afterSave({ name: "Prod", damaged: true, replaced: false, keepingCredentials: false, credentialsSaved: false }),
    { damaged: false, message: "Saved “Prod”" },
  );
  assert.deepEqual(
    afterSave({ name: "Prod", damaged: false, replaced: false, keepingCredentials: true, credentialsSaved: true }),
    { damaged: false, message: "Saved “Prod” with encrypted credentials" },
  );
});

test("saved secrets fill only what is empty, and only for the server they were saved for", () => {
  const saved = {
    host: "prod.example", port: 22, username: "deploy", password: "saved-pw", passphrase: "saved-pp",
    jump: { enabled: true, host: "bastion", port: 2222, username: "ops", password: "jump-pw", passphrase: "" },
  };
  // What a tab keeps for Reconnect: the same servers, no secrets.
  const blank = {
    host: "PROD.example", port: 22, username: "deploy", password: "", passphrase: "",
    jump: { enabled: true, host: "bastion", port: 2222, username: "ops", password: "", passphrase: "" },
  };
  const filled = fillSavedSecrets(blank, saved);
  assert.equal(filled.password, "saved-pw", "a host name differing only in case is the same host");
  assert.equal(filled.passphrase, "saved-pp");
  assert.equal(filled.jump.password, "jump-pw");

  const typed = fillSavedSecrets({ ...blank, password: "typed" }, saved);
  assert.equal(typed.password, "typed", "anything typed by hand wins");

  // Another saved connection's password must never go to this server.
  for (const elsewhere of [{ host: "staging.example" }, { port: 2200 }, { username: "root" }]) {
    const other = fillSavedSecrets({ ...blank, ...elsewhere }, saved);
    assert.equal(other.password, "", `no saved password for ${JSON.stringify(elsewhere)}`);
    assert.equal(other.passphrase, "");
    assert.equal(other.jump.password, "jump-pw", "the jump host is judged on its own");
  }
  const otherJump = fillSavedSecrets({ ...blank, jump: { ...blank.jump, host: "other-bastion" } }, saved);
  assert.equal(otherJump.password, "saved-pw");
  assert.equal(otherJump.jump.password, "", "nor does a jump password go to another jump host");
  const noJump = fillSavedSecrets({ ...blank, jump: { ...blank.jump, enabled: false } }, saved);
  assert.equal(noJump.jump.password, "", "a jump host switched off is given nothing");
});

test("a temporary keyring outage cannot discard an existing credential", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-keyring-outage-"));
  const state = { available: true };
  try {
    const store = new ProfileStore({
      filePath: path.join(directory, "connections.json"),
      encrypt: (plaintext) => Buffer.from(`keyring:${plaintext}`, "utf8"),
      decrypt: (encrypted) => {
        if (!state.available) throw new Error("keyring is temporarily unavailable");
        const text = encrypted.toString("utf8");
        if (!text.startsWith("keyring:")) throw new Error("not keyring ciphertext");
        return text.slice("keyring:".length);
      },
      canEncrypt: () => state.available,
    });
    const saved = store.save({ name: "Prod", startPath: "~", saveCredentials: true, connection: CONNECTION });

    state.available = false;
    const unavailable = store.get(saved.id);
    assert.equal(unavailable.credentialsPresent, true);
    assert.match(unavailable.credentialError, /could not be decrypted/);
    const keepingCredentials = credentialsBoxChecked(unavailable, { secureStorage: false });
    assert.equal(keepingCredentials, true, "the unavailable keyring does not clear retention");

    // A non-credential edit carries the ciphertext byte-for-byte without needing
    // the keyring. When the keyring comes back, both it and the edit are there.
    store.save({
      id: saved.id, name: "Prod", startPath: "/srv", saveCredentials: keepingCredentials,
      connection: { ...unavailable.connection, port: 2222 },
    });
    state.available = true;
    const restored = store.get(saved.id);
    assert.equal(restored.connection.password, "hunter2");
    assert.equal(restored.connection.port, 2222);

    // Trying to replace it during another outage fails without changing the good
    // blob. Even an explicitly confirmed replacement has nowhere safe to land.
    state.available = false;
    assert.throws(() => store.save({
      id: saved.id, name: "Prod", startPath: "/srv", saveCredentials: true,
      replaceCredentials: true,
      connection: { ...unavailable.connection, port: 2222, password: "replacement" },
    }), /Secure credential storage is unavailable/);
    state.available = true;
    assert.equal(store.get(saved.id).connection.password, "hunter2");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("with no keyring, a master password is what makes saving credentials possible", async () => {
  const { store, directory } = storeFixture({ keyring: false });
  try {
    assert.throws(() => store.save({ name: "No keyring", connection: CONNECTION, saveCredentials: true }),
      /Set a master password/);

    const vault = new Vault({});
    store.attachVault(vault);
    vault.adopt(await vault.create("a good long password", { mode: "minutes", minutes: 15 }));
    store.saveVaultConfig(vault.toJSON());
    const saved = store.save({ name: "No keyring", connection: CONNECTION, saveCredentials: true });
    assert.equal(store.get(saved.id).connection.password, "hunter2");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("a credential that can no longer be read does not block a master password", async () => {
  const { store, directory } = storeFixture();
  try {
    const good = store.save({ name: "Readable", connection: CONNECTION, saveCredentials: true });
    const bad = store.save({ name: "Damaged", connection: CONNECTION, saveCredentials: true });
    // As if the keyring had changed under a stored secret: the ciphertext is there
    // and no longer opens.
    const raw = JSON.parse(fs.readFileSync(path.join(directory, "connections.json"), "utf8"));
    const damaged = raw.profiles.find((profile) => profile.name === "Damaged");
    damaged.secret.data = Buffer.from("not-keyring-ciphertext", "utf8").toString("base64");
    fs.writeFileSync(path.join(directory, "connections.json"), JSON.stringify(raw));

    const reloaded = new ProfileStore({
      filePath: path.join(directory, "connections.json"),
      encrypt: (plaintext) => Buffer.from(`keyring:${plaintext}`, "utf8"),
      decrypt: (encrypted) => {
        const text = encrypted.toString("utf8");
        if (!text.startsWith("keyring:")) throw new Error("not keyring ciphertext");
        return text.slice("keyring:".length);
      },
      canEncrypt: () => true,
    });
    const vault = new Vault({});
    reloaded.attachVault(vault);
    const created = await vault.create("a good long password", { mode: "minutes", minutes: 15 });
    const result = reloaded.applyMasterPassword(created);
    vault.adopt(created);

    assert.deepEqual(result, { rewrapped: 1, dropped: 1 });
    assert.equal(reloaded.get(good.id).connection.password, "hunter2", "the readable one came across");
    assert.equal(reloaded.get(bad.id).credentialsSaved, false, "and the damaged one was cleared, not kept");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

/* ------------------------------- names the far end makes up */

// A listing is data from the other end of the connection, and the other end is not
// always the friendly server it claims to be. These drive the manager with a stub
// transport, which is the only way to produce a name no filesystem could hold.
function stubbedManager(readdir, extra = {}) {
  const directoryAttributes = { isDirectory: () => true, isSymbolicLink: () => false, size: 0, mode: 0o40755 };
  const fileAttributes = { isDirectory: () => false, isSymbolicLink: () => false, size: 7, mode: 0o100644 };
  const touched = [];
  const manager = new SshManager({
    knownHosts: { get: () => null },
    confirmHost: async () => ({ accept: false, remember: false }),
  });
  manager.client = {};
  manager.connection = { home: "/" };
  manager.transport = {
    kind: "sftp",
    concurrencyLimit: Infinity,
    close: () => undefined,
    call: async (method, args) => {
      touched.push([method, ...args.map(String)]);
      if (extra[method]) return extra[method](args, { directoryAttributes, fileAttributes });
      if (method === "readdir") return readdir(args[0], { directoryAttributes, fileAttributes });
      if (method === "lstat" || method === "stat") {
        return args[0] === "/folder" || args[0] === "/target" ? directoryAttributes : fileAttributes;
      }
      if (method === "realpath") return args[0];
      throw new Error(`unexpected ${method}`);
    },
  };
  return { manager, touched };
}

test("a made-up name in a listing cannot write outside the chosen folder", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-escape-"));
  try {
    const chosen = path.join(root, "chosen");
    fs.mkdirSync(chosen);
    const written = [];
    const { manager } = stubbedManager(
      (_directory, { fileAttributes }) => [{ filename: "../../escaped.txt", attrs: fileAttributes }],
      { fastGet: (args) => { written.push(args[1]); fs.writeFileSync(args[1], "from the server\n"); return { ok: true }; } },
    );

    await assert.rejects(() => manager.download(["/folder"], chosen), /unusable name/,
      "a recursive download stops rather than following it");
    assert.deepEqual(written, [], "and nothing was written at all");
    assert.equal(fs.existsSync(path.join(root, "escaped.txt")), false, "least of all outside the chosen folder");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("a made-up name in a listing cannot delete outside the selected folder", async () => {
  const { manager, touched } = stubbedManager(
    (_directory, { fileAttributes }) => [{ filename: "../sibling", attrs: fileAttributes }],
    { unlink: () => ({ ok: true }), rmdir: () => ({ ok: true }) },
  );
  const result = await manager.delete(["/target"]);
  assert.equal(result.deleted, 0);
  assert.match(result.failures[0].error, /unusable name/);
  const removals = touched.filter(([method]) => method === "unlink" || method === "rmdir");
  assert.deepEqual(removals, [], "nothing was removed on either side of the boundary");
});

test("browsing keeps what it can read and counts what it will not follow", async () => {
  const { manager } = stubbedManager((_directory, { fileAttributes, directoryAttributes }) => [
    { filename: "readme.txt", attrs: fileAttributes },
    { filename: "../../etc", attrs: directoryAttributes },
    { filename: "..", attrs: directoryAttributes },
    { filename: "deep/name", attrs: fileAttributes },
    { filename: "notes and spaces.txt", attrs: fileAttributes },
  ]);
  const listing = await manager.list("/folder");
  assert.deepEqual(listing.entries.map((entry) => entry.name), ["notes and spaces.txt", "readme.txt"],
    "the ordinary names are shown, in the usual order");
  assert.equal(listing.rejected, 3, "and the three that could not exist are counted, not shown");
});

test("search does not follow a folder whose name could not exist", async () => {
  const { manager, touched } = stubbedManager((directory, { fileAttributes, directoryAttributes }) => (
    directory === "/folder"
      ? [
        { filename: "../escape", attrs: directoryAttributes },
        { filename: "target-here.txt", attrs: fileAttributes },
      ]
      : []
  ));
  const result = await manager.search("/folder", "target", true, { milliseconds: 30000 });
  assert.deepEqual(result.entries.map((entry) => entry.name), ["target-here.txt"]);
  assert.equal(result.rejected, 1);
  assert.equal(touched.filter(([method, target]) => method === "readdir" && target !== "/folder").length, 0,
    "the only folder read is the one that was searched");
});

test("a download will not write through a shortcut that is already there", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-shortcut-"));
  try {
    const chosen = path.join(root, "chosen");
    fs.mkdirSync(chosen);
    // A shortcut pointing at something that does not exist yet is the case that
    // matters: writing through it would create the file it names, wherever that is.
    const wouldBeCreated = path.join(root, "planted.txt");
    try {
      fs.symlinkSync(wouldBeCreated, path.join(chosen, "readme.txt"));
    } catch {
      return; // A platform that will not make symbolic links has nothing to check here.
    }
    const { manager } = stubbedManager(
      (_directory, { fileAttributes }) => [{ filename: "readme.txt", attrs: fileAttributes }],
      { fastGet: (args) => { fs.writeFileSync(args[1], "from the server\n"); return { ok: true }; } },
    );
    await assert.rejects(() => manager.download(["/folder/readme.txt"], chosen), /shortcut/);
    assert.equal(fs.existsSync(wouldBeCreated), false, "and what the shortcut named was never created");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("an ordinary name that merely looks odd is still an ordinary name", () => {
  for (const name of ["...", ".hidden", "a:b", "12:30 notes.txt", "it's fine", "-dashes", "spaced out.tar.gz"]) {
    assert.equal(safeRemoteName(name), true, `${name} should be allowed`);
  }
  for (const name of ["", ".", "..", "a/b", "a\\b", "../../escape", "nul\0byte"]) {
    assert.equal(safeRemoteName(name), false, `${JSON.stringify(name)} should be refused`);
  }
});

test("a copy launched from another folder is not mistaken for this one", () => {
  const running = path.join(path.sep, "apps", "0.11.4", "SSH Workbench.exe");
  assert.equal(sameInstallation(running, running), true);
  assert.equal(sameInstallation(path.join(path.sep, "apps", "0.11.4", ".", "SSH Workbench.exe"), running), true,
    "the same file reached by a longer path is the same copy");
  assert.equal(sameInstallation(path.join(path.sep, "apps", "0.11.3", "SSH Workbench.exe"), running), false,
    "an older extract in its own folder is a different copy");
  assert.equal(sameInstallation(undefined, running), true, "nothing known means no refusal");
  if (process.platform === "win32") {
    assert.equal(sameInstallation(running.toUpperCase(), running), true, "Windows paths differ in case only");
  }
});


// A minimal asar: the 16-byte preamble, the header JSON, then the files. Building one
// by hand is the only way to check the reader against the format rather than against
// a second copy of the reader's own assumptions.
function writeAsar(directory, contents) {
  const body = Buffer.from(contents, "utf8");
  const header = Buffer.from(JSON.stringify({
    files: { "package.json": { offset: "0", size: body.length } },
  }), "utf8");
  const padding = (4 - (header.length % 4)) % 4;
  const preamble = Buffer.alloc(16);
  preamble.writeUInt32LE(4, 0);
  preamble.writeUInt32LE(8 + header.length + padding, 4);
  preamble.writeUInt32LE(4 + header.length + padding, 8);
  preamble.writeUInt32LE(header.length, 12);
  const file = path.join(directory, "app.asar");
  fs.writeFileSync(file, Buffer.concat([preamble, header, Buffer.alloc(padding), body]));
  return file;
}

test("copies a terminal selection without the indentation it all shared", () => {
  // The case that prompted it: a YAML fragment printed inside a tool's own output.
  const printed = "    hooks:\n      PreToolUse:\n        - matcher: Bash\n\n      Stop: []\n";
  assert.equal(cleanCopy(printed), "hooks:\n  PreToolUse:\n    - matcher: Bash\n\n  Stop: []\n");
  // One line is a block of one, and its indentation is no more wanted than a block's.
  assert.equal(cleanCopy("      one line"), "one line");
  // Only the shared part goes; a line that is already flush leaves every other line
  // where it stands, because that difference is the structure.
  assert.equal(cleanCopy("no margin\n  deeper"), "no margin\n  deeper");
  // A blank line in the middle does not veto the margin, and comes back empty rather
  // than holding the spaces the terminal padded it out with.
  assert.equal(cleanCopy("  a\n    \n  b"), "a\n\nb");
  // A tab is one character and eight columns; measuring one and slicing the other
  // would change a line's depth, so a margin they do not share is left alone.
  assert.equal(commonMargin(["\tone", "\t\ttwo"]), "\t");
  assert.equal(cleanCopy("\tone\n\t\ttwo"), "one\n\ttwo");
  assert.equal(cleanCopy("  spaces\n\ttab"), "  spaces\n\ttab");
  assert.equal(cleanCopy(""), "");
  assert.equal(cleanCopy("   "), "");
});

test("identifies an installation by the file that was launched", () => {
  assert.equal(installationPath({ env: {}, execPath: "/opt/app/SSH Workbench" }), "/opt/app/SSH Workbench");
  // An AppImage runs from a fresh mount point every time; the file is what persists.
  assert.equal(
    installationPath({ env: { APPIMAGE: "/home/user/SSH-Workbench.AppImage" }, execPath: "/tmp/.mount_ab12/AppRun" }),
    "/home/user/SSH-Workbench.AppImage");
  assert.equal(installationPath({ env: { SSH_WORKBENCH_INSTALLATION: "/stand/in" }, execPath: "/real" }), "/stand/in");
});

test("reads the build number of a copy sitting in another folder", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-install-"));
  try {
    // A packaged build: package.json inside resources/app.asar, beside the executable.
    const packaged = path.join(root, "packaged");
    fs.mkdirSync(path.join(packaged, "resources"), { recursive: true });
    writeAsar(path.join(packaged, "resources"), JSON.stringify({ name: "ssh-workbench", version: "0.11.3" }));
    assert.equal(installedVersion(path.join(packaged, "SSH Workbench.exe")), "0.11.3");

    // An unpackaged build keeps it in resources/app instead.
    const unpacked = path.join(root, "unpacked");
    fs.mkdirSync(path.join(unpacked, "resources", "app"), { recursive: true });
    fs.writeFileSync(path.join(unpacked, "resources", "app", "package.json"),
      JSON.stringify({ name: "ssh-workbench", version: "0.9.2" }));
    assert.equal(installedVersion(path.join(unpacked, "SSH Workbench.exe")), "0.9.2");

    // Anything else answers nothing at all rather than guessing.
    assert.equal(installedVersion(path.join(root, "empty", "SSH Workbench.exe")), null);
    assert.equal(installedVersion(""), null);
    const truncated = path.join(root, "truncated");
    fs.mkdirSync(path.join(truncated, "resources"), { recursive: true });
    fs.writeFileSync(path.join(truncated, "resources", "app.asar"), Buffer.alloc(8));
    assert.equal(installedVersion(path.join(truncated, "SSH Workbench.exe")), null);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("groups the running copies that are not this installation", () => {
  const identify = (candidate) => (candidate.includes("Workbench")
    ? { name: "ssh-workbench", version: candidate.includes("old") ? "0.11.3" : "0.11.5" }
    : null);
  const listing = [
    { pid: 10, path: "/new/SSH Workbench" },
    { pid: 11, path: "/new/SSH Workbench" },
    { pid: 20, path: "/old/SSH Workbench" },
    { pid: 21, path: "/old/SSH Workbench" },
    { pid: 30, path: "/usr/lib/firefox/firefox" },
    { pid: 40, path: "" },
  ];
  const found = otherInstallations(listing, {
    installation: "/new/SSH Workbench",
    pid: 10,
    execPath: "/new/SSH Workbench",
    identify,
  });
  // One entry for the other folder, carrying every process that has to be closed;
  // this installation's own processes, another application, and a path the operating
  // system would not give up are all left out.
  assert.deepEqual(found, [{ path: "/old/SSH Workbench", pids: [20, 21] }]);
  assert.deepEqual(otherInstallations(listing, {
    installation: "/old/SSH Workbench",
    pid: 20,
    execPath: "/old/SSH Workbench",
    identify,
  }), [{ path: "/new/SSH Workbench", pids: [10, 11] }]);
  assert.deepEqual(otherInstallations([], { installation: "/new/SSH Workbench", pid: 10, identify }), []);
  // A process that shares the executable's name but cannot be identified is still
  // taken to be this application: an unpackaged run has nothing beside it to read.
  assert.deepEqual(otherInstallations([{ pid: 50, path: "/dev/electron" }], {
    installation: "/other/electron",
    pid: 1,
    execPath: "/other/electron",
    identify: () => null,
  }), [{ path: "/dev/electron", pids: [50] }]);
});

test("tells a copy's own helper processes from a foreign build", () => {
  // An AppImage runs from a mount point, so every one of its processes — the main
  // one, its renderers, its GPU process — has an executable path that differs from
  // the file that was launched. Without the installation each process claims, a copy
  // would find its own helpers foreign and close them along with the other build.
  const mine = "/home/user/SSH-Workbench.AppImage";
  const listing = [
    { pid: 1, path: "/tmp/.mount_ab12/ssh-workbench", installation: mine },
    { pid: 2, path: "/tmp/.mount_ab12/ssh-workbench", installation: mine },
    { pid: 7, path: "/tmp/.mount_cd34/ssh-workbench", installation: "/opt/SSH-Workbench-0.11.3.AppImage" },
  ];
  assert.deepEqual(
    otherInstallations(listing, { installation: mine, pid: 1, execPath: "/tmp/.mount_ab12/ssh-workbench", identify: () => null }),
    // Named by the file that was launched, which is what the user recognises, and
    // what closing it has to report.
    [{ path: "/opt/SSH-Workbench-0.11.3.AppImage", pids: [7] }]);
  // Two launches of one AppImage claim the same file and are one installation, so the
  // second is answered with a window rather than an offer to close the first.
  assert.deepEqual(
    otherInstallations([{ pid: 9, path: "/tmp/.mount_ef56/ssh-workbench", installation: mine }],
      { installation: mine, pid: 1, execPath: "/tmp/.mount_ab12/ssh-workbench", identify: () => null }),
    []);
  // A process that will not say, running the same executable, is one of this copy's.
  assert.deepEqual(
    otherInstallations([{ pid: 11, path: "/dist/electron", installation: null }],
      { installation: "/stand/in", pid: 1, execPath: "/dist/electron", identify: () => null }),
    []);
});

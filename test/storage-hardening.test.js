"use strict";

// Regression tests for the 0.12.0 storage and credential audit: saved connections,
// the master password, trusted host keys, and closing another running copy. Each
// test is one finding, written as what has to stay true rather than as the bug.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { Server, utils } = require("ssh2");

const { ProfileStore } = require("../lib/profile-store");
const { Vault, EVERY_IDLE_SECONDS } = require("../lib/vault");
const { KnownHosts, hostIdentity } = require("../lib/known-hosts");
const { otherInstallations, identifyInstallation, sameProcess, processStart } = require("../lib/running-copies");
const { SshManager } = require("../lib/ssh-manager");
const { afterSave, sameHop } = require("../lib/saved-credentials");
const { startTestServer } = require("./helpers/ssh-test-server");

function scratch(t, label) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `ssh-workbench-${label}-`));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// A stand-in for safeStorage whose keyring can be switched off, the way a locked or
// missing Secret Service is on Linux, or swapped for another (`era`), the way a
// changed keyring makes old ciphertext permanently unreadable.
function keyring() {
  const state = { available: true, era: "one", decrypts: 0 };
  return {
    state,
    encrypt: (plaintext) => {
      if (!state.available) throw new Error("keyring unavailable");
      return Buffer.from(`${state.era}:${plaintext}`, "utf8");
    },
    decrypt: (buffer) => {
      state.decrypts += 1;
      if (!state.available) throw new Error("keyring unavailable");
      const text = buffer.toString("utf8");
      if (!text.startsWith(`${state.era}:`)) throw new Error("not this keyring's ciphertext");
      return text.slice(state.era.length + 1);
    },
    canEncrypt: () => state.available,
  };
}

function openStore(file, ring, vault = null) {
  return new ProfileStore({ filePath: file, encrypt: ring.encrypt, decrypt: ring.decrypt, canEncrypt: ring.canEncrypt, vault });
}

function connection(host, extra = {}) {
  return {
    host, port: 22, username: "fixture-user", authType: "password", keyPath: "", protocol: "sftp-scp",
    jump: { enabled: false, host: "", port: 22, username: "", authType: "agent", keyPath: "" },
    ...extra,
  };
}

async function vaultedStore(t, policy = { mode: "minutes", minutes: 15 }) {
  const directory = scratch(t, "vaulted");
  const ring = keyring();
  const vault = new Vault();
  const store = openStore(path.join(directory, "connections.json"), ring, vault);
  const created = await vault.create("first master password", policy);
  store.applyMasterPassword(created);
  vault.adopt(created);
  return { directory, ring, vault, store, file: path.join(directory, "connections.json") };
}

/* ------------------------------------------- 1. re-protecting never discards */

test("changing the master password while the keyring is away keeps every credential", async (t) => {
  const { ring, vault, store } = await vaultedStore(t);
  const { id } = store.save({ name: "Alpha", saveCredentials: true, connection: { ...connection("alpha.example.test"), password: "alpha-secret" } });

  ring.state.available = false;
  for (const [current, next] of [["first master password", "second master password"], ["second master password", "third master password"]]) {
    const oldKey = await vault.keyFor(current);
    const created = await vault.create(next, vault.policy);
    const result = store.changeMasterPassword({ oldKey, newKey: created.key, config: created.config });
    vault.adopt(created);
    assert.deepEqual(result, { rewrapped: 0, carried: 1, dropped: 0 }, "carried across, and said so");
  }
  ring.state.available = true;
  assert.equal(store.secrets(id).connection.password, "alpha-secret", "readable with the newest password once the keyring is back");
  // The first read with everything available moves it behind the current key.
  const onDisk = JSON.parse(fs.readFileSync(store.filePath, "utf8")).profiles[0].secret;
  assert.equal(onDisk.key, undefined, "and it no longer needs the earlier key");
  await vault.unlock("third master password");
  assert.equal(store.secrets(id).connection.password, "alpha-secret");
});

test("setting a master password while the keyring is away keeps keyring credentials, behind the master password", async (t) => {
  const directory = scratch(t, "set-away");
  const ring = keyring();
  const vault = new Vault();
  const store = openStore(path.join(directory, "connections.json"), ring, vault);
  const { id } = store.save({ name: "Bravo", saveCredentials: true, connection: { ...connection("bravo.example.test"), password: "bravo-secret" } });

  ring.state.available = false;
  const created = await vault.create("a master password", { mode: "minutes", minutes: 15 });
  assert.deepEqual(store.applyMasterPassword(created), { rewrapped: 0, carried: 1, dropped: 0 });
  vault.adopt(created);
  ring.state.available = true;

  assert.equal(store.list()[0].masterPassword, true, "it counts as protected by the master password");
  vault.lock();
  assert.equal(store.get(id).needsUnlock, true, "using it asks for the master password");
  assert.equal(store.secrets(id).needsUnlock, true);
  await vault.unlock("a master password");
  assert.equal(store.secrets(id).connection.password, "bravo-secret");
  assert.equal(JSON.parse(fs.readFileSync(store.filePath, "utf8")).profiles[0].secret.scheme, "vault",
    "and the first use moved it behind the master password");
});

test("removing the master password refuses rather than lose a credential it cannot open", async (t) => {
  const { ring, vault, store, file } = await vaultedStore(t);
  store.save({ name: "Charlie", saveCredentials: true, connection: { ...connection("charlie.example.test"), password: "charlie-secret" } });
  const before = fs.readFileSync(file, "utf8");
  ring.state.era = "two";
  const key = await vault.keyFor("first master password");
  assert.throws(() => store.clearMasterPassword({ key }), (error) => {
    assert.deepEqual(error.unreadableProfiles, ["Charlie"]);
    assert.match(error.message, /“Charlie”.*Nothing was changed/);
    return true;
  });
  assert.equal(fs.readFileSync(file, "utf8"), before, "the file is untouched");
});

/* --------------------------------------- 2. a connection is matched by its id */

test("a new connection with an existing name is refused, and inherits nothing", async (t) => {
  const directory = scratch(t, "names");
  const store = openStore(path.join(directory, "connections.json"), keyring());
  const prod = store.save({
    name: "Prod", saveCredentials: true,
    connection: {
      ...connection("old-host.example.test"), password: "old-host-password",
      jump: { enabled: true, host: "old-bastion.example.test", port: 22, username: "fixture-user", authType: "password", keyPath: "", password: "old-bastion-password" },
    },
  });
  assert.throws(() => store.save({
    name: "prod", saveCredentials: true,
    connection: { ...connection("new-host.example.test"), password: "new-host-password" },
  }), (error) => error.duplicateName && /already exists/.test(error.message));
  // Renaming another connection onto it is the same clash.
  const other = store.save({ name: "Staging", saveCredentials: false, connection: connection("staging.example.test") });
  assert.throws(() => store.save({ id: other.id, name: "PROD", saveCredentials: false, connection: connection("staging.example.test") }), /already exists/);
  // A connection changing the case of its own name is not a clash.
  store.save({ id: prod.id, name: "PROD", saveCredentials: true, connection: { ...connection("old-host.example.test"), jump: { enabled: true, host: "old-bastion.example.test", port: 22, username: "fixture-user", authType: "password", keyPath: "" } } });

  assert.deepEqual(store.list().map((entry) => entry.name).sort(), ["PROD", "Staging"]);
  const kept = store.secrets(prod.id).connection;
  assert.equal(kept.host, "old-host.example.test");
  assert.equal(kept.password, "old-host-password");
  assert.equal(kept.jump.password, "old-bastion-password");
});

test("a hop whose server changes loses that hop's saved secrets, and only that hop's", async (t) => {
  const directory = scratch(t, "hops");
  const store = openStore(path.join(directory, "connections.json"), keyring());
  const jump = { enabled: true, host: "old-bastion.example.test", port: 22, username: "fixture-user", authType: "password", keyPath: "" };
  const saved = store.save({
    name: "Through a bastion", saveCredentials: true,
    connection: { ...connection("inner.example.test"), password: "inner-password", jump: { ...jump, password: "bastion-password" } },
  });

  // The bastion is replaced and its password box left empty.
  const moved = store.save({
    id: saved.id, name: "Through a bastion", saveCredentials: true,
    connection: { ...connection("inner.example.test"), jump: { ...jump, host: "new-bastion.example.test" } },
  });
  assert.deepEqual(moved.credentialsDropped, ["jump host"]);
  let now = store.secrets(saved.id).connection;
  assert.equal(now.jump.password, "", "the old bastion's password is not kept for the new one");
  assert.equal(now.password, "inner-password", "the destination keeps its own");
  assert.match(afterSave({ name: "Through a bastion", credentialsSaved: true, keepingCredentials: true, credentialsDropped: moved.credentialsDropped }).message,
    /saved for the jump host were dropped/);

  // A different port is a different server too; letter case is not.
  store.save({
    id: saved.id, name: "Through a bastion", saveCredentials: true,
    connection: { ...connection("INNER.example.test."), jump: { ...jump, host: "new-bastion.example.test", password: "new-bastion-password" } },
  });
  now = store.secrets(saved.id).connection;
  assert.equal(now.password, "inner-password", "a host spelled differently is the same host");
  assert.equal(now.jump.password, "new-bastion-password");
  const ported = store.save({
    id: saved.id, name: "Through a bastion", saveCredentials: true,
    connection: { ...connection("inner.example.test", { port: 2222 }), jump: { ...jump, host: "new-bastion.example.test" } },
  });
  assert.deepEqual(ported.credentialsDropped, ["destination"]);
  now = store.secrets(saved.id).connection;
  assert.equal(now.password, "");
  assert.equal(now.jump.password, "new-bastion-password");

  assert.equal(sameHop({ host: "[::1]", port: 22, username: "u" }, { host: "::1", port: "22", username: "u" }), true);
  assert.equal(sameHop({ host: "a.example.test", port: 22, username: "u" }, { host: "a.example.test", port: 22, username: "v" }), false);
});

/* ------------------------------- 9. choosing a connection decrypts nothing */

test("choosing a saved connection reads no secret and does not count as using one", async (t) => {
  let clock = Date.parse("2026-03-01T09:00:00Z");
  const directory = scratch(t, "choose");
  const ring = keyring();
  const vault = new Vault({ now: () => clock });
  const store = openStore(path.join(directory, "connections.json"), ring, vault);
  const created = await vault.create("browse master password", { mode: "minutes", minutes: 15 });
  store.applyMasterPassword(created);
  vault.adopt(created);
  const { id } = store.save({ name: "Juliet", saveCredentials: true, connection: { ...connection("juliet.example.test"), password: "juliet-secret" } });

  const decryptsBefore = ring.state.decrypts;
  for (let step = 0; step < 8; step += 1) {
    clock += 14 * 60 * 1000;
    const shown = store.get(id);
    assert.equal(shown.connection.password, "", "no secret goes to the form");
  }
  assert.equal(ring.state.decrypts, decryptsBefore, "nothing was decrypted");
  assert.equal(vault.unlocked, false, "and the unlock ran out on time");
  assert.equal(store.get(id).needsUnlock, true);

  // Under "ask every time" the connect-time read is the one use.
  const every = new Vault({ config: { ...vault.toJSON(), policy: { mode: "every" } }, now: () => clock });
  store.attachVault(every);
  await every.unlock("browse master password");
  store.get(id);
  assert.equal(every.unlocked, true, "choosing spends nothing");
  assert.equal(store.secrets(id).connection.password, "juliet-secret");
  assert.equal(every.unlocked, false, "connecting spends the unlock");
});

/* ---------------------------------------------------- 8, 10, 11. the vault */

test("under ask-every-time an unused key does not stay, and a second unlock zeroes the first key", async () => {
  let clock = Date.parse("2026-03-01T09:00:00Z");
  const vault = new Vault({ now: () => clock });
  const created = await vault.create("every time password", { mode: "every" });
  vault.adopt(created);
  assert.equal(vault.unlocked, true);
  clock += (EVERY_IDLE_SECONDS + 1) * 1000;
  assert.equal(vault.unlocked, false, "the key is gone once its short wait is over");
  assert.throws(() => vault.wrap("x"), /locked/);

  const timed = new Vault({ config: { ...created.config, policy: { mode: "minutes", minutes: 15 } }, now: () => clock });
  await timed.unlock("every time password");
  const first = timed.key;
  await timed.unlock("every time password");
  assert.notEqual(first, timed.key);
  assert.ok(first.every((byte) => byte === 0), "the replaced key was zeroed");
});

test("wrong master passwords sent together are rate limited like ones sent in turn", async () => {
  const { config } = await new Vault().create("correct horse battery", { mode: "minutes", minutes: 15 });
  const vault = new Vault({ config });
  const results = await Promise.allSettled(Array.from({ length: 12 }, (_, index) => vault.keyFor(`wrong guess ${index}`)));
  const checked = results.filter((result) => result.status === "rejected" && !result.reason.rateLimited).length;
  assert.equal(checked, 5, "four free attempts and the one that starts the pause");
  assert.ok(vault.cooldownSeconds() > 0);
});

test("a clock set back does not stretch an unlock or a pause", async () => {
  let clock = Date.parse("2026-03-02T12:00:00Z");
  const vault = new Vault({ now: () => clock });
  vault.adopt(await vault.create("clock password", { mode: "minutes", minutes: 15 }));
  clock -= 6 * 3600 * 1000;
  assert.equal(vault.unlocked, false, "more time left than the window allows is not believed");

  vault.blockedUntil = clock + 10 * 3600 * 1000;
  assert.ok(vault.cooldownSeconds() <= 60, "nor is a pause longer than the longest there is");
});

/* ------------------------------------------- 4, 6, 12. the files themselves */

test("entries this version does not recognise are kept, copied, and warned about", (t) => {
  const directory = scratch(t, "unrecognised");
  const file = path.join(directory, "connections.json");
  const good = { id: "id-good", name: "Delta", updatedAt: "2026-01-01T00:00:00.000Z", startPath: "~", connection: connection("delta.example.test"), secret: null };
  const future = { ...good, id: "id-future", name: "Echo", secret: { scheme: "hardware-token", data: "AAAA" } };
  const handEdited = { id: "id-hand", name: "Foxtrot", connection: connection("foxtrot.example.test"), secret: null };
  fs.writeFileSync(file, JSON.stringify({ version: 2, vault: null, profiles: [good, future, handEdited] }));

  const store = openStore(file, keyring());
  assert.deepEqual(store.list().map((entry) => entry.name), ["Delta"]);
  assert.match(store.loadWarning, /2 saved connections were not recognised/);
  assert.ok(fs.existsSync(`${file}.unrecognised`), "a copy was kept");
  store.save({ id: "id-good", name: "Delta", saveCredentials: false, connection: connection("delta.example.test", { port: 2222 }) });
  const onDisk = JSON.parse(fs.readFileSync(file, "utf8")).profiles;
  assert.deepEqual(onDisk.map((entry) => entry.id), ["id-good", "id-future", "id-hand"]);
  assert.deepEqual(onDisk[1], future, "written back exactly as found");
});

test("a file from a newer version is used but not written over", (t) => {
  const directory = scratch(t, "newer");
  const file = path.join(directory, "connections.json");
  const raw = JSON.stringify({ version: 99, vault: null, profiles: [{ id: "id-g", name: "Golf", updatedAt: "", startPath: "~", connection: connection("golf.example.test"), secret: null }], extra: true });
  fs.writeFileSync(file, raw);
  const store = openStore(file, keyring());
  assert.deepEqual(store.list().map((entry) => entry.name), ["Golf"]);
  assert.match(store.loadWarning, /newer version/);
  assert.throws(() => store.save({ name: "Hotel", saveCredentials: false, connection: connection("hotel.example.test") }), /newer version/);
  assert.equal(fs.readFileSync(file, "utf8"), raw);

  const hostsFile = path.join(directory, "known-hosts.json");
  fs.writeFileSync(hostsFile, JSON.stringify({ version: 7, hosts: {} }));
  const hosts = new KnownHosts(hostsFile);
  assert.throws(() => hosts.remember("a.example.test:22", "ab".repeat(32)), /newer version/);
});

test("a damaged file is kept under a free name, every time, or not written over at all", (t) => {
  const directory = scratch(t, "corrupt");
  const file = path.join(directory, "connections.json");
  fs.writeFileSync(file, '{"version":2,"profiles":[{"id":"first-damaged-copy" ');
  openStore(file, keyring());
  fs.writeFileSync(file, '{"version":2,"profiles":[{"id":"second-damaged-copy" ');
  const second = openStore(file, keyring());
  assert.match(fs.readFileSync(`${file}.corrupt`, "utf8"), /first-damaged-copy/);
  assert.match(fs.readFileSync(`${file}.corrupt.1`, "utf8"), /second-damaged-copy/);
  assert.match(second.loadWarning, /connections\.json\.corrupt\.1/);

  // Valid JSON with no list of connections in it is no more usable.
  fs.writeFileSync(file, JSON.stringify({ connections: [] }));
  openStore(file, keyring());
  assert.ok(fs.existsSync(`${file}.corrupt.2`));

  // Nowhere to keep a copy: the original stays, and nothing writes over it.
  const locked = path.join(directory, "locked");
  fs.mkdirSync(locked);
  const lockedFile = path.join(locked, "connections.json");
  fs.writeFileSync(lockedFile, "{ damaged");
  fs.chmodSync(locked, 0o500);
  t.after(() => { try { fs.chmodSync(locked, 0o700); } catch { /* already removed */ } });
  if (process.getuid?.() === 0) return; // root ignores the permission
  const stuck = openStore(lockedFile, keyring());
  assert.match(stuck.loadWarning, /no copy/);
  fs.chmodSync(locked, 0o700);
  assert.throws(() => stuck.save({ name: "India", saveCredentials: false, connection: connection("india.example.test") }), /no copy/);
  assert.equal(fs.readFileSync(lockedFile, "utf8"), "{ damaged");

  const hostsFile = path.join(directory, "known-hosts.json");
  fs.writeFileSync(hostsFile, '{"hosts":{"first.example.test:22"');
  new KnownHosts(hostsFile);
  fs.writeFileSync(hostsFile, '{"hosts":{"second.example.test:22"');
  new KnownHosts(hostsFile);
  assert.match(fs.readFileSync(`${hostsFile}.corrupt`, "utf8"), /first\.example\.test/);
  assert.match(fs.readFileSync(`${hostsFile}.corrupt.1`, "utf8"), /second\.example\.test/);
});

test("a saved-connections file that is a symbolic link stays one", (t) => {
  const directory = scratch(t, "symlink");
  const real = path.join(directory, "synced", "connections.json");
  fs.mkdirSync(path.dirname(real));
  fs.writeFileSync(real, JSON.stringify({ version: 2, vault: null, profiles: [] }));
  const linked = path.join(directory, "profile", "connections.json");
  fs.mkdirSync(path.dirname(linked));
  fs.symlinkSync(real, linked);
  openStore(linked, keyring()).save({ name: "Kilo", saveCredentials: false, connection: connection("kilo.example.test") });
  assert.equal(fs.lstatSync(linked).isSymbolicLink(), true);
  assert.match(fs.readFileSync(real, "utf8"), /kilo\.example\.test/);

  // A link whose target does not exist yet creates that target.
  const dangling = path.join(directory, "profile", "known-hosts.json");
  const target = path.join(directory, "synced", "known-hosts.json");
  fs.symlinkSync(target, dangling);
  new KnownHosts(dangling).remember("kilo.example.test:22", "cd".repeat(32));
  assert.equal(fs.lstatSync(dangling).isSymbolicLink(), true);
  assert.match(fs.readFileSync(target, "utf8"), /kilo\.example\.test/);
});

/* ------------------------------------------------- 5. one name for one host */

test("host names are remembered in one spelling, and old entries are brought into it", (t) => {
  assert.equal(hostIdentity("Server.Example.Test.", 22), "server.example.test:22");
  assert.equal(hostIdentity("[::1]", "2222"), "::1:2222");
  const directory = scratch(t, "case");
  const file = path.join(directory, "known-hosts.json");
  const older = "11".repeat(32);
  const newer = "22".repeat(32);
  fs.writeFileSync(file, JSON.stringify({
    version: 1,
    hosts: {
      "Mixed.Example.Test:22": { sha256: older, trustedAt: "2025-01-01T00:00:00.000Z" },
      "mixed.example.test.:22": { sha256: newer, trustedAt: "2026-01-01T00:00:00.000Z" },
    },
  }));
  const hosts = new KnownHosts(file);
  assert.equal(hosts.get("MIXED.example.test:22").sha256, newer, "the most recently trusted spelling wins");
  assert.deepEqual(Object.keys(hosts.hosts), ["mixed.example.test:22"]);
});

/* ------------------------------------------- 7 and the PID check. takeover */

test("only a copy whose package says it is this application is closed", (t) => {
  const directory = scratch(t, "takeover");
  const install = (folder, manifest) => {
    fs.mkdirSync(path.join(directory, folder, "resources", "app"), { recursive: true });
    fs.writeFileSync(path.join(directory, folder, "resources", "app", "package.json"), JSON.stringify(manifest));
    return path.join(directory, folder, "electron");
  };
  const foreign = install("notes-app", { name: "unrelated-notes-app", version: "3.1.4" });
  const ours = install("older-build", { name: "ssh-workbench", version: "0.11.3" });
  const mine = path.join(directory, "checkout", "electron");
  assert.deepEqual(identifyInstallation(foreign), { name: "unrelated-notes-app", version: "3.1.4" });
  const groups = otherInstallations(
    [{ pid: 4242, path: foreign, installation: null }, { pid: 4343, path: ours, installation: null, started: "777" }],
    { installation: mine, pid: 1, execPath: mine },
  );
  assert.deepEqual(groups, [{ path: ours, pids: [4343], started: { 4343: "777" } }]);
});

test("a process id is only signalled while it still names the process that was listed", () => {
  assert.equal(sameProcess(1234, null), true, "nothing recorded: the id is all there is");
  assert.equal(sameProcess(1234, "500", { readStart: () => "500" }), true);
  assert.equal(sameProcess(1234, "500", { readStart: () => "900" }), false, "a reused id is someone else");
  assert.equal(sameProcess(1234, "500", { readStart: () => null }), false, "an ended process is gone");
  if (process.platform === "linux") {
    assert.ok(processStart(process.pid));
    assert.equal(sameProcess(process.pid, processStart(process.pid)), true);
  }
});

/* --------------------------------------- host keys over a real handshake */

// A server that completes key exchange and refuses every login, serving connection
// n with key n % keys.length -- so two routes to "one host" can present two keys.
function keyRotatingServer(t, keys) {
  let turn = 0;
  const servers = keys.map((key) => new Server({ hostKeys: [key] }, (client) => {
    client.on("authentication", (context) => context.reject());
    client.on("error", () => {});
  }));
  const front = net.createServer((socket) => {
    servers[turn % servers.length].injectSocket(socket);
    turn += 1;
  });
  t.after(() => front.close());
  return new Promise((resolve) => front.listen(0, "127.0.0.1", () => resolve(front.address().port)));
}

const newHostKey = () => utils.generateKeyPairSync("ed25519").private;
const sha256 = (key) => crypto.createHash("sha256").update(utils.parseKey(key).getPublicSSH()).digest("hex");

test("a changed key reached through another spelling of the host is shown as changed", async (t) => {
  const trusted = newHostKey();
  const port = await keyRotatingServer(t, [newHostKey()]);
  const knownHosts = new KnownHosts(path.join(scratch(t, "kh-case"), "known-hosts.json"));
  knownHosts.remember(`localhost:${port}`, sha256(trusted));
  const asked = [];
  const manager = new SshManager({ knownHosts, confirmHost: async (request) => { asked.push(request); return { accept: false, remember: false }; } });
  await manager.connect({ host: "LOCALHOST.", port, username: "fixture-user", authType: "password", password: "unused" }).catch(() => undefined);
  assert.equal(asked.length, 1);
  assert.notEqual(asked[0].previousFingerprint, null, "the warning, not a first-use prompt");
  assert.equal(asked[0].identity, `localhost:${port}`);
});

test("two first-use prompts for one host are asked in turn, the second as a changed key", async (t) => {
  const first = newHostKey();
  const second = newHostKey();
  const port = await keyRotatingServer(t, [first, second]);
  const knownHosts = new KnownHosts(path.join(scratch(t, "kh-race"), "known-hosts.json"));
  const prompts = [];
  let open = 0;
  let mostOpen = 0;
  const confirmHost = (request) => new Promise((resolve) => {
    open += 1;
    mostOpen = Math.max(mostOpen, open);
    prompts.push(request);
    setTimeout(() => { open -= 1; resolve({ accept: true, remember: prompts.length === 1 }); }, 300);
  });
  const config = { host: "127.0.0.1", port, username: "fixture-user", authType: "password", password: "unused" };
  const a = new SshManager({ knownHosts, confirmHost });
  const b = new SshManager({ knownHosts, confirmHost });
  const one = a.connect(config).catch(() => undefined);
  await new Promise((resolve) => setTimeout(resolve, 100));
  await Promise.all([one, b.connect(config).catch(() => undefined)]);
  assert.equal(mostOpen, 1, "never two prompts for one host at once");
  assert.equal(prompts.length, 2);
  assert.equal(prompts[0].previousFingerprint, null);
  assert.notEqual(prompts[1].previousFingerprint, null, "the second sees what the first remembered");
  assert.equal(knownHosts.get(`127.0.0.1:${port}`).sha256, sha256(first));
});

/* --------------------------------------------- connecting: transport 10, 13, 14 */

async function testServer(t, options = {}) {
  const root = scratch(t, "remote");
  const server = await startTestServer({ root, ...options });
  t.after(() => server.close());
  return server;
}

test("the handshake limit waits while a host key is being read", async (t) => {
  const server = await testServer(t);
  const knownHostsPath = path.join(scratch(t, "kh-slow"), "known-hosts.json");
  const manager = new SshManager({
    knownHostsPath,
    confirmHost: () => new Promise((resolve) => setTimeout(() => resolve({ accept: true, remember: true }), 1500)),
  });
  manager.handshakeTimeout = 800;
  t.after(() => manager.disconnect());
  await manager.connect({ host: server.host, port: server.port, username: server.username, authType: "password", password: server.password });
  assert.ok(new KnownHosts(knownHostsPath).get(`${server.host}:${server.port}`));
});

test("a Trust given after the connection has failed is not remembered", async (t) => {
  const server = await testServer(t);
  const knownHostsPath = path.join(scratch(t, "kh-late"), "known-hosts.json");
  let signal = null;
  const manager = new SshManager({
    knownHostsPath,
    confirmHost: (request) => {
      signal = request.signal;
      // The host gives up while the person is still reading.
      setTimeout(() => server.dropClients(), 200);
      return new Promise((resolve) => setTimeout(() => resolve({ accept: true, remember: true }), 800));
    },
  });
  await assert.rejects(manager.connect({ host: server.host, port: server.port, username: server.username, authType: "password", password: server.password }));
  await new Promise((resolve) => setTimeout(resolve, 900));
  assert.equal(signal?.aborted, true, "the open prompt is told to close");
  assert.equal(fs.existsSync(knownHostsPath), false, "and its late answer changes nothing");
});

test("a wrong password is sent once per connect, not again over keyboard-interactive", async (t) => {
  const attempts = [];
  const server = new Server({ hostKeys: [newHostKey()] }, (client) => {
    client.on("authentication", (context) => {
      if (context.method === "password") {
        attempts.push(`password:${context.password}`);
        return context.reject(["password", "keyboard-interactive"]);
      }
      if (context.method === "keyboard-interactive") {
        return context.prompt([{ prompt: "Password: ", echo: false }], (answers) => {
          attempts.push(`keyboard-interactive:${answers[0]}`);
          context.reject(["password", "keyboard-interactive"]);
        });
      }
      return context.reject(["password", "keyboard-interactive"]);
    });
    client.on("error", () => {});
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const manager = new SshManager({
    knownHostsPath: path.join(scratch(t, "kh-pw"), "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  await assert.rejects(manager.connect({ host: "127.0.0.1", port: server.address().port, username: "fixture-user", authType: "password", password: "stale-pass" }));
  assert.deepEqual(attempts, ["password:stale-pass"]);
});

test("a connect overtaken by another closes what it opened", async (t) => {
  const server = await testServer(t, { authDelay: 600 });
  const manager = new SshManager({
    knownHostsPath: path.join(scratch(t, "kh-twice"), "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  const input = { host: server.host, port: server.port, username: server.username, authType: "password", password: server.password };
  const first = manager.connect(input).then(() => "ok", (error) => error.message);
  await new Promise((resolve) => setTimeout(resolve, 150));
  const second = manager.connect(input).then(() => "ok", (error) => error.message);
  assert.match(await first, /newer connection/);
  assert.equal(await second, "ok");
  assert.equal(manager.connected, true, "the newer one is the one in use");
  await manager.disconnect();
  await new Promise((resolve) => setTimeout(resolve, 500));
  assert.equal(server.clientCount(), 0, "and nothing is left open");
});

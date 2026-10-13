"use strict";

// The shell-and-scp transport, exercised through the same manager the interface
// uses, against a server whose SFTP subsystem is refused — the configuration the
// fallback exists for.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { SshManager } = require("../lib/ssh-manager");
const { startTestServer } = require("./helpers/ssh-test-server");

function temporaryDirectory(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `ssh-workbench-${label}-`));
}

async function withScpSession(run, { protocol = "sftp-scp", ...serverOptions } = {}) {
  const remoteRoot = temporaryDirectory("remote-scp");
  const localRoot = temporaryDirectory("local-scp");
  const server = await startTestServer({ root: remoteRoot, refuseSftp: true, ...serverOptions });
  const manager = new SshManager({
    knownHostsPath: path.join(localRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  try {
    const connection = await manager.connect({
      host: server.host,
      port: server.port,
      username: server.username,
      authType: "password",
      password: server.password,
      protocol,
    });
    await run({ manager, server, connection, remoteRoot, localRoot });
  } finally {
    await manager.disconnect();
    await server.close();
    fs.rmSync(remoteRoot, { recursive: true, force: true });
    fs.rmSync(localRoot, { recursive: true, force: true });
  }
}

test("falls back to SCP when the host refuses the SFTP subsystem", async () => {
  await withScpSession(async ({ connection, remoteRoot }) => {
    assert.equal(connection.protocol, "scp");
    assert.equal(connection.requestedProtocol, "sftp-scp");
    assert.ok(connection.sftpUnavailable, "the reason SFTP could not be used is reported");
    assert.equal(connection.home, remoteRoot, "the shell's working directory is the starting folder");
  });
});

test("SFTP only does not silently fall back", async () => {
  const remoteRoot = temporaryDirectory("remote-strict");
  const localRoot = temporaryDirectory("local-strict");
  const server = await startTestServer({ root: remoteRoot, refuseSftp: true });
  const manager = new SshManager({
    knownHostsPath: path.join(localRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  try {
    await assert.rejects(
      () => manager.connect({
        host: server.host,
        port: server.port,
        username: server.username,
        authType: "password",
        password: server.password,
        protocol: "sftp",
      }),
      /SFTP is unavailable/,
    );
    assert.equal(manager.connected, false);
  } finally {
    await manager.disconnect();
    await server.close();
    fs.rmSync(remoteRoot, { recursive: true, force: true });
    fs.rmSync(localRoot, { recursive: true, force: true });
  }
});

test("a host without scp says so instead of connecting to a half-working session", async () => {
  const remoteRoot = temporaryDirectory("remote-noscp");
  const localRoot = temporaryDirectory("local-noscp");
  const server = await startTestServer({ root: remoteRoot, refuseSftp: true, scp: false });
  const manager = new SshManager({
    knownHostsPath: path.join(localRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  try {
    await assert.rejects(
      () => manager.connect({
        host: server.host,
        port: server.port,
        username: server.username,
        authType: "password",
        password: server.password,
      }),
      /scp is not installed/,
    );
  } finally {
    await manager.disconnect();
    await server.close();
    fs.rmSync(remoteRoot, { recursive: true, force: true });
    fs.rmSync(localRoot, { recursive: true, force: true });
  }
});

test("lists a folder from ls output, folders first, with sizes, modes and links", async () => {
  await withScpSession(async ({ manager, remoteRoot }) => {
    fs.mkdirSync(path.join(remoteRoot, "folder"));
    fs.writeFileSync(path.join(remoteRoot, "notes.txt"), "twelve bytes");
    fs.writeFileSync(path.join(remoteRoot, "small.bin"), Buffer.alloc(3));
    fs.symlinkSync(path.join(remoteRoot, "notes.txt"), path.join(remoteRoot, "shortcut"));

    const listing = await manager.list(remoteRoot);
    assert.equal(listing.path, remoteRoot);
    const names = listing.entries.map((entry) => entry.name);
    assert.deepEqual(names, ["folder", "notes.txt", "shortcut", "small.bin"]);

    const folder = listing.entries[0];
    assert.equal(folder.directory, true);
    assert.match(folder.mode, /^drwx/);

    const notes = listing.entries.find((entry) => entry.name === "notes.txt");
    assert.equal(notes.size, 12);
    assert.equal(notes.directory, false);
    assert.ok(notes.modified, "a modified time is parsed from the listing");

    const link = listing.entries.find((entry) => entry.name === "shortcut");
    assert.equal(link.symlink, true, "the link target is not treated as part of the name");
  });
});

test("hidden files are listed and the dot entries are not", async () => {
  await withScpSession(async ({ manager, remoteRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, ".hidden"), "x");
    const names = (await manager.list(remoteRoot)).entries.map((entry) => entry.name);
    assert.deepEqual(names, [".hidden"]);
  });
});

test("uploads and downloads with scp, including a name with a space", async () => {
  await withScpSession(async ({ manager, remoteRoot, localRoot }) => {
    const contents = Buffer.from("scp carries the bytes unchanged\n".repeat(400));
    const source = path.join(localRoot, "my report.txt");
    fs.writeFileSync(source, contents);

    const { uploaded } = await manager.upload([source], remoteRoot);
    assert.deepEqual(uploaded, [path.posix.join(remoteRoot, "my report.txt")]);
    assert.deepEqual(fs.readFileSync(path.join(remoteRoot, "my report.txt")), contents);

    const destination = temporaryDirectory("download");
    try {
      const [returned] = await manager.download([path.posix.join(remoteRoot, "my report.txt")], destination);
      assert.deepEqual(fs.readFileSync(returned), contents);
    } finally {
      fs.rmSync(destination, { recursive: true, force: true });
    }
  });
});

test("collisions are found and settled over scp as well", async () => {
  await withScpSession(async ({ manager, remoteRoot, localRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "my report.txt"), "remote");
    fs.writeFileSync(path.join(localRoot, "my report.txt"), "local");
    fs.writeFileSync(path.join(localRoot, "unclaimed.txt"), "local");

    const plan = await manager.planUpload([
      path.join(localRoot, "my report.txt"),
      path.join(localRoot, "unclaimed.txt"),
    ], remoteRoot);
    // A name that is not there has to read as absent rather than as an error: over
    // this transport a missing item is a nonzero `ls`, not a status code.
    assert.deepEqual(plan.collisions.map((item) => item.name), ["my report.txt"]);
    assert.equal(plan.collisions[0].remote.size, "remote".length);

    const report = await manager.upload([path.join(localRoot, "my report.txt")], remoteRoot,
      { "my report.txt": "keep-both" });
    assert.deepEqual(report.uploaded, [path.posix.join(remoteRoot, "my report_2.txt")]);
    assert.equal(fs.readFileSync(path.join(remoteRoot, "my report.txt"), "utf8"), "remote");
    assert.equal(fs.readFileSync(path.join(remoteRoot, "my report_2.txt"), "utf8"), "local");
  });
});

test("a quote in a filename is a filename, not shell syntax", async () => {
  await withScpSession(async ({ manager, remoteRoot, localRoot }) => {
    const awkward = "it's a \"test\" $(file).txt";
    const source = path.join(localRoot, awkward);
    fs.writeFileSync(source, "quoted safely");

    await manager.upload([source], remoteRoot);
    assert.equal(fs.readFileSync(path.join(remoteRoot, awkward), "utf8"), "quoted safely");

    const names = (await manager.list(remoteRoot)).entries.map((entry) => entry.name);
    assert.deepEqual(names, [awkward]);

    const renamed = await manager.rename(path.posix.join(remoteRoot, awkward), "calm name.txt");
    assert.equal(fs.existsSync(path.join(remoteRoot, "calm name.txt")), true);
    assert.equal(fs.existsSync(path.join(remoteRoot, awkward)), false, "the original name is gone, not merely hidden");
    assert.equal(renamed.path, path.posix.join(remoteRoot, "calm name.txt"));
  });
});

test("a line break in a name is refused rather than framed as a second header", async () => {
  await withScpSession(async ({ manager, remoteRoot, localRoot }) => {
    // The scp header is one line. A name carrying a line ending would be announced
    // as two records, and everything after the break would be read by the sink as a
    // header of its own -- so the name is refused before a byte goes out.
    const injected = "notes\nC0644 6 pwned";
    const source = path.join(localRoot, injected);
    fs.writeFileSync(source, "hello\n");

    await assert.rejects(
      () => manager.upload([source], remoteRoot),
      /its name contains a line break/,
    );
    assert.deepEqual(fs.readdirSync(remoteRoot), [], "nothing was written under either name");
  });
});

test("SCP will not create a name it could never list again", async () => {
  await withScpSession(async ({ manager, remoteRoot, localRoot }) => {
    // A folder is made with mkdir rather than announced in an scp header, so the
    // header check does not cover it. The listing is line-based either way: a name
    // with a line break in it comes back as a phantom entry that nothing can reach.
    const odd = "folder\nsecond-line";
    fs.mkdirSync(path.join(localRoot, odd));
    fs.writeFileSync(path.join(localRoot, odd, "inside.txt"), "inside\n");
    await assert.rejects(
      () => manager.upload([path.join(localRoot, odd)], remoteRoot),
      /cannot be created over SCP: its name contains a line break/,
    );
    assert.deepEqual(fs.readdirSync(remoteRoot), [], "and nothing was left behind on the way to failing");

    // Renaming into one is refused for the same reason.
    fs.writeFileSync(path.join(remoteRoot, "plain.txt"), "here\n");
    await assert.rejects(
      () => manager.rename(path.posix.join(remoteRoot, "plain.txt"), "renamed\nsecond-line"),
      /cannot be renamed to over SCP: its name contains a line break/,
    );
    assert.deepEqual(fs.readdirSync(remoteRoot), ["plain.txt"]);
  });
});

test("creates, renames and deletes folders and files over the shell", async () => {
  await withScpSession(async ({ manager, remoteRoot }) => {
    const created = await manager.mkdir(remoteRoot, "made here");
    assert.equal(fs.statSync(path.join(remoteRoot, "made here")).isDirectory(), true);

    fs.writeFileSync(path.join(created.path, "inside.txt"), "x");
    const result = await manager.delete([created.path]);
    assert.deepEqual(result, { deleted: 1, failures: [] });
    assert.equal(fs.existsSync(created.path), false, "the folder and what was in it are both gone");
  });
});

test("edits a text file: read, change, write back", async () => {
  await withScpSession(async ({ manager, remoteRoot }) => {
    const target = path.posix.join(remoteRoot, "config.ini");
    fs.writeFileSync(target, "mode=old\n");

    assert.equal(await manager.readFile(target), "mode=old\n");
    await manager.writeFile(target, "mode=new\n");
    assert.equal(fs.readFileSync(target, "utf8"), "mode=new\n");
    assert.equal(await manager.readFile(target), "mode=new\n");
  });
});

test("uploads a folder tree and downloads it back", async () => {
  await withScpSession(async ({ manager, remoteRoot, localRoot }) => {
    const tree = path.join(localRoot, "project");
    fs.mkdirSync(path.join(tree, "src"), { recursive: true });
    fs.writeFileSync(path.join(tree, "README.md"), "# project\n");
    fs.writeFileSync(path.join(tree, "src", "main.js"), "console.log(1);\n");

    await manager.upload([tree], remoteRoot);
    assert.equal(fs.readFileSync(path.join(remoteRoot, "project", "src", "main.js"), "utf8"), "console.log(1);\n");

    const destination = temporaryDirectory("tree");
    try {
      await manager.download([path.posix.join(remoteRoot, "project")], destination);
      assert.equal(fs.readFileSync(path.join(destination, "project", "README.md"), "utf8"), "# project\n");
      assert.equal(fs.readFileSync(path.join(destination, "project", "src", "main.js"), "utf8"), "console.log(1);\n");
    } finally {
      fs.rmSync(destination, { recursive: true, force: true });
    }
  });
});

test("search walks the tree over ls, within the channels a host allows", async () => {
  await withScpSession(async ({ manager, server, remoteRoot }) => {
    for (const name of ["one", "two", "three"]) {
      fs.mkdirSync(path.join(remoteRoot, name));
      fs.writeFileSync(path.join(remoteRoot, name, `${name}-target.log`), "x");
      fs.writeFileSync(path.join(remoteRoot, name, "other.txt"), "x");
    }
    const result = await manager.search(remoteRoot, "target");
    const found = result.entries.map((entry) => entry.name).sort();
    assert.deepEqual(found, ["one-target.log", "three-target.log", "two-target.log"]);
    assert.equal(result.truncated, false);
    assert.ok(server.commands().some((command) => command.includes("ls -lAn")), "listings came from ls");
  });
});

test("a host whose ls has no --time-style is still listed", async () => {
  await withScpSession(async ({ manager, remoteRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "plain.txt"), "seven!!");
    const [entry] = (await manager.list(remoteRoot)).entries;
    assert.equal(entry.name, "plain.txt");
    assert.equal(entry.size, 7);
    assert.equal(entry.directory, false);
  }, { timeStyle: false });
});

test("SCP can be asked for outright, without waiting for SFTP to fail", async () => {
  const remoteRoot = temporaryDirectory("remote-direct");
  const localRoot = temporaryDirectory("local-direct");
  // A perfectly good SFTP server, which this session is not going to use.
  const server = await startTestServer({ root: remoteRoot });
  const manager = new SshManager({
    knownHostsPath: path.join(localRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  try {
    const connection = await manager.connect({
      host: server.host,
      port: server.port,
      username: server.username,
      authType: "password",
      password: server.password,
      protocol: "scp",
    });
    assert.equal(connection.protocol, "scp");
    assert.equal(connection.sftpUnavailable, null, "nothing failed; this is what was asked for");
    fs.writeFileSync(path.join(remoteRoot, "here.txt"), "x");
    assert.deepEqual((await manager.list(remoteRoot)).entries.map((entry) => entry.name), ["here.txt"]);
  } finally {
    await manager.disconnect();
    await server.close();
    fs.rmSync(remoteRoot, { recursive: true, force: true });
    fs.rmSync(localRoot, { recursive: true, force: true });
  }
});

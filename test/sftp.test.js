"use strict";

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

async function withSession(run) {
  const remoteRoot = temporaryDirectory("remote");
  const localRoot = temporaryDirectory("local");
  const server = await startTestServer({ root: remoteRoot });
  const manager = new SshManager({
    knownHostsPath: path.join(localRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  try {
    await manager.connect({
      host: server.host,
      port: server.port,
      username: server.username,
      authType: "password",
      password: server.password,
    });
    await run({ manager, server, remoteRoot, localRoot });
  } finally {
    await manager.disconnect();
    await server.close();
    fs.rmSync(remoteRoot, { recursive: true, force: true });
    fs.rmSync(localRoot, { recursive: true, force: true });
  }
}

test("lists a remote directory with folders first", async () => {
  await withSession(async ({ manager, remoteRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "beta.txt"), "beta");
    fs.mkdirSync(path.join(remoteRoot, "alpha"));
    const listing = await manager.list(remoteRoot);
    assert.equal(listing.path, remoteRoot);
    assert.deepEqual(listing.entries.map((entry) => entry.name), ["alpha", "beta.txt"]);
    assert.equal(listing.entries[0].directory, true);
    assert.equal(listing.entries[1].size, 4);
    assert.match(listing.entries[1].mode, /^-rw/);
  });
});

test("resolves a symbolic link to a directory so it can be opened", async () => {
  await withSession(async ({ manager, remoteRoot }) => {
    fs.mkdirSync(path.join(remoteRoot, "real"));
    fs.writeFileSync(path.join(remoteRoot, "real", "inside.txt"), "inside");
    fs.symlinkSync(path.join(remoteRoot, "real"), path.join(remoteRoot, "shortcut"));
    const listing = await manager.list(remoteRoot);
    const shortcut = listing.entries.find((entry) => entry.name === "shortcut");
    assert.equal(shortcut.symlink, true);
    assert.equal(shortcut.directory, false, "readdir reports the link itself, not its target");
    const resolved = await manager.resolve(shortcut.path);
    assert.equal(resolved.directory, true, "resolve follows the link so the row can be opened");
    const opened = await manager.list(resolved.path);
    assert.deepEqual(opened.entries.map((entry) => entry.name), ["inside.txt"]);
  });
});

test("uploads a nested folder, spaces in names, and links without looping", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    const tree = path.join(localRoot, "project files");
    fs.mkdirSync(path.join(tree, "nested", "deeper"), { recursive: true });
    fs.writeFileSync(path.join(tree, "top level.txt"), "top");
    fs.writeFileSync(path.join(tree, "nested", "deeper", "deep.txt"), "deep");
    fs.symlinkSync(path.join(tree, "nested"), path.join(tree, "link-to-nested"));
    fs.symlinkSync(tree, path.join(tree, "nested", "loop"));

    const { uploaded } = await manager.upload([tree], remoteRoot);
    assert.deepEqual(uploaded, [path.posix.join(remoteRoot, "project files")]);
    const landed = path.join(remoteRoot, "project files");
    assert.equal(fs.readFileSync(path.join(landed, "top level.txt"), "utf8"), "top");
    assert.equal(fs.readFileSync(path.join(landed, "nested", "deeper", "deep.txt"), "utf8"), "deep");
    assert.equal(
      fs.readFileSync(path.join(landed, "link-to-nested", "deeper", "deep.txt"), "utf8"),
      "deep",
      "a linked directory is uploaded as a real directory",
    );
    assert.equal(fs.existsSync(path.join(landed, "nested", "loop", "nested", "loop")), false,
      "the link loop is visited once instead of recursing forever");
  });
});

test("uploads several dropped files into the shown folder", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    const first = path.join(localRoot, "one.txt");
    const second = path.join(localRoot, "two three.txt");
    fs.writeFileSync(first, "one");
    fs.writeFileSync(second, "two three");
    const target = path.join(remoteRoot, "inbox");
    fs.mkdirSync(target);
    const { uploaded } = await manager.upload([first, second], target);
    assert.equal(uploaded.length, 2);
    assert.equal(fs.readFileSync(path.join(target, "one.txt"), "utf8"), "one");
    assert.equal(fs.readFileSync(path.join(target, "two three.txt"), "utf8"), "two three");
  });
});

test("writes a pasted image under a generated name without overwriting", async () => {
  await withSession(async ({ manager, remoteRoot }) => {
    const png = Buffer.from("89504e470d0a1a0a", "hex");
    const first = await manager.writePastedImage(remoteRoot, png, "png");
    assert.match(first.name, /^pasted-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}\.png$/);
    assert.equal(first.bytes, png.length);
    assert.deepEqual(fs.readFileSync(first.path), png);

    // A second paste in the same second must not clobber the first.
    const second = await manager.writePastedImage(remoteRoot, Buffer.from("second"), "png");
    assert.notEqual(second.name, first.name);
    assert.equal(fs.readFileSync(first.path).length, png.length, "the first file is untouched");
    assert.equal(fs.readFileSync(second.path, "utf8"), "second");

    const jpeg = await manager.writePastedImage(remoteRoot, Buffer.from("jpeg"), "jpg");
    assert.match(jpeg.name, /\.jpg$/);
    assert.equal(path.posix.dirname(jpeg.path), remoteRoot);
  });
});

test("downloads files, folders, and linked folders as real local items", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    fs.mkdirSync(path.join(remoteRoot, "bundle", "inner"), { recursive: true });
    fs.writeFileSync(path.join(remoteRoot, "bundle", "inner", "file.txt"), "payload");
    fs.writeFileSync(path.join(remoteRoot, "single.txt"), "single");
    fs.symlinkSync(path.join(remoteRoot, "bundle"), path.join(remoteRoot, "bundle-link"));

    const destination = path.join(localRoot, "downloads");
    fs.mkdirSync(destination);
    const saved = await manager.download(
      [path.posix.join(remoteRoot, "bundle"), path.posix.join(remoteRoot, "single.txt"), path.posix.join(remoteRoot, "bundle-link")],
      destination,
    );
    assert.equal(saved.length, 3);
    assert.equal(fs.readFileSync(path.join(destination, "bundle", "inner", "file.txt"), "utf8"), "payload");
    assert.equal(fs.readFileSync(path.join(destination, "single.txt"), "utf8"), "single");
    assert.equal(fs.readFileSync(path.join(destination, "bundle-link", "inner", "file.txt"), "utf8"), "payload");
  });
});

test("reports what an upload would land on before anything is sent", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "report.txt"), "old remote");
    fs.mkdirSync(path.join(remoteRoot, "bundle"));
    fs.mkdirSync(path.join(remoteRoot, "clash"));
    fs.writeFileSync(path.join(remoteRoot, "fresh.txt"), "untouched");

    fs.writeFileSync(path.join(localRoot, "report.txt"), "new local copy");
    fs.mkdirSync(path.join(localRoot, "bundle"));
    fs.writeFileSync(path.join(localRoot, "clash"), "a file where a folder is");
    fs.writeFileSync(path.join(localRoot, "brand-new.txt"), "nothing in the way");

    const plan = await manager.planUpload([
      path.join(localRoot, "report.txt"),
      path.join(localRoot, "bundle"),
      path.join(localRoot, "clash"),
      path.join(localRoot, "brand-new.txt"),
    ], remoteRoot);

    assert.equal(plan.directory, remoteRoot);
    // Only the names already taken are reported, and nothing has been written.
    assert.deepEqual(plan.collisions.map((item) => item.name), ["report.txt", "bundle", "clash"]);
    assert.equal(fs.readFileSync(path.join(remoteRoot, "report.txt"), "utf8"), "old remote");

    const [file, folder, mismatch] = plan.collisions;
    assert.equal(file.directory, false);
    assert.equal(file.mismatch, false);
    assert.equal(file.remote.size, "old remote".length);
    assert.equal(file.local.size, "new local copy".length);
    assert.match(file.remote.modified, /^\d{4}-\d{2}-\d{2}T/);
    assert.equal(folder.directory, true);
    assert.equal(folder.remote.directory, true);
    assert.equal(folder.mismatch, false);
    assert.equal(mismatch.mismatch, true, "a file dropped onto a folder cannot be overwritten");
  });
});

test("overwrites, skips, or keeps both as the upload was told to", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    for (const name of ["replace.txt", "leave.txt", "both.txt"]) {
      fs.writeFileSync(path.join(remoteRoot, name), "remote");
      fs.writeFileSync(path.join(localRoot, name), `local ${name}`);
    }

    const report = await manager.upload(
      ["replace.txt", "leave.txt", "both.txt"].map((name) => path.join(localRoot, name)),
      remoteRoot,
      { "replace.txt": "overwrite", "leave.txt": "skip", "both.txt": "keep-both" },
    );

    assert.deepEqual(report.uploaded, [
      path.posix.join(remoteRoot, "replace.txt"),
      path.posix.join(remoteRoot, "both_2.txt"),
    ]);
    assert.deepEqual(report.skipped, [path.posix.join(remoteRoot, "leave.txt")]);
    assert.deepEqual(report.renamed, [{
      from: path.posix.join(remoteRoot, "both.txt"),
      to: path.posix.join(remoteRoot, "both_2.txt"),
    }]);

    assert.equal(fs.readFileSync(path.join(remoteRoot, "replace.txt"), "utf8"), "local replace.txt");
    assert.equal(fs.readFileSync(path.join(remoteRoot, "leave.txt"), "utf8"), "remote");
    assert.equal(fs.readFileSync(path.join(remoteRoot, "both.txt"), "utf8"), "remote");
    assert.equal(fs.readFileSync(path.join(remoteRoot, "both_2.txt"), "utf8"), "local both.txt");
  });
});

test("keeps counting up until a remote upload name is free", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    fs.writeFileSync(path.join(localRoot, "notes.txt"), "local");
    for (const name of ["notes.txt", "notes_2.txt", "notes_3.txt"]) {
      fs.writeFileSync(path.join(remoteRoot, name), "taken");
    }
    const report = await manager.upload([path.join(localRoot, "notes.txt")], remoteRoot,
      { "notes.txt": "keep-both" });
    assert.deepEqual(report.uploaded, [path.posix.join(remoteRoot, "notes_4.txt")]);
    assert.equal(fs.readFileSync(path.join(remoteRoot, "notes_4.txt"), "utf8"), "local");
  });
});

test("a skipped folder is left alone and a folder kept alongside lands beside it", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    for (const name of ["keep", "copy"]) {
      fs.mkdirSync(path.join(remoteRoot, name));
      fs.writeFileSync(path.join(remoteRoot, name, "existing.txt"), "remote");
      fs.mkdirSync(path.join(localRoot, name));
      fs.writeFileSync(path.join(localRoot, name, "added.txt"), "local");
    }

    const report = await manager.upload(
      [path.join(localRoot, "keep"), path.join(localRoot, "copy")],
      remoteRoot,
      { keep: "skip", copy: "keep-both" },
    );

    assert.deepEqual(report.uploaded, [path.posix.join(remoteRoot, "copy_2")]);
    assert.equal(fs.existsSync(path.join(remoteRoot, "keep", "added.txt")), false, "a skipped folder is not merged into");
    assert.equal(fs.readFileSync(path.join(remoteRoot, "copy_2", "added.txt"), "utf8"), "local");
    assert.equal(fs.existsSync(path.join(remoteRoot, "copy", "added.txt")), false);
  });
});

// A host that asks over keyboard-interactive rather than accepting the password
// method outright is ordinary. What is not ordinary is a host that keeps asking, and
// the password is only ever an answer to the first question.
test("the password answers one hidden prompt, and nothing that comes after it", async () => {
  const cases = [
    { name: "one hidden prompt is a password prompt",
      rounds: [[{ prompt: "Password: ", echo: false }]], answered: [["secret"]], connects: true },
    { name: "a second round gets nothing, whatever it asks",
      rounds: [[{ prompt: "Password: ", echo: false }], [{ prompt: "Verification code: ", echo: false }]],
      answered: [["secret"], [""]], connects: false },
    { name: "two prompts at once are not a password prompt",
      rounds: [[{ prompt: "Password: ", echo: false }, { prompt: "Token: ", echo: false }]],
      answered: [["", ""]], connects: false },
    { name: "a prompt that echoes is asking for something that is not a secret",
      rounds: [[{ prompt: "Which realm? ", echo: true }]], answered: [[""]], connects: false },
  ];
  for (const { name, rounds, answered, connects } of cases) {
    const remoteRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-workbench-ki-"));
    const server = await startTestServer({ root: remoteRoot, keyboardInteractive: rounds });
    const manager = new SshManager({
      knownHostsPath: path.join(remoteRoot, "known-hosts.json"),
      confirmHost: async () => ({ accept: true, remember: false }),
    });
    try {
      const attempt = manager.connect({
        host: server.host, port: server.port, username: server.username,
        authType: "password", password: server.password,
      });
      if (connects) await attempt;
      else await assert.rejects(() => attempt, undefined, `${name}: must not get in`);
      assert.deepEqual(server.keyboardAnswers(), answered, name);
    } finally {
      await manager.disconnect();
      await server.close();
      fs.rmSync(remoteRoot, { recursive: true, force: true });
    }
  }
});

test("two dropped items sharing a name are put to the caller, not silently merged", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    fs.mkdirSync(path.join(localRoot, "a"));
    fs.mkdirSync(path.join(localRoot, "b"));
    fs.writeFileSync(path.join(localRoot, "a", "report.txt"), "from a");
    fs.writeFileSync(path.join(localRoot, "b", "report.txt"), "from b");
    const sources = [path.join(localRoot, "a", "report.txt"), path.join(localRoot, "b", "report.txt")];

    // Nothing is in the way of the first write, so probing the host alone would see
    // no clash at all and the second copy would quietly replace the first.
    const plan = await manager.planUpload(sources, remoteRoot);
    assert.equal(plan.collisions.length, 1, "the shared name is reported once, not once per copy");
    assert.equal(plan.collisions[0].name, "report.txt");
    assert.equal(plan.collisions[0].remote, null, "there is nothing on the host to describe");
    assert.equal(plan.collisions[0].duplicates, 2);

    const kept = await manager.upload(sources, remoteRoot, { "report.txt": "keep-both" });
    assert.deepEqual(kept.uploaded, [
      path.posix.join(remoteRoot, "report.txt"),
      path.posix.join(remoteRoot, "report_2.txt"),
    ]);
    assert.equal(fs.readFileSync(path.join(remoteRoot, "report.txt"), "utf8"), "from a");
    assert.equal(fs.readFileSync(path.join(remoteRoot, "report_2.txt"), "utf8"), "from b");
  });
});

test("the answer for a shared name covers every copy of it", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    for (const folder of ["a", "b"]) {
      fs.mkdirSync(path.join(localRoot, folder));
      fs.writeFileSync(path.join(localRoot, folder, "report.txt"), `from ${folder}`);
    }
    const sources = ["a", "b"].map((folder) => path.join(localRoot, folder, "report.txt"));

    const first = await manager.upload(sources, remoteRoot, { "report.txt": "skip" });
    assert.deepEqual(first.uploaded, [path.posix.join(remoteRoot, "report.txt")]);
    assert.deepEqual(first.skipped, [path.posix.join(remoteRoot, "report.txt")]);
    assert.equal(fs.readFileSync(path.join(remoteRoot, "report.txt"), "utf8"), "from a",
      "keeping the first means the second does not land on it");

    fs.rmSync(path.join(remoteRoot, "report.txt"));
    const last = await manager.upload(sources, remoteRoot, { "report.txt": "overwrite" });
    assert.equal(fs.readFileSync(path.join(remoteRoot, "report.txt"), "utf8"), "from b",
      "keeping the last is the answer that replaces");
  });
});

test("two dropped items sharing a name but not a kind cannot be told to overwrite", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    // Nothing on the host: the clash is entirely between the two dropped items, and
    // one of them is a file where the other is a folder.
    fs.mkdirSync(path.join(localRoot, "a"));
    fs.mkdirSync(path.join(localRoot, "b"));
    fs.writeFileSync(path.join(localRoot, "a", "logs"), "i am a file");
    fs.mkdirSync(path.join(localRoot, "b", "logs"));
    fs.writeFileSync(path.join(localRoot, "b", "logs", "inside.txt"), "i am inside");
    const sources = [path.join(localRoot, "a", "logs"), path.join(localRoot, "b", "logs")];

    const plan = await manager.planUpload(sources, remoteRoot);
    assert.equal(plan.collisions.length, 1);
    assert.equal(plan.collisions[0].duplicates, 2);
    assert.equal(plan.collisions[0].mixed, true, "the two are not the same kind");
    assert.equal(plan.collisions[0].mismatch, true,
      "which is what stops the dialog offering to overwrite, exactly as a kind clash with the host does");

    // Keeping both is what is left, and it works: whichever is written first is what
    // the other then lands beside.
    const kept = await manager.upload(sources, remoteRoot, { logs: "keep-both" });
    assert.deepEqual(kept.uploaded, [
      path.posix.join(remoteRoot, "logs"),
      path.posix.join(remoteRoot, "logs_2"),
    ]);
    assert.equal(fs.readFileSync(path.join(remoteRoot, "logs"), "utf8"), "i am a file");
    assert.equal(fs.readFileSync(path.join(remoteRoot, "logs_2", "inside.txt"), "utf8"), "i am inside");
  });
});

test("a folder that would land on a file says so, rather than passing on one word", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "logs"), "a file is here");
    fs.mkdirSync(path.join(localRoot, "logs"));
    fs.writeFileSync(path.join(localRoot, "logs", "inside.txt"), "inside");
    await assert.rejects(
      () => manager.upload([path.join(localRoot, "logs")], remoteRoot, { logs: "overwrite" }),
      /already there as a file, and a folder cannot replace it/,
    );
  });
});

test("a name that clashes with the host and with a second dropped item says both", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "report.txt"), "already here");
    for (const folder of ["a", "b"]) {
      fs.mkdirSync(path.join(localRoot, folder));
      fs.writeFileSync(path.join(localRoot, folder, "report.txt"), `from ${folder}`);
    }
    const sources = ["a", "b"].map((folder) => path.join(localRoot, folder, "report.txt"));
    const plan = await manager.planUpload(sources, remoteRoot);
    assert.equal(plan.collisions.length, 1);
    assert.equal(plan.collisions[0].duplicates, 2, "the shared name is still counted");
    assert.equal(plan.collisions[0].remote.size, "already here".length, "and the host copy is still described");

    const kept = await manager.upload(sources, remoteRoot, { "report.txt": "keep-both" });
    assert.deepEqual(kept.uploaded, [
      path.posix.join(remoteRoot, "report_2.txt"),
      path.posix.join(remoteRoot, "report_3.txt"),
    ]);
    assert.equal(fs.readFileSync(path.join(remoteRoot, "report.txt"), "utf8"), "already here");
  });
});

test("an unknown upload choice is refused rather than read as an overwrite", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "report.txt"), "remote");
    fs.writeFileSync(path.join(localRoot, "report.txt"), "local");
    await assert.rejects(
      () => manager.upload([path.join(localRoot, "report.txt")], remoteRoot, { "report.txt": "replace" }),
      /Unknown upload choice/,
    );
    assert.equal(fs.readFileSync(path.join(remoteRoot, "report.txt"), "utf8"), "remote");
  });
});

test("keeps both local copies when a download name already exists", async () => {
  await withSession(async ({ manager, remoteRoot, localRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "report.txt"), "remote");
    const destination = path.join(localRoot, "downloads");
    fs.mkdirSync(destination);
    fs.writeFileSync(path.join(destination, "report.txt"), "existing");
    const [saved] = await manager.download([path.posix.join(remoteRoot, "report.txt")], destination);
    assert.equal(path.basename(saved), "report_2.txt");
    assert.equal(fs.readFileSync(path.join(destination, "report.txt"), "utf8"), "existing");
    assert.equal(fs.readFileSync(saved, "utf8"), "remote");
  });
});

test("edits, creates, renames, and recursively deletes remote items", async () => {
  await withSession(async ({ manager, remoteRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "notes.txt"), "first line\n");
    assert.equal((await manager.readFile(path.posix.join(remoteRoot, "notes.txt"))).text, "first line\n");
    await manager.writeFile(path.posix.join(remoteRoot, "notes.txt"), "second line\n");
    assert.equal(fs.readFileSync(path.join(remoteRoot, "notes.txt"), "utf8"), "second line\n");

    const made = await manager.mkdir(remoteRoot, "new folder");
    assert.equal(fs.statSync(made.path).isDirectory(), true);
    const renamed = await manager.rename(made.path, "renamed folder");
    assert.equal(path.basename(renamed.path), "renamed folder");

    fs.mkdirSync(path.join(remoteRoot, "renamed folder", "child"), { recursive: true });
    fs.writeFileSync(path.join(remoteRoot, "renamed folder", "child", "leaf.txt"), "leaf");
    const removal = await manager.delete([renamed.path, path.posix.join(remoteRoot, "notes.txt")]);
    assert.deepEqual(removal, { deleted: 2, failures: [] });
    assert.equal(fs.existsSync(renamed.path), false);
  });
});

test("reports failures per item instead of aborting a deletion batch", async () => {
  await withSession(async ({ manager, remoteRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "present.txt"), "here");
    const result = await manager.delete([
      path.posix.join(remoteRoot, "missing.txt"),
      path.posix.join(remoteRoot, "present.txt"),
    ]);
    assert.equal(result.deleted, 1);
    assert.equal(result.failures.length, 1);
    assert.equal(fs.existsSync(path.join(remoteRoot, "present.txt")), false);
  });
});

test("searches names in the current folder and in subfolders", async () => {
  await withSession(async ({ manager, remoteRoot }) => {
    fs.mkdirSync(path.join(remoteRoot, "logs", "archive"), { recursive: true });
    fs.writeFileSync(path.join(remoteRoot, "report-top.txt"), "top");
    fs.writeFileSync(path.join(remoteRoot, "logs", "report-mid.txt"), "mid");
    fs.writeFileSync(path.join(remoteRoot, "logs", "archive", "REPORT-deep.txt"), "deep");

    const shallow = await manager.search(remoteRoot, "report", false);
    assert.deepEqual(shallow.entries.map((entry) => entry.name), ["report-top.txt"]);

    const deep = await manager.search(remoteRoot, "report", true);
    assert.deepEqual(
      deep.entries.map((entry) => entry.name).sort(),
      ["REPORT-deep.txt", "report-mid.txt", "report-top.txt"],
      "search is case-insensitive and recursive",
    );
    const deepest = deep.entries.find((entry) => entry.name === "REPORT-deep.txt");
    assert.equal(deepest.location, "logs/archive");
    await assert.rejects(() => manager.search(remoteRoot, "   ", true), /Search text is empty/);
  });
});

test("searches by relative path, full path, and wildcard", async () => {
  await withSession(async ({ manager, remoteRoot }) => {
    fs.mkdirSync(path.join(remoteRoot, "logs", "archive"), { recursive: true });
    fs.mkdirSync(path.join(remoteRoot, "notes"), { recursive: true });
    fs.writeFileSync(path.join(remoteRoot, "logs", "archive", "app.log"), "a");
    fs.writeFileSync(path.join(remoteRoot, "logs", "app.log"), "b");
    fs.writeFileSync(path.join(remoteRoot, "notes", "app.log"), "c");
    fs.writeFileSync(path.join(remoteRoot, "notes", "app.txt"), "d");

    const byName = await manager.search(remoteRoot, "app.log", true);
    assert.equal(byName.scope, "name");
    assert.equal(byName.entries.length, 3, "a plain query matches the name anywhere in the tree");

    const byPath = await manager.search(remoteRoot, "logs/app.log", true);
    assert.equal(byPath.scope, "relative path");
    assert.deepEqual(byPath.entries.map((entry) => entry.location), ["logs"],
      "a query with a slash matches the path below the searched folder");

    const nested = await manager.search(remoteRoot, "archive/app", true);
    assert.deepEqual(nested.entries.map((entry) => entry.location), ["logs/archive"]);

    const byFullPath = await manager.search(remoteRoot, `${remoteRoot}/notes`, true);
    assert.equal(byFullPath.scope, "full path");
    assert.equal(byFullPath.entries.length, 3, "the notes folder and both files inside it");

    const wildcard = await manager.search(remoteRoot, "*.log", true);
    assert.equal(wildcard.wildcard, true);
    assert.equal(wildcard.entries.length, 3);
    assert.equal((await manager.search(remoteRoot, "app.?og", true)).entries.length, 3);
    assert.equal((await manager.search(remoteRoot, "notes/*.log", true)).entries.length, 1);
    assert.equal((await manager.search(remoteRoot, "*.log", false)).entries.length, 0,
      "a current-folder search does not descend");
  });
});

test("reports what a search could not cover", async () => {
  await withSession(async ({ manager, remoteRoot }) => {
    fs.mkdirSync(path.join(remoteRoot, "node_modules", "package"), { recursive: true });
    fs.writeFileSync(path.join(remoteRoot, "node_modules", "package", "target.txt"), "hidden");
    fs.mkdirSync(path.join(remoteRoot, ".git"));
    fs.writeFileSync(path.join(remoteRoot, ".git", "target.txt"), "hidden");
    fs.mkdirSync(path.join(remoteRoot, "locked"));
    fs.writeFileSync(path.join(remoteRoot, "locked", "target.txt"), "unreachable");
    fs.chmodSync(path.join(remoteRoot, "locked"), 0o000);
    fs.mkdirSync(path.join(remoteRoot, "open"));
    fs.writeFileSync(path.join(remoteRoot, "open", "target.txt"), "found");

    try {
      const result = await manager.search(remoteRoot, "target.txt", true);
      assert.deepEqual(result.entries.map((entry) => entry.location), ["open"]);
      assert.deepEqual(result.excluded, [".git", "node_modules"],
        "build and history folders are named rather than silently skipped");
      assert.equal(result.unreadable, 1, "a folder that cannot be read is counted");
      assert.ok(result.scanned >= 2, `scanned ${result.scanned} folders`);
      assert.equal(result.timedOut, false);
      assert.equal(result.truncated, false);
      assert.equal(result.unexplored, 0);
      assert.equal(result.limit, 500);
    } finally {
      fs.chmodSync(path.join(remoteRoot, "locked"), 0o700);
    }
  });
});

test("searches nearest folders first so a capped search stays useful", async () => {
  await withSession(async ({ manager, remoteRoot }) => {
    // One match beside the searched folder, one at the bottom of a deep chain.
    fs.writeFileSync(path.join(remoteRoot, "target-shallow.txt"), "near");
    let deep = remoteRoot;
    for (let level = 0; level < 12; level += 1) {
      deep = path.join(deep, `level-${level}`);
      fs.mkdirSync(deep);
    }
    fs.writeFileSync(path.join(deep, "target-deep.txt"), "far");

    // An explicit, generous deadline: what is being checked here is the order the
    // tree is walked in and that both matches are found, not how fast the machine
    // running the tests happens to be. With the production four seconds, a loaded
    // machine can time out partway down the chain and fail for no real reason.
    const result = await manager.search(remoteRoot, "target", true, { milliseconds: 60000 });
    assert.deepEqual(
      result.entries.map((entry) => entry.name),
      ["target-deep.txt", "target-shallow.txt"],
      "both are found when there is time; results are sorted by name",
    );
    assert.equal(result.entries.find((entry) => entry.name === "target-shallow.txt").location, ".");

    // With room for a single match, the near one has to be the one that survives.
    // A depth-first walk would return the file twelve levels down instead.
    const capped = await manager.search(remoteRoot, "target", true, { limit: 1 });
    assert.deepEqual(capped.entries.map((entry) => entry.name), ["target-shallow.txt"]);
    assert.equal(capped.truncated, true);
    assert.ok(capped.unexplored > 0, "the folders it never reached are counted");

    const expired = await manager.search(remoteRoot, "target", true, { milliseconds: 0 });
    assert.equal(expired.timedOut, true, "an exhausted deadline is reported, not hidden");
    assert.equal(expired.truncated, true);
    assert.equal(expired.entries.length, 0);
    assert.equal(expired.scanned, 0);
  });
});

test("refuses oversized and binary text edits", async () => {
  await withSession(async ({ manager, remoteRoot }) => {
    fs.writeFileSync(path.join(remoteRoot, "binary.bin"), Buffer.from([0x41, 0x00, 0x42]));
    await assert.rejects(
      () => manager.readFile(path.posix.join(remoteRoot, "binary.bin")),
      /Binary file cannot be edited as text/,
    );
    fs.writeFileSync(path.join(remoteRoot, "big.txt"), Buffer.alloc(64));
    await assert.rejects(
      () => manager.readFile(path.posix.join(remoteRoot, "big.txt"), 10),
      /too large/,
    );
  });
});

test("runs a remote shell and forwards input, output, and resize", async () => {
  await withSession(async ({ manager }) => {
    const chunks = [];
    manager.on("terminal-data", (data) => chunks.push(data));
    await manager.startTerminal({ columns: 100, rows: 30 });
    await new Promise((resolve) => setTimeout(resolve, 150));
    manager.terminalInput("echo hello\r");
    manager.terminalResize(120, 40);
    await new Promise((resolve) => setTimeout(resolve, 150));
    const output = chunks.join("");
    assert.match(output, /test-shell-ready/);
    assert.match(output, /echo hello/);
  });
});

test("rejects operations once the session is disconnected", async () => {
  const remoteRoot = temporaryDirectory("remote-closed");
  const server = await startTestServer({ root: remoteRoot });
  const manager = new SshManager({
    knownHostsPath: path.join(remoteRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  try {
    await manager.connect({
      host: server.host,
      port: server.port,
      username: server.username,
      authType: "password",
      password: server.password,
    });
    await manager.disconnect();
    assert.equal(manager.connected, false);
    await assert.rejects(() => manager.list(remoteRoot), /Not connected/);
    await assert.rejects(() => manager.upload([remoteRoot], remoteRoot), /Not connected/);
  } finally {
    await manager.disconnect();
    await server.close();
    fs.rmSync(remoteRoot, { recursive: true, force: true });
  }
});

test("declining the host fingerprint stops the connection", async () => {
  const remoteRoot = temporaryDirectory("remote-untrusted");
  const server = await startTestServer({ root: remoteRoot });
  const manager = new SshManager({
    knownHostsPath: path.join(remoteRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: false, remember: false }),
  });
  try {
    await assert.rejects(() => manager.connect({
      host: server.host,
      port: server.port,
      username: server.username,
      authType: "password",
      password: server.password,
    }), /Destination host/);
    assert.equal(manager.connected, false);
  } finally {
    await manager.disconnect();
    await server.close();
    fs.rmSync(remoteRoot, { recursive: true, force: true });
  }
});

test("keeps folder reads in flight so a slow link is not searched one folder at a time", async () => {
  const remoteRoot = temporaryDirectory("remote-latency");
  // 25 ms per directory listing: a plausible round trip to a machine a few
  // hundred kilometres away.
  const server = await startTestServer({ root: remoteRoot, latency: 25 });
  const manager = new SshManager({
    knownHostsPath: path.join(remoteRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  try {
    for (let index = 0; index < 36; index += 1) {
      const folder = path.join(remoteRoot, `folder-${String(index).padStart(2, "0")}`);
      fs.mkdirSync(folder);
      fs.writeFileSync(path.join(folder, index === 35 ? "target.txt" : "other.txt"), "x");
    }
    await manager.connect({
      host: server.host,
      port: server.port,
      username: server.username,
      authType: "password",
      password: server.password,
    });

    const serialStart = Date.now();
    const serial = await manager.search(remoteRoot, "target.txt", true, { concurrency: 1, milliseconds: 60_000 });
    const serialMilliseconds = Date.now() - serialStart;

    const pooledStart = Date.now();
    const pooled = await manager.search(remoteRoot, "target.txt", true, { milliseconds: 60_000 });
    const pooledMilliseconds = Date.now() - pooledStart;

    assert.equal(serial.entries.length, 1);
    assert.equal(pooled.entries.length, 1, "the same single match is found either way");
    assert.equal(pooled.scanned, serial.scanned, "and the same folders are covered");
    assert.ok(
      pooledMilliseconds * 2 < serialMilliseconds,
      `keeping reads in flight should be far quicker: ${pooledMilliseconds} ms pooled vs ${serialMilliseconds} ms serial`,
    );
  } finally {
    await manager.disconnect();
    await server.close();
    fs.rmSync(remoteRoot, { recursive: true, force: true });
  }
});

test("a disconnect during the handshake leaves no connection behind", async () => {
  const remoteRoot = temporaryDirectory("remote-abandoned");
  // The handshake is held open so the disconnect lands while it is still in flight,
  // which is what closing a window mid-connection does.
  const server = await startTestServer({ root: remoteRoot, authDelay: 400 });
  const manager = new SshManager({
    knownHostsPath: path.join(remoteRoot, "known-hosts.json"),
    confirmHost: async () => ({ accept: true, remember: false }),
  });
  try {
    const connecting = manager.connect({
      host: server.host,
      port: server.port,
      username: server.username,
      authType: "password",
      password: server.password,
    });
    // Far enough in to be past connect's own initial disconnect.
    await new Promise((resolve) => setTimeout(resolve, 120));
    await manager.disconnect();

    await assert.rejects(() => connecting, /closed before it finished opening|Not connected|closed during setup/);
    assert.equal(manager.connected, false, "no usable session is left behind");
    assert.equal(manager.connection, null);

    // And the server sees the connection go, rather than holding it open forever.
    const deadline = Date.now() + 5000;
    while (server.clientCount() > 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(server.clientCount(), 0, "the abandoned connection is closed, not leaked");
  } finally {
    await manager.disconnect();
    await server.close();
    fs.rmSync(remoteRoot, { recursive: true, force: true });
  }
});

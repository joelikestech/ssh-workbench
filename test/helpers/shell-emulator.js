"use strict";

// Enough of a POSIX shell to answer the exact command lines the SCP transport
// sends, backed by a real directory. It exists so the shell-and-scp path can be
// tested against the commands it actually emits — a listing this parses is a
// listing `ls` would have printed — without a remote machine or a real sshd.
//
// It is a test double: it understands the small grammar the transport uses
// (`;`, `&&`, `||`, /dev/null redirection, single-quoted words) and nothing more.

const fs = require("node:fs");
const path = require("node:path");
const { WRAPPER } = require("../../lib/shell-transport");

function tokenize(text) {
  const tokens = [];
  let current = "";
  let started = false;
  let index = 0;
  while (index < text.length) {
    const character = text[index];
    if (character === "'") {
      started = true;
      index += 1;
      while (index < text.length && text[index] !== "'") {
        current += text[index];
        index += 1;
      }
      index += 1;
      continue;
    }
    // Outside quotes a backslash escapes the next character. The transport writes a
    // literal quote inside a quoted word exactly as a shell requires — '\'' — and a
    // tokenizer that missed this would make its quoting look broken when it is not.
    if (character === "\\" && index + 1 < text.length) {
      started = true;
      current += text[index + 1];
      index += 2;
      continue;
    }
    if (/\s/.test(character)) {
      if (started) tokens.push(current);
      current = "";
      started = false;
      index += 1;
      continue;
    }
    started = true;
    current += character;
    index += 1;
  }
  if (started) tokens.push(current);
  return tokens;
}

// Splits a line into the pipeline pieces the transport builds, keeping the
// operator that joined them so the caller can honour && and ||.
function split(line) {
  const parts = [];
  let current = "";
  let quoted = false;
  let index = 0;
  const push = (operator) => {
    parts.push({ text: current.trim(), operator });
    current = "";
  };
  while (index < line.length) {
    const character = line[index];
    if (character === "'") quoted = !quoted;
    if (!quoted && line.startsWith("&&", index)) { push("&&"); index += 2; continue; }
    if (!quoted && line.startsWith("||", index)) { push("||"); index += 2; continue; }
    if (!quoted && character === ";") { push(";"); index += 1; continue; }
    current += character;
    index += 1;
  }
  push(null);
  return parts.filter((part) => part.text);
}

function stripRedirections(tokens) {
  const kept = [];
  let discardOutput = false;
  for (const token of tokens) {
    if (token === "2>&1" || token === "2>/dev/null") continue;
    if (token === ">/dev/null" || token === "1>/dev/null") { discardOutput = true; continue; }
    kept.push(token);
  }
  return { tokens: kept, discardOutput };
}

function permissions(stats) {
  const type = stats.isDirectory() ? "d" : stats.isSymbolicLink() ? "l" : stats.isFIFO() ? "p"
    : stats.isCharacterDevice() ? "c" : stats.isBlockDevice() ? "b" : stats.isSocket() ? "s" : "-";
  const bits = [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001];
  return type + bits.map((bit, position) => (stats.mode & bit ? "rwx"[position % 3] : "-")).join("");
}

function listingLine(name, stats, target) {
  const size = String(stats.size);
  const seconds = Math.floor(stats.mtimeMs / 1000);
  const shown = stats.isSymbolicLink() && target ? `${name} -> ${target}` : name;
  return `${permissions(stats)} 1 ${stats.uid} ${stats.gid} ${size.padStart(6)} ${seconds} ${shown}`;
}

class ShellEmulator {
  // `wrapper: false` is a login shell that runs only the commands it is named --
  // the restricted shells and ForceCommand wrappers that refuse `exec /bin/sh`.
  constructor(root, { scp = true, timeStyle = true, wrapper = true } = {}) {
    this.root = root;
    this.scp = scp;
    this.timeStyle = timeStyle;
    this.wrapper = wrapper;
  }

  resolve(value) {
    const target = String(value || ".");
    return path.isAbsolute(target) ? target : path.resolve(this.root, target);
  }

  // `scp -t` and `scp -f` are conversations rather than commands, so they are run
  // against the live channel; everything else produces text and an exit code.
  //
  // The transport sends its command lines to /bin/sh on standard input, behind a
  // fixed wrapper the login shell sees. That first line is read off here, exactly as
  // `read` would, and whatever followed it is handed on to the command it names.
  // `onCommand` hears every command line actually run, wrapped or not.
  run(commandLine, stream, onCommand = () => undefined) {
    if (commandLine === WRAPPER && this.wrapper) {
      let pending = Buffer.alloc(0);
      const take = (chunk) => {
        pending = Buffer.concat([pending, chunk]);
        const end = pending.indexOf(0x0a);
        if (end < 0) return;
        stream.removeListener("data", take);
        const rest = pending.subarray(end + 1);
        try {
          this.run(pending.subarray(0, end).toString("utf8"), stream, onCommand);
        } catch (error) {
          stream.stderr.write(`sh: ${error.message}\n`);
          stream.exit(1);
          stream.end();
          return;
        }
        if (rest.length) stream.emit("data", rest);
      };
      stream.on("data", take);
      return undefined;
    }
    onCommand(commandLine);
    const first = split(commandLine)[0];
    const opening = stripRedirections(tokenize(first.text)).tokens.filter((token) => !/^[A-Z_]+=/.test(token));
    if (opening[0] === "scp" && this.scp) {
      const flags = opening[1] || "";
      const target = opening[opening.length - 1];
      if (flags.includes("t")) return this.#sink(stream, this.resolve(target));
      if (flags.includes("f")) return this.#source(stream, this.resolve(target));
    }
    const { output, code } = this.#script(commandLine);
    if (output.stdout) stream.write(output.stdout);
    if (output.stderr) stream.stderr.write(output.stderr);
    stream.exit(code);
    stream.end();
    return undefined;
  }

  #script(commandLine) {
    const output = { stdout: "", stderr: "" };
    let code = 0;
    let skipUntilNext = false;
    for (const part of split(commandLine)) {
      if (!skipUntilNext) {
        const result = this.#one(part.text);
        code = result.code;
        if (!result.discardOutput) {
          output.stdout += result.stdout || "";
          output.stderr += result.stderr || "";
        }
      }
      // && runs the next piece only after a success, || only after a failure.
      if (part.operator === "&&") skipUntilNext = code !== 0;
      else if (part.operator === "||") skipUntilNext = code === 0;
      else skipUntilNext = false;
    }
    return { output, code };
  }

  #one(text) {
    const { tokens, discardOutput } = stripRedirections(tokenize(text));
    const words = tokens.filter((token) => !/^[A-Z_]+=/.test(token));
    const command = words[0];
    const rest = words.slice(1);
    const finish = (result) => ({ discardOutput, stdout: "", stderr: "", code: 0, ...result });
    try {
      switch (command) {
        case "pwd": return finish({ stdout: `${this.root}\n` });
        case "echo": return finish({ stdout: `${rest.join(" ")}\n` });
        case "printf": {
          const format = rest[0] || "";
          const value = rest[1] || "";
          return finish({ stdout: format.replace("%s", value).replace(/\\n/g, "\n") });
        }
        case "command": {
          if (rest[0] === "-v" && rest[1] === "scp") {
            return this.scp ? finish({ stdout: "/usr/bin/scp\n" }) : finish({ code: 1 });
          }
          return finish({ code: 1 });
        }
        case "test": {
          let operands = rest;
          const negate = operands[0] === "!";
          if (negate) operands = operands.slice(1);
          const [flag, operand] = operands;
          const target = this.resolve(operand);
          const link = fs.lstatSync(target, { throwIfNoEntry: false });
          const followed = fs.statSync(target, { throwIfNoEntry: false });
          const answers = { "-e": Boolean(followed), "-h": Boolean(link?.isSymbolicLink()), "-L": Boolean(link?.isSymbolicLink()), "-d": Boolean(followed?.isDirectory()) };
          if (!(flag in answers)) return finish({ stderr: `test: ${flag}: unknown operator\n`, code: 2 });
          return finish({ code: answers[flag] !== negate ? 0 : 1 });
        }
        case "chmod": {
          const [mode, target] = rest.filter((token) => token !== "--");
          fs.chmodSync(this.resolve(target), parseInt(mode, 8));
          return finish({});
        }
        case "chown": {
          const [owner, target] = rest.filter((token) => token !== "--");
          const [uid, gid] = owner.split(":").map(Number);
          fs.chownSync(this.resolve(target), uid, gid);
          return finish({});
        }
        case "readlink": {
          const target = this.resolve(rest[rest.length - 1]);
          return finish({ stdout: `${fs.realpathSync(target)}\n` });
        }
        case "ls": return finish(this.#ls(rest));
        case "mkdir": {
          fs.mkdirSync(this.resolve(rest[rest.length - 1]));
          return finish({});
        }
        case "rmdir": {
          fs.rmdirSync(this.resolve(rest[rest.length - 1]));
          return finish({});
        }
        case "rm": {
          const target = this.resolve(rest[rest.length - 1]);
          fs.rmSync(target, { force: rest.some((flag) => flag.includes("f")), recursive: rest.some((flag) => flag.includes("r")) });
          return finish({});
        }
        case "mv": {
          const [source, destination] = rest.filter((token) => token !== "--").slice(-2);
          fs.renameSync(this.resolve(source), this.resolve(destination));
          return finish({});
        }
        default:
          return finish({ stderr: `sh: ${command}: not found\n`, code: 127 });
      }
    } catch (error) {
      return finish({ stderr: `${command}: ${error.code === "ENOENT" ? "No such file or directory" : error.message}\n`, code: 1 });
    }
  }

  #ls(argv) {
    const flags = argv.filter((token) => token.startsWith("-") && token !== "--");
    const operands = [];
    let seenSeparator = false;
    for (const token of argv) {
      if (token === "--") { seenSeparator = true; continue; }
      if (!seenSeparator && token.startsWith("-")) continue;
      operands.push(token);
    }
    const asked = flags.join("");
    if (asked.includes("--time-style") && !this.timeStyle) {
      return { stderr: "ls: unrecognized option '--time-style'\n", code: 2 };
    }
    const epoch = asked.includes("--time-style") && this.timeStyle;
    const target = this.resolve(operands[0] || ".");
    const single = /(^|[^-])d/.test(asked.replace("--time-style=+%s", ""));
    const dereference = asked.includes("L");
    const stats = dereference ? fs.statSync(target) : fs.lstatSync(target);

    const format = (name, itemStats, linkTarget) => (epoch
      ? listingLine(name, itemStats, linkTarget)
      : listingLine(name, itemStats, linkTarget).replace(/ \d{9,} /, " Jan  1 00:00 "));

    if (single || !stats.isDirectory()) {
      const link = stats.isSymbolicLink() ? fs.readlinkSync(target) : null;
      return { stdout: `${format(target, stats, link)}\n` };
    }
    const lines = ["total 8"];
    for (const name of fs.readdirSync(target)) {
      const itemStats = fs.lstatSync(path.join(target, name));
      const link = itemStats.isSymbolicLink() ? fs.readlinkSync(path.join(target, name)) : null;
      lines.push(format(name, itemStats, link));
    }
    return { stdout: `${lines.join("\n")}\n` };
  }

  // Receives files, as `scp -t` does: acknowledge, read a header, take exactly the
  // bytes it announced, acknowledge again.
  #sink(stream, directory) {
    let buffer = Buffer.alloc(0);
    let state = { mode: "header", remaining: 0, target: null, chunks: [] };
    stream.write(Buffer.from([0]));
    stream.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      let progressing = true;
      while (progressing) {
        progressing = false;
        if (state.mode === "header") {
          const end = buffer.indexOf(0x0a);
          if (end < 0) break;
          const header = buffer.subarray(0, end).toString("utf8");
          buffer = buffer.subarray(end + 1);
          const match = /^C([0-7]{4})\s+(\d+)\s+(.*)$/.exec(header);
          if (!match) {
            stream.write(Buffer.from([2]));
            stream.write("scp: protocol error\n");
            stream.exit(1);
            stream.end();
            return;
          }
          const name = match[3];
          const destination = fs.existsSync(directory) && fs.statSync(directory).isDirectory()
            ? path.join(directory, name)
            : directory;
          state = { mode: "body", remaining: Number(match[2]), target: destination, chunks: [], mode_bits: parseInt(match[1], 8) };
          stream.write(Buffer.from([0]));
          progressing = true;
          continue;
        }
        if (state.mode === "body") {
          if (state.remaining > 0) {
            const take = buffer.subarray(0, Math.min(state.remaining, buffer.length));
            state.chunks.push(Buffer.from(take));
            buffer = buffer.subarray(take.length);
            state.remaining -= take.length;
          }
          if (state.remaining === 0) {
            if (!buffer.length) break;
            buffer = buffer.subarray(1);
            try {
              fs.writeFileSync(state.target, Buffer.concat(state.chunks), { mode: state.mode_bits & 0o777 });
              stream.write(Buffer.from([0]));
            } catch (error) {
              stream.write(Buffer.from([1]));
              stream.write(`scp: ${state.target}: ${error.message}\n`);
            }
            state = { mode: "header", remaining: 0, target: null, chunks: [] };
            progressing = true;
          }
        }
      }
    });
    stream.once("end", () => {
      stream.exit(0);
      stream.end();
    });
    return undefined;
  }

  // Sends one file, as `scp -f` does.
  #source(stream, target) {
    let stage = "start";
    stream.on("data", () => {
      if (stage === "start") {
        stage = "sent-header";
        let stats;
        try {
          stats = fs.statSync(target);
        } catch {
          stream.write(Buffer.from([1]));
          stream.write(`scp: ${target}: No such file or directory\n`);
          stream.exit(1);
          stream.end();
          return;
        }
        if (stats.isDirectory()) {
          stream.write(`D0755 0 ${path.basename(target)}\n`);
          return;
        }
        stream.write(`C0${(stats.mode & 0o777).toString(8)} ${stats.size} ${path.basename(target)}\n`);
        return;
      }
      if (stage === "sent-header") {
        stage = "sent-body";
        stream.write(fs.readFileSync(target));
        stream.write(Buffer.from([0]));
        return;
      }
      if (stage === "sent-body") {
        stage = "done";
        stream.exit(0);
        stream.end();
      }
    });
    return undefined;
  }
}

module.exports = { ShellEmulator, tokenize, split, permissions };

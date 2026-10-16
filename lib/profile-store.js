"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { writeFileAtomic, setAside } = require("./atomic-write");
const { normalizeProtocol } = require("./protocols");
const { sameHop } = require("./saved-credentials");
const { Vault } = require("./vault");

const AUTH_TYPES = new Set(["agent", "key", "password"]);
const STORE_VERSION = 2;

class ProfileStore {
  // Two ways of protecting a saved secret. "os" is the operating system keyring on
  // its own, as every version before this one used. "vault" is the keyring with a
  // master password over it, and is used for every secret once one is set.
  constructor({ filePath, encrypt, decrypt, canEncrypt, vault = null }) {
    this.filePath = filePath;
    this.encrypt = encrypt;
    this.decrypt = decrypt;
    this.canEncrypt = canEncrypt;
    this.vault = vault;
    this.profiles = [];
    this.vaultConfig = null;
    this.loadWarning = null;
    // Entries this build could not make sense of. They are written back exactly as
    // they were found rather than deleted by the first unrelated save; see #load.
    this.unrecognised = [];
    // Why the file on disk must not be written over, when it must not.
    this.readOnly = null;
    this.#load();
  }

  attachVault(vault) {
    this.vault = vault;
  }

  list() {
    return this.profiles
      .map(({ id, name, updatedAt, secret }) => ({
        id,
        name,
        updatedAt,
        credentialsSaved: Boolean(secret),
        // Whether using them asks for the master password. Once one is set every saved
        // credential does, including one that could not be re-encrypted under it yet.
        masterPassword: Boolean(secret) && (secret.scheme === "vault" || Boolean(this.vault?.configured)),
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  // What the form shows for a saved connection: everything except its secrets.
  // Choosing a connection from the list -- or having it chosen at startup, because it
  // was the last one used -- is not a decision to hand over a password, so nothing is
  // decrypted here at all. Decrypting would count as using the credential: it would
  // keep a timed unlock alive for as long as someone clicked through the list, and it
  // would put the password into a form field where it outlives a lock. Whether the
  // stored secrets can actually be read is found out when they are needed, by
  // `secrets`.
  get(id) {
    const profile = this.#find(id);
    return {
      id: profile.id,
      name: profile.name,
      updatedAt: profile.updatedAt,
      credentialsPresent: Boolean(profile.secret),
      credentialsSaved: Boolean(profile.secret),
      credentialError: null,
      // A locked vault is not an error and must not read like one: the credentials
      // are there, they just need the master password first.
      needsUnlock: Boolean(profile.secret) && this.#locked(),
      startPath: profile.startPath,
      connection: mergeSecrets(profile.connection, emptySecrets()),
    };
  }

  // The stored secrets of a connection, for the one moment they are wanted: a
  // connection is about to be opened with them. This is the only read that counts as
  // using a credential, so under "ask every time" it is what spends the unlock.
  //
  // Nothing is thrown for the expected cases, because an error crossing into the
  // window arrives as a bare message with nothing on it to act on: a locked vault
  // comes back as `needsUnlock`, and credentials that cannot be decrypted as
  // `credentialError`, with the connection's secret fields empty either way. Whether
  // something is stored, and whether it could be read, are reported separately. An
  // editor that conflates the two clears its own "save credentials" box for a
  // damaged connection, and then saving discards the very thing that might still be
  // recoverable -- without anyone having asked for it to go.
  secrets(id) {
    const profile = this.#find(id);
    const answer = (secrets, extra = {}) => ({
      id: profile.id,
      credentialsPresent: Boolean(profile.secret),
      needsUnlock: false,
      credentialError: null,
      ...extra,
      connection: mergeSecrets(profile.connection, secrets),
    });
    if (!profile.secret) return answer(emptySecrets());
    if (this.#locked()) return answer(emptySecrets(), { needsUnlock: true });
    let plaintext;
    let secrets;
    try {
      plaintext = this.#unprotect(profile.secret, { spend: false });
      secrets = normalizeSecrets(JSON.parse(plaintext));
    } catch (error) {
      return answer(emptySecrets(), error?.locked
        ? { needsUnlock: true, credentialError: "Saved credentials are locked. Enter the master password to use them." }
        : { credentialError: "Saved credentials could not be decrypted. Enter them again and save, and you will be asked whether to replace them." });
    }
    this.#upgrade(profile, plaintext);
    if (this.vault?.configured) this.vault.spend();
    return answer(secrets);
  }

  // With a master password set, a credential is expected to be behind it. One that is
  // not -- it was carried across under its old protection because the keyring could
  // not be reached when the master password was set or changed -- is moved behind
  // the current key the first time it is read with everything available. Failing to
  // is not worth failing the connection over; the old blob is still a good one.
  #upgrade(profile, plaintext) {
    if (!this.vault?.configured || !this.vault.unlocked) return;
    if (profile.secret.scheme === "vault" && !profile.secret.key) return;
    try {
      const secret = this.#protect(plaintext);
      const original = profile.secret;
      this.#commit((staged) => {
        const current = staged.profiles.find((candidate) => candidate.id === profile.id);
        if (current && current.secret === original) current.secret = secret;
      });
    } catch { /* left as it was */ }
  }

  #locked() {
    return Boolean(this.vault?.configured) && !this.vault.unlocked;
  }

  // Saving with credentials and saving without them are two different intentions,
  // and an empty password box means neither of them on its own. A connection whose
  // secrets are sitting in a locked vault comes back from `get` with nothing in
  // those fields, so re-saving it -- to change a port, or a start path -- arrives
  // here asking to keep credentials it cannot show. Writing `null` there would
  // destroy the stored password for good, silently, on the way to changing
  // something else entirely. Only being told plainly to stop saving credentials
  // does that.
  save(input) {
    const name = cleanText(input?.name, "Profile name", 80);
    const connection = normalizeConnection(input?.connection);
    const startPath = String(input?.startPath || "~").trim().slice(0, 4096) || "~";
    const secrets = extractSecrets(input?.connection);

    let movedHops = [];
    const id = this.#commit((staged) => {
      // A connection is the one it was loaded as, and nothing else. Finding it by
      // name instead would let a new connection typed into a blank form replace an
      // existing one that happened to share its name -- and inherit that one's saved
      // passwords, which would then go to whichever server the new one points at.
      const profile = input?.id
        ? staged.profiles.find((candidate) => candidate.id === String(input.id)) || null
        : null;
      // Two connections called "Prod" and "prod" cannot be told apart in the list, so
      // a second one is refused rather than quietly merged into the first.
      const folded = name.toLocaleLowerCase();
      const clash = staged.profiles.find((candidate) => candidate !== profile && candidate.name.toLocaleLowerCase() === folded);
      if (clash) {
        const error = new Error(`A saved connection named “${clash.name}” already exists. Choose another name, or choose “${clash.name}” in the list to change that one.`);
        error.duplicateName = true;
        throw error;
      }
      // Worked out before anything is added to the list, because it can fail -- a
      // locked vault, no keyring -- and a save that fails must leave the store as it
      // was rather than a nameless entry for the next one to trip over.
      const secret = input?.saveCredentials
        ? this.#secretFor(profile, secrets, connection, Boolean(input?.replaceCredentials))
        : null;
      // Reported only for a hop that was using a stored secret the last time it was
      // saved; a jump host edited while switched off had nothing to lose.
      movedHops = input?.saveCredentials && profile?.secret
        ? hopsMoved(profile.connection, connection).filter((hop) => (hop === "destination"
          ? profile.connection.authType !== "agent"
          : profile.connection.jump?.enabled && profile.connection.jump.authType !== "agent"))
        : [];
      const target = profile || { id: crypto.randomUUID() };
      if (!profile) staged.profiles.push(target);
      Object.assign(target, {
        name,
        updatedAt: new Date().toISOString(),
        startPath,
        connection,
        secret,
      });
      return target.id;
    });
    // Which servers had their stored secrets left behind, so the window can say so
    // rather than let a dropped password surface as a failed login later.
    return { ...this.list().find((candidate) => candidate.id === id), credentialsDropped: movedHops };
  }

  // What to store for a connection that is keeping its credentials. There are four
  // of them -- a password and a key passphrase, for the destination and for the jump
  // host -- and they are typed into four separate boxes that are blank whenever the
  // vault is locked, because reading them is the thing the master password is for.
  //
  // So an empty box means "leave this one alone" and never "forget it": forgetting
  // is what clearing the tick does, to all four at once. Changing one password must
  // not take the other three with it, which means merging field by field rather than
  // replacing the four as a block.
  //
  // With nothing typed at all there is nothing to merge, and the stored blob is
  // carried across untouched -- no decryption, so re-saving a connection to change
  // its port still works while the vault is locked.
  //
  // A saved secret belongs to the server it was saved for. A hop whose host, port or
  // user has been edited is a different server, and what was stored for the old one
  // is dropped rather than merged: an empty password box on a bastion that has just
  // been changed must not mean "keep sending the old bastion's password". The other
  // hop keeps its own.
  //
  // `replaceUnreadable` is the answer to the one case merging cannot serve: a stored
  // blob that cannot be decrypted at all, because the keyring has changed under it.
  // There is nothing in it to keep and no way to get it back, so refusing outright
  // would leave the connection unrepairable -- but replacing it is still a decision
  // someone has to make, because a keyring that is merely unavailable today may read
  // the same blob perfectly well tomorrow. The caller asks; this does not guess.
  #secretFor(profile, secrets, connection, replaceUnreadable = false) {
    const typed = Object.values(secrets).some(Boolean);
    const fresh = () => (typed ? this.#protect(JSON.stringify(secrets)) : null);
    if (!profile?.secret) return fresh();
    const moved = hopsMoved(profile.connection, connection);
    const targetMoved = moved.includes("destination");
    const jumpMoved = moved.includes("jump host");
    if (!typed && !targetMoved && !jumpMoved) return profile.secret;
    // Both servers changed: nothing that was stored applies to either, and there is
    // nothing to decrypt.
    if (targetMoved && jumpMoved) return fresh();

    let stored;
    try {
      stored = normalizeSecrets(JSON.parse(this.#unprotect(profile.secret, { spend: false })));
    } catch (error) {
      // Locked is not damaged: those credentials are readable by whoever knows the
      // master password, so this waits for it rather than offering to discard them.
      if (error?.locked) throw error;
      if (replaceUnreadable) return fresh();
      const unreadable = new Error("The saved credentials for this connection cannot be read, so they cannot be changed one at a time. They can be replaced with what you have entered, or discarded by saving without credentials.");
      // Marked so the caller can tell it apart from a refusal it can do nothing
      // about, and offer the replacement rather than repeating the problem.
      unreadable.unreadableCredentials = true;
      throw unreadable;
    }
    // A credential for an authentication type that is no longer selected is kept
    // rather than dropped. It is not in use, and switching back to it later should
    // not be a way to discover it is gone.
    const merged = { ...stored };
    if (targetMoved) Object.assign(merged, { password: "", passphrase: "" });
    if (jumpMoved) Object.assign(merged, { jumpPassword: "", jumpPassphrase: "" });
    for (const [field, value] of Object.entries(secrets)) if (value) merged[field] = value;
    if (!Object.values(merged).some(Boolean)) return null;
    return this.#protect(JSON.stringify(merged));
  }

  delete(id) {
    return this.#commit((staged) => {
      const index = staged.profiles.findIndex((profile) => profile.id === String(id));
      if (index < 0) throw new Error("Saved connection was not found");
      staged.profiles.splice(index, 1);
      return { ok: true };
    });
  }

  // Every change is written before it is believed. What is in memory is what the
  // interface reads back, so a change that could not reach the disk must not survive
  // in it -- an antivirus holding the file open across the rename is enough to fail
  // a write, and the next successful save would otherwise carry the rejected change
  // along with it, having reported that it did not happen.
  //
  // The change is made against copies, and they are installed only once the file is
  // on disk. Each profile is copied one level deep, which is as deep as anything
  // here reaches: every mutation replaces whole top-level fields.
  #commit(change) {
    const staged = {
      profiles: this.profiles.map((profile) => ({ ...profile })),
      vaultConfig: this.vaultConfig,
    };
    const result = change(staged);
    this.#write(staged);
    this.profiles = staged.profiles;
    this.vaultConfig = staged.vaultConfig;
    return result;
  }

  #find(id) {
    const profile = this.profiles.find((candidate) => candidate.id === String(id));
    if (!profile) throw new Error("Saved connection was not found");
    return profile;
  }

  // With a master password set, the keyring still wraps the outside: the vault
  // ciphertext is what the keyring protects, so both have to be defeated. Without
  // one, this is exactly what earlier versions stored.
  #protect(plaintext) {
    if (this.vault?.configured) {
      // The vault checks the policy and refuses while locked; saving a credential
      // needs the master password just as reading one does.
      const sealed = this.vault.wrap(plaintext);
      const keyring = this.canEncrypt();
      return {
        scheme: "vault",
        keyring,
        data: keyring ? this.encrypt(sealed).toString("base64") : sealed,
      };
    }
    if (!this.canEncrypt()) {
      throw new Error("Secure credential storage is unavailable. Set a master password, save without credentials, or enable your operating system keyring.");
    }
    return { scheme: "os", data: this.encrypt(plaintext).toString("base64") };
  }

  // `spend` says whether this counts as handing a credential over. Reading one to
  // give it to a connection does; reading one in order to write it straight back
  // does not, and under "ask every time" the difference is whether the write half of
  // a merge still has a key to work with.
  #unprotect(secret, { spend = true } = {}) {
    if (secret.scheme === "vault") {
      if (!this.vault?.configured) {
        throw new Error("These credentials were saved with a master password that is no longer set");
      }
      const sealed = this.#unsealKeyring(secret);
      let plaintext;
      if (secret.key) {
        // Sealed under an earlier master password's key, which travels with it
        // encrypted under the current one; see changeMasterPassword.
        const earlier = Buffer.from(this.vault.unwrapToRewrite(secret.key), "base64");
        try { plaintext = Vault.decrypt(earlier, sealed); } finally { earlier.fill(0); }
      } else {
        plaintext = this.vault.unwrapToRewrite(sealed);
      }
      if (spend) this.vault.spend();
      return plaintext;
    }
    return this.#openKeyring(secret);
  }

  // The vault ciphertext, with the keyring wrapped around the outside wherever the
  // platform has one. A key handed in explicitly is used during a password change,
  // when the vault has not adopted the new key yet.
  #sealVault(key, plaintext) {
    const sealed = Vault.encrypt(key, plaintext);
    const keyring = this.canEncrypt();
    return {
      scheme: "vault",
      keyring,
      data: keyring ? this.encrypt(sealed).toString("base64") : sealed,
    };
  }

  #openVault(key, secret) {
    const sealed = this.#unsealKeyring(secret);
    const inner = this.#sealingKey(key, secret);
    try { return Vault.decrypt(inner, sealed); } finally { if (inner !== key) inner.fill(0); }
  }

  // The key a vault secret was sealed with, given the key of the master password in
  // force: the same key, or -- for a secret carried across a password change without
  // being re-sealed -- the earlier key it names, unwrapped with this one.
  #sealingKey(key, secret) {
    return secret.key ? Buffer.from(Vault.decrypt(key, secret.key), "base64") : key;
  }

  #unsealKeyring(secret) {
    return secret.keyring ? this.decrypt(Buffer.from(secret.data, "base64")) : secret.data;
  }

  #openKeyring(secret) {
    return this.decrypt(Buffer.from(secret.data, "base64"));
  }

  // Setting, changing, or clearing the master password rewrites every stored
  // secret. Each is read and re-wrapped in memory first and the file is written
  // once, so an interruption cannot leave half the connections readable with the
  // old password and half with the new one.
  //
  // A secret that cannot be read right now is not thereby lost. The usual reason is
  // a keyring that is locked or missing for the moment -- on Linux a Secret Service
  // that has not started -- and the same blob reads perfectly well once it is back.
  // Such a secret is carried across under the protection it already has, wherever
  // that protection will still open it afterwards (`carry`). Where it would not, the
  // operation is refused and says which connections are in the way: discarding
  // someone's saved passwords is not a side effect a password change may have.
  #reprotect({ read, write, carry = () => null, vaultConfig }) {
    return this.#commit((staged) => {
      const replaced = new Map();
      const stuck = [];
      let rewrapped = 0;
      let carried = 0;
      for (const profile of staged.profiles) {
        if (!profile.secret) continue;
        let plaintext;
        try {
          plaintext = read(profile.secret);
        } catch {
          let kept = null;
          try { kept = carry(profile.secret); } catch { /* nothing to carry it with */ }
          if (kept) {
            replaced.set(profile, kept);
            carried += 1;
          } else {
            stuck.push(profile.name);
          }
          continue;
        }
        replaced.set(profile, write(plaintext));
        rewrapped += 1;
      }
      if (stuck.length) {
        const names = stuck.map((name) => `“${name}”`).join(", ");
        const error = new Error(`The saved credentials for ${names} cannot be read right now, and this would lose them. Nothing was changed. Try again once the operating system keyring is available, or save ${stuck.length === 1 ? "that connection" : "those connections"} without credentials first.`);
        error.unreadableProfiles = stuck;
        throw error;
      }
      staged.vaultConfig = vaultConfig || null;
      for (const [profile, secret] of replaced) profile.secret = secret;
      return { rewrapped, carried, dropped: 0 };
    });
  }

  // Credentials still under the keyring alone, because it could not be reached just
  // now, stay exactly as they are: the keyring opens them when it is back, using one
  // still asks for the master password, and the first use moves it behind it.
  applyMasterPassword({ key, config }) {
    return this.#reprotect({
      read: (secret) => {
        if (secret.scheme === "vault") throw new Error("A master password is already protecting these credentials");
        return this.#openKeyring(secret);
      },
      write: (plaintext) => this.#sealVault(key, plaintext),
      carry: (secret) => secret,
      vaultConfig: config,
    });
  }

  // A vault secret that cannot be unwrapped now -- the keyring around it is
  // unavailable -- is still sealed with the old key inside. The old key goes along
  // with it, encrypted under the new one, so the new password opens it as soon as the
  // keyring does; nothing weaker than the new password guards it. A secret that was
  // already carrying an earlier key has that one re-wrapped instead, so there is
  // never more than one step to undo.
  changeMasterPassword({ oldKey, newKey, config }) {
    return this.#reprotect({
      read: (secret) => (secret.scheme === "vault" ? this.#openVault(oldKey, secret) : this.#openKeyring(secret)),
      write: (plaintext) => this.#sealVault(newKey, plaintext),
      carry: (secret) => {
        if (secret.scheme !== "vault") return secret;
        const sealing = this.#sealingKey(oldKey, secret);
        try {
          return { ...secret, key: Vault.encrypt(newKey, sealing.toString("base64")) };
        } finally {
          if (sealing !== oldKey) sealing.fill(0);
        }
      },
      vaultConfig: config,
    });
  }

  // Where there is no keyring to hand the secrets back to, the only honest options
  // are to keep the master password or to forget the credentials. The caller says
  // which, and forgetting keeps the connections themselves. A vault secret that
  // cannot be opened has nothing to be carried with once the master password is
  // gone, so it stops the removal instead.
  clearMasterPassword({ key, discardCredentials = false }) {
    if (!this.canEncrypt() && !discardCredentials) {
      throw new Error("Removing the master password would leave the saved credentials unprotected, because the operating system keyring is unavailable.");
    }
    if (discardCredentials || !this.canEncrypt()) {
      return this.#reprotect({ read: () => "", write: () => null, vaultConfig: null });
    }
    return this.#reprotect({
      read: (secret) => (secret.scheme === "vault" ? this.#openVault(key, secret) : this.#openKeyring(secret)),
      write: (plaintext) => ({ scheme: "os", data: this.encrypt(plaintext).toString("base64") }),
      carry: (secret) => (secret.scheme === "vault" ? null : secret),
      vaultConfig: null,
    });
  }

  saveVaultConfig(config) {
    this.#commit((staged) => { staged.vaultConfig = config || null; });
  }

  #load() {
    let raw;
    try {
      raw = fs.readFileSync(this.filePath, "utf8");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      this.profiles = [];
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.profiles)) {
        throw new Error("not a saved-connections file");
      }
    } catch {
      // Keep the damaged file instead of overwriting it, and start with an empty
      // list so a corrupt store cannot stop the application from opening. A file
      // that parses but has no list of connections in it is no more usable than
      // one that does not parse, and is kept the same way. If no copy can be made,
      // nothing is written over the original either.
      this.profiles = [];
      const kept = setAside(this.filePath, "corrupt", { move: true });
      if (kept) {
        this.loadWarning = `Saved connections could not be read and were set aside as ${path.basename(kept)}.`;
      } else {
        this.readOnly = "Saved connections could not be read, and no copy of them could be made, so nothing is being saved until the file is moved or repaired.";
        this.loadWarning = this.readOnly;
      }
      return;
    }

    // A file from a later build may hold things this one does not understand, and
    // writing it back in this build's terms would lose them. It is used for what can
    // be read, and left alone.
    if (Number(parsed.version) > STORE_VERSION) {
      this.readOnly = "Saved connections were written by a newer version of SSH Workbench. They can be used here, but changes cannot be saved by this version.";
      this.loadWarning = this.readOnly;
    }

    // An entry that does not look like a connection this build can use -- a secret
    // scheme from a later version, a hand edit that left a field out -- is kept, not
    // deleted: it is written back exactly as found, so the first unrelated save
    // cannot take it with it, and a copy of the whole file is kept before anything
    // changes.
    const profiles = [];
    const unrecognised = [];
    for (const entry of parsed.profiles) {
      const migrated = migrateProfile(entry);
      if (validStoredProfile(migrated)) profiles.push(migrated);
      else unrecognised.push(entry);
    }
    this.profiles = profiles;
    this.unrecognised = unrecognised;
    this.vaultConfig = parsed.vault || null;
    if (unrecognised.length && !this.readOnly) {
      const kept = setAside(this.filePath, "unrecognised");
      const count = `${unrecognised.length} saved connection${unrecognised.length === 1 ? " was" : "s were"} not recognised by this version`;
      if (kept) {
        this.loadWarning = `${count}. ${unrecognised.length === 1 ? "It is" : "They are"} kept in the file unchanged, and a copy was saved as ${path.basename(kept)}.`;
      } else {
        this.readOnly = `${count}, and no copy of the file could be made, so nothing is being saved.`;
        this.loadWarning = this.readOnly;
      }
    }
  }

  #write({ profiles, vaultConfig }) {
    if (this.readOnly) throw new Error(this.readOnly);
    const contents = { version: STORE_VERSION, vault: vaultConfig, profiles: [...profiles, ...this.unrecognised] };
    writeFileAtomic(this.filePath, `${JSON.stringify(contents, null, 2)}\n`);
  }
}

// The hops whose server -- host, port or user -- is not the one a stored secret was
// saved for.
function hopsMoved(before, after) {
  const moved = [];
  if (!sameHop(before, after)) moved.push("destination");
  if (!sameHop(before?.jump, after?.jump)) moved.push("jump host");
  return moved;
}

function normalizeConnection(input) {
  const target = normalizeEndpoint(input, "Destination");
  const jumpInput = input?.jump || {};
  const jump = jumpInput.enabled
    ? { enabled: true, ...normalizeEndpoint(jumpInput, "Jump host") }
    : {
        enabled: false,
        host: String(jumpInput.host || "").trim().slice(0, 1024),
        port: normalizePort(jumpInput.port || 22, "Jump host"),
        username: String(jumpInput.username || "").trim().slice(0, 255),
        authType: normalizeAuth(jumpInput.authType || "agent", "Jump host"),
        keyPath: String(jumpInput.keyPath || "").slice(0, 4096),
      };
  // Saved before the protocol became a choice means SFTP with the SCP fallback,
  // which is how those connections have always behaved.
  return { ...target, protocol: normalizeProtocol(input?.protocol), jump };
}

function normalizeEndpoint(input, label) {
  return {
    host: cleanText(input?.host, `${label} host`, 1024),
    port: normalizePort(input?.port || 22, label),
    username: cleanText(input?.username, `${label} username`, 255),
    authType: normalizeAuth(input?.authType || "agent", label),
    keyPath: String(input?.keyPath || "").slice(0, 4096),
  };
}

function normalizePort(value, label) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`${label} SSH port is invalid`);
  return port;
}

function normalizeAuth(value, label) {
  const authType = String(value);
  if (!AUTH_TYPES.has(authType)) throw new Error(`${label} authentication type is invalid`);
  return authType;
}

function cleanText(value, label, limit) {
  const text = String(value || "").trim();
  if (!text) throw new Error(`${label} is required`);
  if (text.length > limit) throw new Error(`${label} is too long`);
  return text;
}

function extractSecrets(input) {
  const targetAuth = String(input?.authType || "agent");
  const jumpAuth = String(input?.jump?.authType || "agent");
  const jumpEnabled = Boolean(input?.jump?.enabled);
  return normalizeSecrets({
    password: targetAuth === "password" ? input?.password : "",
    passphrase: targetAuth === "key" ? input?.passphrase : "",
    jumpPassword: jumpEnabled && jumpAuth === "password" ? input?.jump?.password : "",
    jumpPassphrase: jumpEnabled && jumpAuth === "key" ? input?.jump?.passphrase : "",
  });
}

function normalizeSecrets(input) {
  return {
    password: String(input?.password || ""),
    passphrase: String(input?.passphrase || ""),
    jumpPassword: String(input?.jumpPassword || ""),
    jumpPassphrase: String(input?.jumpPassphrase || ""),
  };
}

function emptySecrets() {
  return normalizeSecrets({});
}

function mergeSecrets(connection, secrets) {
  return {
    ...connection,
    password: secrets.password,
    passphrase: secrets.passphrase,
    jump: {
      ...connection.jump,
      password: secrets.jumpPassword,
      passphrase: secrets.jumpPassphrase,
    },
  };
}

// Version 1 stored the keyring ciphertext as a bare string. It is read as what it
// was — a keyring-only secret — and written back in the tagged form the next time
// the connection is saved.
function migrateProfile(profile) {
  if (!profile || typeof profile !== "object") return profile;
  const migrated = { ...profile };
  if (typeof profile.secret === "string") {
    migrated.secret = { scheme: "os", data: profile.secret };
  }
  // The protocol arrived with the SCP fallback. A connection saved before it says
  // nothing on the subject, and what it has always done is try SFTP.
  if (migrated.connection && typeof migrated.connection === "object" && !migrated.connection.protocol) {
    migrated.connection = { ...migrated.connection, protocol: "sftp-scp" };
  }
  return migrated;
}

function validStoredProfile(profile) {
  return Boolean(
    profile && typeof profile.id === "string" && typeof profile.name === "string" &&
    profile.connection && typeof profile.connection === "object" &&
    typeof profile.startPath === "string" && validStoredSecret(profile.secret),
  );
}

function validStoredSecret(secret) {
  if (secret === null || secret === undefined) return true;
  return Boolean(
    typeof secret === "object" && typeof secret.data === "string" &&
    (secret.scheme === "os" || secret.scheme === "vault") &&
    (secret.key === undefined || (secret.scheme === "vault" && typeof secret.key === "string")),
  );
}

module.exports = { ProfileStore };

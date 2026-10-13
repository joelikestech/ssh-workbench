"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");

const { writeFileAtomic } = require("./atomic-write");
const { normalizeProtocol } = require("./protocols");
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
        masterPassword: secret?.scheme === "vault",
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  get(id) {
    const profile = this.#find(id);
    let secrets = emptySecrets();
    let credentialError = null;
    let needsUnlock = false;
    if (profile.secret) {
      // A locked vault is not an error and must not read like one: the credentials
      // are there, they just need the master password first.
      if (profile.secret.scheme === "vault" && !this.vault?.unlocked) {
        needsUnlock = true;
      } else {
        try {
          secrets = normalizeSecrets(JSON.parse(this.#unprotect(profile.secret)));
        } catch (error) {
          credentialError = error?.locked
            ? "Saved credentials are locked. Enter the master password to use them."
            : "Saved credentials could not be decrypted. Enter them again and save, and you will be asked whether to replace them.";
        }
      }
    }
    return {
      id: profile.id,
      name: profile.name,
      updatedAt: profile.updatedAt,
      // Whether something is stored, and separately whether it could be read. An
      // editor that conflates the two clears its own "save credentials" box for a
      // damaged connection, and then saving discards the very thing that might still
      // be recoverable -- without anyone having asked for it to go.
      credentialsPresent: Boolean(profile.secret),
      credentialsSaved: Boolean(profile.secret) && !credentialError,
      credentialError,
      needsUnlock,
      startPath: profile.startPath,
      connection: mergeSecrets(profile.connection, secrets),
    };
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

    const id = this.#commit((staged) => {
      let profile = null;
      if (input?.id) profile = staged.profiles.find((candidate) => candidate.id === String(input.id)) || null;
      if (!profile) {
        profile = staged.profiles.find((candidate) => candidate.name.toLocaleLowerCase() === name.toLocaleLowerCase()) || null;
      }
      // Worked out before anything is added to the list, because it can fail -- a
      // locked vault, no keyring -- and a save that fails must leave the store as it
      // was rather than a nameless entry for the next one to trip over.
      const secret = input?.saveCredentials
        ? this.#secretFor(profile, secrets, Boolean(input?.replaceCredentials))
        : null;
      if (!profile) {
        profile = { id: crypto.randomUUID() };
        staged.profiles.push(profile);
      }
      Object.assign(profile, {
        name,
        updatedAt: new Date().toISOString(),
        startPath,
        connection,
        secret,
      });
      return profile.id;
    });
    return this.list().find((candidate) => candidate.id === id);
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
  // `replaceUnreadable` is the answer to the one case merging cannot serve: a stored
  // blob that cannot be decrypted at all, because the keyring has changed under it.
  // There is nothing in it to keep and no way to get it back, so refusing outright
  // would leave the connection unrepairable -- but replacing it is still a decision
  // someone has to make, because a keyring that is merely unavailable today may read
  // the same blob perfectly well tomorrow. The caller asks; this does not guess.
  #secretFor(profile, secrets, replaceUnreadable = false) {
    const typed = Object.values(secrets).some(Boolean);
    if (!profile?.secret) return typed ? this.#protect(JSON.stringify(secrets)) : null;
    if (!typed) return profile.secret;

    let stored;
    try {
      stored = normalizeSecrets(JSON.parse(this.#unprotect(profile.secret, { spend: false })));
    } catch (error) {
      // Locked is not damaged: those credentials are readable by whoever knows the
      // master password, so this waits for it rather than offering to discard them.
      if (error?.locked) throw error;
      if (replaceUnreadable) return this.#protect(JSON.stringify(secrets));
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
    for (const [field, value] of Object.entries(secrets)) if (value) merged[field] = value;
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
      return spend ? this.vault.unwrap(sealed) : this.vault.unwrapToRewrite(sealed);
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
    return Vault.decrypt(key, this.#unsealKeyring(secret));
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
  #reprotect({ read, write, vaultConfig }) {
    return this.#commit((staged) => {
      const rewrapped = [];
      let dropped = 0;
      for (const profile of staged.profiles) {
        if (!profile.secret) continue;
        try {
          rewrapped.push({ profile, secret: write(read(profile.secret)) });
        } catch {
          // A secret that cannot be read — a keyring that has changed under it, say —
          // is already lost. Dropping it lets the other connections be re-wrapped
          // instead of failing the whole operation on one damaged entry.
          rewrapped.push({ profile, secret: null });
          dropped += 1;
        }
      }
      staged.vaultConfig = vaultConfig || null;
      for (const { profile, secret } of rewrapped) profile.secret = secret;
      return { rewrapped: rewrapped.length - dropped, dropped };
    });
  }

  applyMasterPassword({ key, config }) {
    return this.#reprotect({
      read: (secret) => {
        if (secret.scheme === "vault") throw new Error("A master password is already protecting these credentials");
        return this.#openKeyring(secret);
      },
      write: (plaintext) => this.#sealVault(key, plaintext),
      vaultConfig: config,
    });
  }

  changeMasterPassword({ oldKey, newKey, config }) {
    return this.#reprotect({
      read: (secret) => (secret.scheme === "vault" ? this.#openVault(oldKey, secret) : this.#openKeyring(secret)),
      write: (plaintext) => this.#sealVault(newKey, plaintext),
      vaultConfig: config,
    });
  }

  // Where there is no keyring to hand the secrets back to, the only honest options
  // are to keep the master password or to forget the credentials. The caller says
  // which, and forgetting keeps the connections themselves.
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
    try {
      const parsed = JSON.parse(raw);
      this.profiles = Array.isArray(parsed?.profiles)
        ? parsed.profiles.map(migrateProfile).filter(validStoredProfile)
        : [];
      this.vaultConfig = parsed?.vault || null;
    } catch {
      // Keep the damaged file instead of overwriting it, and start with an empty
      // list so a corrupt store cannot stop the application from opening.
      this.profiles = [];
      this.loadWarning = "Saved connections could not be read and were set aside as connections.json.corrupt.";
      try { fs.renameSync(this.filePath, `${this.filePath}.corrupt`); } catch { /* leave it in place */ }
    }
  }

  #write({ profiles, vaultConfig }) {
    const contents = { version: STORE_VERSION, vault: vaultConfig, profiles };
    writeFileAtomic(this.filePath, `${JSON.stringify(contents, null, 2)}\n`);
  }
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
    (secret.scheme === "os" || secret.scheme === "vault"),
  );
}

module.exports = { ProfileStore };

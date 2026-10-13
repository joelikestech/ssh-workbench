"use strict";

// A master password for saved credentials. The operating system keyring already
// protects them at rest; this adds the part a keyring cannot provide — that
// something has to be typed before a saved password is handed to a connection,
// and that the key does not sit in memory any longer than the policy allows.
//
// The password itself is never stored. A random salt and scrypt turn it into a
// key, and a verifier — a known token encrypted with that key — is what proves a
// typed password was the right one.

const crypto = require("node:crypto");

const VERIFIER_TOKEN = "ssh-workbench-vault-v1";
const KDF = { N: 1 << 16, r: 8, p: 1, keyLength: 32, maxmem: 128 * 1024 * 1024 };
const MIN_PASSWORD = 6;
const MAX_PASSWORD = 1024;
// Rate limiting, deliberately mild. Deriving a key already costs a few hundred
// milliseconds, which is most of the protection; this stops a script from spending
// all night on it without punishing someone who mistypes twice. It lives in memory
// only, so restarting the application clears it — a determined attacker with the
// file does not go through this code at all, they go through scrypt.
const FREE_ATTEMPTS = 4;
const COOLDOWN_STEP_SECONDS = 15;
const MAX_COOLDOWN_SECONDS = 60;
const MIN_MINUTES = 1;
const MAX_MINUTES = 1440;
const DEFAULT_MINUTES = 15;

function normalizePolicy(input) {
  const mode = input?.mode === "every" ? "every" : "minutes";
  const asked = Number(input?.minutes);
  const minutes = Number.isFinite(asked)
    ? Math.min(MAX_MINUTES, Math.max(MIN_MINUTES, Math.round(asked)))
    : DEFAULT_MINUTES;
  return { mode, minutes };
}

function derive(password, salt, kdf = KDF) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      Buffer.from(String(password), "utf8"),
      salt,
      kdf.keyLength || KDF.keyLength,
      { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: KDF.maxmem },
      (error, key) => (error ? reject(error) : resolve(key)),
    );
  });
}

function encryptWith(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64");
}

function decryptWith(key, blob) {
  const raw = Buffer.from(String(blob), "base64");
  if (raw.length < 29) throw new Error("The stored credential is not readable");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
  decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
}

class Vault {
  // `now` is injected so the re-prompt policy can be tested without waiting for a
  // clock, and because a test that sleeps for fifteen minutes is not a test.
  constructor({ config = null, now = () => Date.now() } = {}) {
    this.now = now;
    this.config = validConfig(config) ? config : null;
    this.key = null;
    this.expiresAt = 0;
    this.failures = 0;
    this.blockedUntil = 0;
  }

  get configured() {
    return Boolean(this.config);
  }

  get policy() {
    return normalizePolicy(this.config?.policy);
  }

  // "every" means the key is discarded the moment it has been used, so there is
  // nothing to expire; otherwise the key stops being usable once its window has
  // passed, whether or not anything asks.
  get unlocked() {
    if (!this.key) return false;
    if (this.policy.mode === "every") return true;
    if (this.now() >= this.expiresAt) {
      this.lock();
      return false;
    }
    return true;
  }

  status() {
    const policy = this.policy;
    return {
      configured: this.configured,
      unlocked: this.unlocked,
      mode: policy.mode,
      minutes: policy.minutes,
      // Whole seconds, so a countdown does not have to do the arithmetic.
      secondsRemaining: this.unlocked && policy.mode === "minutes"
        ? Math.max(0, Math.round((this.expiresAt - this.now()) / 1000))
        : 0,
      cooldownSeconds: this.cooldownSeconds(),
    };
  }

  async create(password, policy) {
    checkPassword(password);
    const salt = crypto.randomBytes(16);
    const kdf = { N: KDF.N, r: KDF.r, p: KDF.p, keyLength: KDF.keyLength };
    const key = await derive(password, salt, kdf);
    return {
      key,
      config: {
        salt: salt.toString("base64"),
        kdf,
        verifier: encryptWith(key, VERIFIER_TOKEN),
        policy: normalizePolicy(policy),
      },
    };
  }

  // Adopts a configuration and its key together, which is what makes a password
  // change atomic from the caller's point of view: the new key is only in use once
  // the re-wrapped credentials have been written.
  adopt({ config, key }) {
    // Zero whatever was held before rather than leaving it for the collector.
    if (this.key && this.key !== key) this.key.fill(0);
    this.config = config;
    this.key = key;
    this.#renew();
  }

  async unlock(password) {
    const key = await this.keyFor(password);
    this.key = key;
    this.#renew();
    return this.status();
  }

  lock() {
    if (this.key) this.key.fill(0);
    this.key = null;
    this.expiresAt = 0;
  }

  // Forgets the master password altogether. The caller has already rewritten every
  // stored credential without it by the time this runs.
  clear() {
    this.lock();
    this.config = null;
    this.failures = 0;
    this.blockedUntil = 0;
  }

  // Working out a new configuration and living by it are two steps, because what
  // goes between them can fail. The policy is stored before it is adopted: one that
  // the file refused is not one this process should be enforcing, and getting that
  // backwards means a failed change can quietly relax how often the password is
  // asked for -- reported as an error, and in force anyway.
  configFor(policy) {
    if (!this.configured) throw new Error("No master password has been set");
    return { ...this.config, policy: normalizePolicy(policy) };
  }

  adoptConfig(config) {
    this.config = config;
    // A shorter window applies at once rather than at the next unlock.
    if (this.key) this.#renew();
    return this.status();
  }

  async setPolicy(policy) {
    return this.adoptConfig(this.configFor(policy));
  }

  // Verifies a password and returns its key without the policy treating it as an
  // ordinary credential use, which is what changing or removing the master password
  // needs. Every path that checks a password comes through here, so the penalty for
  // repeated wrong guesses applies to all of them and not only to unlocking.
  async keyFor(password) {
    if (!this.configured) throw new Error("No master password has been set");
    const waiting = this.cooldownSeconds();
    if (waiting) {
      const error = new Error(`Too many attempts. Try again in ${waiting} ${waiting === 1 ? "second" : "seconds"}.`);
      error.rateLimited = true;
      throw error;
    }
    const key = await this.#derive(password);
    try {
      if (decryptWith(key, this.config.verifier) !== VERIFIER_TOKEN) throw new Error("mismatch");
    } catch {
      key.fill(0);
      this.#refuse();
      throw new Error("That master password is not correct");
    }
    this.failures = 0;
    this.blockedUntil = 0;
    return key;
  }

  // Zero while a password may be tried, otherwise the whole seconds left to wait.
  cooldownSeconds() {
    const remaining = this.blockedUntil - this.now();
    return remaining > 0 ? Math.ceil(remaining / 1000) : 0;
  }

  wrap(plaintext) {
    return encryptWith(this.#useKey(), plaintext);
  }

  unwrap(blob) {
    const key = this.#useKey();
    const plaintext = decryptWith(key, blob);
    this.#spend();
    return plaintext;
  }

  // Reading a credential in order to write it straight back is not the same as
  // handing one to a connection, and it is handing one over that the re-prompt
  // policy counts. Changing a single saved password reads all four and rewrites all
  // four; under "ask every time" the read would otherwise spend the unlock and leave
  // the write half of the same operation with no key at all.
  unwrapToRewrite(blob) {
    return decryptWith(this.#useKey(), blob);
  }

  // Crypto with a key the caller already holds, for re-wrapping every stored
  // credential during a password change. It deliberately ignores the policy.
  static encrypt(key, plaintext) {
    return encryptWith(key, plaintext);
  }

  static decrypt(key, blob) {
    return decryptWith(key, blob);
  }

  toJSON() {
    return this.config;
  }

  // A few wrong answers cost nothing extra — that is what mistyping looks like.
  // After that each one buys a longer pause, up to a minute.
  #refuse() {
    this.failures += 1;
    if (this.failures <= FREE_ATTEMPTS) return;
    const seconds = Math.min((this.failures - FREE_ATTEMPTS) * COOLDOWN_STEP_SECONDS, MAX_COOLDOWN_SECONDS);
    this.blockedUntil = this.now() + seconds * 1000;
  }

  #derive(password) {
    const salt = Buffer.from(this.config.salt, "base64");
    return derive(password, salt, this.config.kdf || KDF);
  }

  #useKey() {
    if (!this.configured) throw new Error("No master password has been set");
    if (!this.unlocked) {
      const error = new Error("Saved credentials are locked. Enter the master password to continue.");
      // Marked so a caller can tell "locked" from "cannot be decrypted", which are
      // very different things to tell someone.
      error.locked = true;
      throw error;
    }
    return this.key;
  }

  // Reading a credential either uses up the unlock or pushes the window out,
  // depending on which the policy asked for.
  #spend() {
    if (this.policy.mode === "every") this.lock();
    else this.#renew();
  }

  #renew() {
    this.expiresAt = this.policy.mode === "every"
      ? Number.POSITIVE_INFINITY
      : this.now() + this.policy.minutes * 60000;
  }
}

function checkPassword(password) {
  const text = String(password ?? "");
  if (text.length < MIN_PASSWORD) throw new Error(`A master password needs at least ${MIN_PASSWORD} characters`);
  if (text.length > MAX_PASSWORD) throw new Error("That master password is too long");
  return text;
}

function validConfig(config) {
  return Boolean(
    config && typeof config.salt === "string" && typeof config.verifier === "string" &&
    config.kdf && Number.isInteger(config.kdf.N) && Number.isInteger(config.kdf.r) && Number.isInteger(config.kdf.p),
  );
}

module.exports = { Vault, MIN_PASSWORD, DEFAULT_MINUTES };

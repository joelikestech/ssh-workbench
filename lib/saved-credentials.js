"use strict";

// The four small decisions the connection form makes about a saved connection's
// credentials. They are here rather than in the window because each of them has been
// got wrong once: what the "Save credentials" box should show for a connection whose
// stored credentials cannot be read, whether that box remains usable while encryption
// is unavailable, when replacing them has to be asked about, and what may honestly be
// said afterwards. None of that needs a window to be true, and none of it was being
// tested while it lived in one.

// A connection can be holding credentials that cannot be read -- a keyring changed
// underneath them -- and holding them is still holding them. Clearing this box is
// what discards credentials, so the program must never clear it on someone's behalf
// for that reason: the next save would throw away the one copy that a keyring coming
// back tomorrow could still decrypt.
function credentialsBoxChecked(profile) {
  return Boolean(profile?.credentialsPresent || profile?.credentialsSaved || profile?.needsUnlock);
}

// Encryption availability decides whether a new credential can be added. It must
// not decide whether an existing encrypted blob may be retained: carrying that blob
// forward needs no keyring, and clearing it while a keyring is temporarily missing
// destroys the only copy that keyring may be able to open when it returns.
function credentialsControlEnabled(profile, { secureStorage = false } = {}) {
  return Boolean(secureStorage || profile?.credentialsPresent || profile?.needsUnlock);
}

// Whether a connection's stored credentials are known to be unreadable. A locked
// vault is not damage -- nothing has tried to read it yet -- and saying otherwise
// would put the replacement question to someone whose credentials are perfectly
// fine and merely waiting for a password.
function credentialsUnreadable(profile) {
  return Boolean(profile?.credentialError) && !profile?.needsUnlock;
}

// What is true once a save has gone through, and what may be said about it.
// Credentials are mended only by being replaced or by being discarded outright; a
// save that carried an unreadable blob across untouched -- because this one was
// about the port -- has mended nothing and must not report that it has.
function afterSave({ name, damaged, replaced, keepingCredentials, credentialsSaved }) {
  const stillDamaged = Boolean(damaged) && !replaced && Boolean(keepingCredentials);
  const note = stillDamaged
    ? ". Its saved credentials still cannot be read"
    : credentialsSaved ? " with encrypted credentials" : "";
  return { damaged: stillDamaged, message: `Saved “${name}”${note}` };
}

// Which server a hop is: the thing a saved credential was saved for.
function sameHop(a, b) {
  return String(a?.host || "").toLowerCase() === String(b?.host || "").toLowerCase()
    && Number(a?.port || 22) === Number(b?.port || 22)
    && String(a?.username || "") === String(b?.username || "");
}

// Fills the secrets a connection is about to go out without from the ones saved with
// it. Anything typed by hand wins. A saved secret goes only to the server it was saved
// for: a connection whose host has been edited since -- in the form, or in the saved
// connection while a tab opened from it was still around -- gets nothing, because
// handing one server's password to another is the one mistake here that cannot be
// taken back. The jump host is judged on its own, as it is a server of its own.
function fillSavedSecrets(config, saved) {
  const target = sameHop(config, saved);
  const jump = Boolean(config?.jump?.enabled && saved?.jump?.enabled) && sameHop(config.jump, saved.jump);
  return {
    ...config,
    password: config.password || (target && saved.password) || "",
    passphrase: config.passphrase || (target && saved.passphrase) || "",
    jump: {
      ...config.jump,
      password: config.jump?.password || (jump && saved.jump.password) || "",
      passphrase: config.jump?.passphrase || (jump && saved.jump.passphrase) || "",
    },
  };
}

module.exports = {
  credentialsBoxChecked, credentialsControlEnabled, credentialsUnreadable, afterSave, fillSavedSecrets,
};

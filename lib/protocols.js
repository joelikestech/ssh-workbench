"use strict";

// How a session moves files and reads folders. SFTP is the better protocol and is
// tried first; a host with the subsystem switched off can still be worked with over
// a shell and scp, which is what the fallback is for. Both the connection code and
// the saved-connection store validate against this one list.
const PROTOCOLS = new Set(["sftp", "sftp-scp", "scp"]);
const DEFAULT_PROTOCOL = "sftp-scp";

function normalizeProtocol(value) {
  const protocol = String(value || DEFAULT_PROTOCOL);
  if (!PROTOCOLS.has(protocol)) throw new Error("File transfer protocol is invalid");
  return protocol;
}

module.exports = { PROTOCOLS, DEFAULT_PROTOCOL, normalizeProtocol };

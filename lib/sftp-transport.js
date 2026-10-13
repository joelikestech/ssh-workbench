"use strict";

// The SFTP session, behind the same two calls the shell transport answers, so the
// rest of the manager does not know or care which one it is talking to.
class SftpTransport {
  constructor(sftp) {
    this.sftp = sftp;
    this.kind = "sftp";
    // A real SFTP session multiplexes requests over one channel, so a recursive
    // search can keep as many reads in flight as it likes.
    this.concurrencyLimit = Infinity;
  }

  call(method, args) {
    return new Promise((resolve, reject) => {
      this.sftp[method](...args, (error, ...values) => {
        if (error) reject(error);
        else resolve(values.length > 1 ? values : values[0]);
      });
    });
  }

  close() {
    try { this.sftp.end(); } catch { /* already closed */ }
  }
}

module.exports = { SftpTransport };

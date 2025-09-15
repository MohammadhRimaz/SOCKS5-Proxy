require("dotenv").config();

const net = require("net");
const PORT = process.env.PORT || 1080;
const AUTH_USER = process.env.PROXY_USERNAME;
const AUTH_PASS = process.env.PROXY_PASSWORD;

const server = net.createServer((client) => {
  client.setNoDelay(true);
  const clientId = `${client.remoteAddress}:${client.remotePort}`;
  console.log(`[${new Date().toISOString()}] Client connected: ${clientId}`);

  // Buffer to hold partial data between reads
  let leftover = Buffer.alloc(0);

  // Helper: read exactly n bytes from the socket (accumulating if needed)
  function readBytes(n) {
    return new Promise((resolve, reject) => {
      // If leftover already has enough
      if (leftover.length >= n) {
        const chunk = leftover.slice(0, n);
        leftover = leftover.slice(n);
        return resolve(chunk);
      }

      // Otherwise wait for data events until we have n bytes
      function onData(data) {
        leftover = Buffer.concat([leftover, data]);
        if (leftover.length >= n) {
          client.removeListener("data", onData);
          const chunk = leftover.slice(0, n);
          leftover = leftover.slice(n);
          resolve(chunk);
        }
      }

      function onClose() {
        client.removeListener("data", onData);
        reject(new Error("Socket closed before enough bytes were received"));
      }

      client.on("data", onData);
      client.once("close", onClose);
      client.once("error", (err) => {
        client.removeListener("data", onData);
        reject(err);
      });
    });
  }

  // Write a standard SOCKS5 reply (VER, REP, RSV, ATYP=IPv4, ADDR=0.0.0.0, PORT=0)
  function sendReply(rep) {
    // VER(0x05), REP, RSV(0x00), ATYP(0x01 IPv4), BND.ADDR(0.0.0.0), BND.PORT(0)
    const reply = Buffer.from([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    client.write(reply);
  }

  async () => {
    try {
      // --- 1) SOCKS5 greeting: VER, NMETHODS
      const hdr = await readBytes(2);
      if (hdr[0] !== 0x05) {
        console.log(`Invalid SOCKS version from ${clientId}: ${hdr[0]}`);
        client.end();
        return;
      }
      const nmethods = hdr[1];
      const methods = await readBytes(nmethods); // method bytes

      // Check for username/password method (0x02)
      const METHOD_USERNAME_PASSWORD = 0x02;
      if (!methods.includes(METHOD_USERNAME_PASSWORD)) {
        // no acceptable methods
        client.write(Buffer.from([0x05, 0xff]));
        console.log(`No supported auth methods from ${clientId}`);
        client.end();
        return;
      }

      // Request username/password auth
      client.write(Buffer.from([0x05, METHOD_USERNAME_PASSWORD]));

      // --- 2) Username/Password Authentication (RFC 1929)
      // auth request: VER(0x01), ULEN, UNAME, PLEN, PASSWD
    } catch (error) {}
  };
});

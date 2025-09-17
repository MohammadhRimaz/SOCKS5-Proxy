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

  (async () => {
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
      const authHead = await readBytes(2);
      if (authHead[0] !== 0x01) {
        console.log(`Invalid auth version from ${clientId}: ${authHead[0]}`);
        client.end();
        return;
      }

      const ulen = authHead[1];
      const unameBuf = await readBytes(ulen);
      const uname = unameBuf.toString("utf8");

      const plenBuf = await readBytes(1);
      const plen = plenBuf[0];
      const passwdBuf = await readBytes(plen);
      const passwd = passwdBuf.toString("utf8");

      const authOk = uname === AUTH_USER && passwd === AUTH_PASS;
      client.write(Buffer.from([0x01, authOk ? 0x00 : 0x01]));
      if (!authOk) {
        console.log(`[AUTH FAIL] ${clientId} -> (${uname})`);
        client.end();
        return;
      }
      console.log(`[AUTH_OK] ${clientId} as "${uname}"`);

      // --- 3) Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
      // First read 4 bytes header
      const reqHeader = await readBytes(4);
      const ver = reqHeader[0],
        cmd = reqHeader[1],
        rsv = reqHeader[2],
        atyp = reqHeader[3];
      if (ver !== 0x05) {
        console.log(`Invalid request version from ${clientId}: ${ver}`);
        client.end();
        return;
      }
      if (cmd !== 0x01) {
        // we only support CONNECT (0x01)
        console.log(`Unsupported CMD (${cmd}) from ${clientId}`);
        sendReply(0x07); // Command not supported
        client.end();
        return;
      }

      let destAddr = null;
      let destPort = null;

      if (atyp === 0x01) {
        // IPv4
        const addrPort = await readBytes(6); // 4 bytes IP + 2 bytes port
        destAddr = Array.from(addrPort.slice(0, 4)).join(".");
        destPort = addrPort.readUInt16BE(4);
      } else if (atyp === 0x03) {
        // Domain name
        const lenBuf = await readBytes(1);
        const dlen = lenBuf[0];
        const domainAndPort = await readBytes(dlen + 2);
        destAddr = domainAndPort.slice(0, dlen).toString("utf8");
        destPort = domainAndPort.readUInt16BE(dlen);
      } else if (atyp === 0x04) {
        // IPv6 (support minimally)
        const addrPort = await readBytes(16 + 2);
        const addrBuf = addrPort.slice(0, 16);
        // format IPv6 from buffer (simple hex groups)
        const groups = [];
        for (let i = 0; i < 16; i += 2) {
          groups.push(addrBuf.readUInt16BE(i).toString(16));
        }
        destAddr = groups.join(":");
        destPort = addrPort.readUInt16BE(16);
      } else {
        sendReply(0x08); // address type not supported
        client.end();
        return;
      }

      console.log(`[CONNECT] ${clientId} -> ${destAddr}:${destPort}`);

      // --- 4) Connect to destination and tunnel
      const remote = net.createConnection(destPort, destAddr);

      remote.on("connect", () => {
        // success
        sendReply(0x00); // succeeded
        // If leftover has any bytes (rare),forward them
        if (leftover.length > 0) {
          remote.write(leftover);
          leftover = Buffer.alloc(0);
        }
        // pipe both ways
        client.pipe(remote);
        remote.pipe(client);
      });

      remote.on("error", (err) => {
        console.log(
          `[REMOTE ERROR] ${clientId} -> ${destAddr}:${destPort} : ${err.message}`
        );
        sendReply(0x05); // Connection refused or general failure
        client.end();
      });

      // close peers on end
      client.on("close", () => remote.end());
      remote.on("close", () => client.end());
    } catch (error) {
      console.log(`[ERROR] ${clientId} : ${error.message}`);
      try {
        client.end();
      } catch (e) {}
    }
  })();
});

server.on("error", (err) => {
  console.error("Server error:", err);
});

server.listen(PORT, () => {
  console.log(`SOCKS5 proxy listening on port ${PORT}`);
  console.log(`Auth user: "${AUTH_USER}"`);
});

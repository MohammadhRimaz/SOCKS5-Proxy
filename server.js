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
});

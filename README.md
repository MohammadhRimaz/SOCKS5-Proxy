# Minimal SOCKS5 Proxy (Node.js)

## Requirements

- Node.js: 16+ (or compatible)

## Setup

1. Install dependencies:

```bash
npm install
```

2. Copy `.env-example` to `.env` and edit .env to set credentials.

3. Run proxy:

```bash
npm start
```

4. Test (From another terminal):

```bash
curl -x socks5h://youruser:yourpasswd@127.0.0.1:1080 https://ipinfo.io/json
```

## Logs

Server prints connection logs such as:

```bash
[AUTH_OK] ::ffff:127.0.0.1:58442 as "youruser"
[CONNECT] ::ffff:127.0.0.1:58442 -> ipinfo.io:443
```

## Reflection:

- Implemented handshake, RFC1929 username/password, CONNECT tunneling using Node `net`.
- Debugging: added stepwise logs and a `readBytes` helper to handle partial TCP frames.
- Improvements (if more time): UDP ASSOCIATE, TLS between client/proxy, unit tests, connection throttling.

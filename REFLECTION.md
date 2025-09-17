I learned the SOCKS5 basics (RFC 1928) and the username/password auth extension (RFC 1929). I implemented method negotiation, the username/password exchange, parsing of CONNECT requests for IPv4/domain/IPv6, and streaming/tunneling of TCP traffic using Node's 'net' sockets. The `readBytes` helper solved partial-packet parsing edge cases.

For debugging I relied on clear logging at each protocol stage (greating, auth, request, remote connect) and tested with `curl` using `socks5h://user:pass@host:port`.

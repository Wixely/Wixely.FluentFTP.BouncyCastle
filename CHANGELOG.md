# Changelog

## 0.1.0-alpha.1

- Add a FluentFTP custom stream backed by Bouncy Castle TLS.
- Carry the control connection's resumable TLS 1.2 session into data connections.
- Require verified session resumption by default.
- Add an opt-in compatibility switch for servers without Extended Master Secret.
- Delegate certificate acceptance to FluentFTP's configured validation policy.
- Add a read-only hardware verification harness.

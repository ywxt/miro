# Miro

A Hysteria protocol implementation in Rust.

## TODO

- [ ] Server
- [ ] Client
- [ ] Protocol
  - [ ]  Obfuscation
  - [ ]  Congestion control
  - [x] Server
    - [x] Handshake
    - [x] TCP transport
    - [x] Masquerade(404 only)
    - [x] UDP transport
      - [x] Fragmentation
      - [x] Session management
  - [ ] Client
    - [ ] Handshake
    - [ ] TCP transport
    - [ ] UDP transport
      - [ ] Fragmentation
      - [ ] Merge frames and send to remote
      - [ ] Session management

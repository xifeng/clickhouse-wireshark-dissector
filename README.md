# ClickHouse Wireshark Dissector

A Lua-based Wireshark dissector for the ClickHouse Native Protocol (TCP).

## Features

- **Handshake Dissection**: Full support for both Client and Server `Hello` packets, including versioning and authentication details.
- **Query Analysis**: Dissects `Query` packets with `ClientInfo` (including OTEL tracing), `Settings`, and the SQL body.
- **Data Block Inspection**: Decodes `Data` blocks, providing visibility into `BlockInfo`, column counts, row counts, and column metadata (names and types).
- **Error Handling**: Detailed dissection of `Exception` packets, including nested errors and stack traces.
- **Progress Tracking**: Monitors query execution via `Progress` and `ProfileInfo` packets.
- **Protocol Helpers**: Robust implementation of ClickHouse-specific types like `UVarInt` (LEB128) and length-prefixed strings.

## Installation

1.  **Install the Script**:
    - Copy [clickhouse.lua](clickhouse.lua) into ~/.config/wireshark/plugins/.

2.  **Reload Plugins**:
    - Either restart Wireshark or press `Cmd+Shift+L` to reload Lua plugins.

## Usage

Once installed, Wireshark will automatically dissect any traffic on TCP port `9000` as ClickHouse Native Protocol.

### Filtering
You can use the following display filters:
- `clickhouse`: Show all ClickHouse traffic.
- `clickhouse.packet_type == 0`: Show Hello packets.
- `clickhouse.query_body contains "SELECT"`: Filter by query content.
- `clickhouse.exception_code`: Show packets containing server exceptions.

## Protocol Support & Verification

Below is the current implementation and verification status of the ClickHouse Native Protocol features:

### Client Packets
- [x] **Hello (0)**: Handshake, auth, and versioning.
- [ ] **Query (1)**: Pending implementation.
- [ ] **Data (2)**: Pending implementation.
- [ ] **Cancel (3)**: Pending implementation.
- [ ] **Ping (4)**: Pending implementation.
- [ ] **TableStatus (5)**: Pending implementation.

### Server Packets
- [x] **Hello (0)**: Server version and revision info (with dynamic revision checks).
- [ ] **Data (1)**: Pending implementation.
- [ ] **Exception (2)**: Pending implementation.
- [ ] **Progress (3)**: Pending implementation.
- [ ] **Pong (4)**: Pending implementation.
- [ ] **EndOfStream (5)**: Pending implementation.
- [ ] **ProfileInfo (6)**: Pending implementation.
- [ ] **Totals (7)**: Pending implementation.
- [ ] **Extremes (8)**: Pending implementation.
- [ ] **Log (10)**: Pending implementation.

## References

- [ClickHouse Native Protocol - Client](https://clickhouse.com/docs/native-protocol/client)
- [ClickHouse Native Protocol - Server](https://clickhouse.com/docs/native-protocol/server)

## License

Apache License 2.0

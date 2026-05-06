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
- [x] **Query (1)**: Query ID, SQL body, stage, compression, settings, and parameters.
- [x] **Data (2)**: Table name and data block with columns.
- [x] **Cancel (3)**: Empty packet for query cancellation.
- [x] **Ping (4)**: Empty packet for connection health check.
- [x] **TableStatus (5)**: Table name request.

### Server Packets
- [x] **Hello (0)**: Server version and revision info (with dynamic revision checks).
- [x] **Data (1)**: Data blocks with BlockInfo, columns, and rows.
- [x] **Exception (2)**: Error code, name, message, stack trace, and nested exceptions.
- [x] **Progress (3)**: Rows, bytes, totals, written rows/bytes, and elapsed time.
- [x] **Pong (4)**: Response to client Ping.
- [x] **EndOfStream (5)**: Marks end of data stream.
- [x] **ProfileInfo (6)**: Query execution statistics.
- [x] **Totals (7)**: Aggregated totals block.
- [x] **Extremes (8)**: Min and max data blocks.
- [x] **Log (10)**: Log messages with timestamp, timezone, level, source, and message.

## References

- [ClickHouse Native Protocol - Client](https://clickhouse.com/docs/native-protocol/client)
- [ClickHouse Native Protocol - Server](https://clickhouse.com/docs/native-protocol/server)

## License

Apache License 2.0

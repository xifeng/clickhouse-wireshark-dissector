-- ClickHouse Native Protocol Dissector for Wireshark
-- Based on:
-- https://clickhouse.com/docs/native-protocol/client
-- https://clickhouse.com/docs/native-protocol/server

local clickhouse_protocol = Proto("clickhouse", "ClickHouse Native Protocol")

--------------------------------------------------------------------------------
-- Protocol Constants
--------------------------------------------------------------------------------
local CLICKHOUSE_PORT = 9000

local REVISIONS = {
    DBMS_MIN_REVISION_WITH_SERVER_TIMEZONE = 54058,
    DBMS_MIN_REVISION_WITH_SERVER_DISPLAY_NAME = 54372,
    DBMS_MIN_REVISION_WITH_VERSION_PATCH = 54401,
    DBMS_MIN_REVISION_WITH_VERSIONED_PARALLEL_REPLICAS_PROTOCOL = 54453,
    DBMS_MIN_PROTOCOL_VERSION_WITH_CHUNKED_PACKETS = 54461,
    DBMS_MIN_PROTOCOL_VERSION_WITH_PASSWORD_COMPLEXITY_RULES = 54498,
    DBMS_MIN_REVISION_WITH_INTERSERVER_SECRET_V2 = 54469,
    DBMS_MIN_REVISION_WITH_SERVER_SETTINGS = 54429,
    DBMS_MIN_REVISION_WITH_QUERY_PLAN_SERIALIZATION = 54462,
    DBMS_MIN_REVISION_WITH_VERSIONED_CLUSTER_FUNCTION_PROTOCOL = 54479
}

local PACKET_TYPES = {
    CLIENT = {
        [0] = "Hello"
    },
    SERVER = {
        [0] = "Hello"
    }
}

--------------------------------------------------------------------------------
-- Fields
--------------------------------------------------------------------------------
local f = clickhouse_protocol.fields

-- Common
f.packet_type = ProtoField.uint32("clickhouse.packet_type", "Packet Type", base.DEC, nil, 0xFF)

-- Hello (Client)
f.hello_client_name = ProtoField.string("clickhouse.hello.client.name", "Client Name")
f.hello_client_version_major = ProtoField.uint32("clickhouse.hello.client.version_major", "Version Major")
f.hello_client_version_minor = ProtoField.uint32("clickhouse.hello.client.version_minor", "Version Minor")
f.hello_client_protocol_version = ProtoField.uint32("clickhouse.hello.client.protocol_version", "Protocol Version")
f.hello_client_database = ProtoField.string("clickhouse.hello.client.database", "Database")
f.hello_client_username = ProtoField.string("clickhouse.hello.client.username", "Username")
f.hello_client_password = ProtoField.string("clickhouse.hello.client.password", "Password")

-- Hello (Server)
f.hello_server_name = ProtoField.string("clickhouse.hello.server.name", "Server Name")
f.hello_server_version_major = ProtoField.uint32("clickhouse.hello.server.version_major", "Version Major")
f.hello_server_version_minor = ProtoField.uint32("clickhouse.hello.server.version_minor", "Version Minor")
f.hello_server_revision = ProtoField.uint32("clickhouse.hello.server.revision", "Revision")
f.hello_server_parallel_replicas_proto_version = ProtoField.uint32("clickhouse.hello.server.parallel_replicas_proto_version", "Parallel Replicas Proto Version")
f.hello_server_timezone = ProtoField.string("clickhouse.hello.server.timezone", "Timezone")
f.hello_server_display_name = ProtoField.string("clickhouse.hello.server.display_name", "Display Name")
f.hello_server_version_patch = ProtoField.uint32("clickhouse.hello.server.version_patch", "Version Patch")
f.hello_server_proto_cap_send = ProtoField.string("clickhouse.hello.server.proto_cap_send", "Proto Cap Send")
f.hello_server_proto_cap_recv = ProtoField.string("clickhouse.hello.server.proto_cap_recv", "Proto Cap Recv")
f.hello_server_password_complexity_rules_count = ProtoField.uint32("clickhouse.hello.server.password_complexity_rules_count", "Password Complexity Rules Count")
f.hello_server_password_complexity_rule_pattern = ProtoField.string("clickhouse.hello.server.password_complexity_rule_pattern", "Rule Pattern")
f.hello_server_password_complexity_rule_message = ProtoField.string("clickhouse.hello.server.password_complexity_rule_message", "Rule Message")
f.hello_server_nonce = ProtoField.uint64("clickhouse.hello.server.nonce", "Nonce", base.HEX)
f.hello_server_query_plan_serialization_version = ProtoField.uint32("clickhouse.hello.server.query_plan_serialization_version", "Query Plan Serialization Version")
f.hello_server_cluster_processing_protocol_version = ProtoField.uint32("clickhouse.hello.server.cluster_processing_protocol_version", "Cluster Processing Protocol Version")
f.hello_server_settings_empty = ProtoField.bool("clickhouse.hello.server.settings_empty", "Settings Empty")


-- Read UVarInt (LEB128) - matches ClickHouse C++ logic exactly
local function read_uvarint(buffer, offset)
    local x = 0
    local shift = 0
    for i = 0, 9 do
        if offset + i >= buffer:len() then
            return nil, 0
        end
        
        local byte = buffer(offset + i, 1):uint()
        local low7 = bit.band(byte, 0x7F)
        
        -- Accumulate using math to avoid 32-bit signed overflow in Lua bitwise operations.
        -- Lua's double-precision numbers handle up to 53 bits of integer precision perfectly.
        x = x + (low7 * (2 ^ shift))
        
        if bit.band(byte, 0x80) == 0 then
            return x, i + 1
        end
        shift = shift + 7
    end
    return x, 10
end

-- Helper to dissect and read a ClickHouse string (UVarInt length prefix)
local function read_ch_string(buffer, offset)
    local len, len_len = read_uvarint(buffer, offset)
    if not len then return nil, 0 end

    if offset + len_len + len > buffer:len() then
        return nil, 0
    end

    local str = buffer(offset + len_len, len):string()
    return str, len_len + len
end

--------------------------------------------------------------------------------
-- Packet Dissectors
--------------------------------------------------------------------------------
local dissectors = {
    client = {},
    server = {}
}

-- Hello (Client)
dissectors.client[0] = function(buffer, offset, subtree)
    local initial_offset = offset
    
    local name, name_bytes = read_ch_string(buffer, offset)
    if not name then return 0 end
    subtree:add(f.hello_client_name, buffer(offset, name_bytes), name)
    offset = offset + name_bytes

    local major, major_bytes = read_uvarint(buffer, offset)
    if not major then return 0 end
    subtree:add(f.hello_client_version_major, buffer(offset, major_bytes), major)
    offset = offset + major_bytes

    local minor, minor_bytes = read_uvarint(buffer, offset)
    if not minor then return 0 end
    subtree:add(f.hello_client_version_minor, buffer(offset, minor_bytes), minor)
    offset = offset + minor_bytes

    local proto, proto_bytes = read_uvarint(buffer, offset)
    if not proto then return 0 end
    subtree:add(f.hello_client_protocol_version, buffer(offset, proto_bytes), proto)
    offset = offset + proto_bytes

    local db, db_bytes = read_ch_string(buffer, offset)
    if not db then return 0 end
    subtree:add(f.hello_client_database, buffer(offset, db_bytes), db)
    offset = offset + db_bytes

    local user, user_bytes = read_ch_string(buffer, offset)
    if not user then return 0 end
    subtree:add(f.hello_client_username, buffer(offset, user_bytes), user)
    offset = offset + user_bytes

    local pass, pass_bytes = read_ch_string(buffer, offset)
    if not pass then return 0 end
    subtree:add(f.hello_client_password, buffer(offset, pass_bytes), pass)
    offset = offset + pass_bytes
    
    return offset - initial_offset
end

-- Hello (Server)
dissectors.server[0] = function(buffer, offset, subtree)
    local initial_offset = offset
    
    local name, name_bytes = read_ch_string(buffer, offset)
    if not name then return 0 end
    subtree:add(f.hello_server_name, buffer(offset, name_bytes), name)
    offset = offset + name_bytes

    local major, major_bytes = read_uvarint(buffer, offset)
    if not major then return 0 end
    subtree:add(f.hello_server_version_major, buffer(offset, major_bytes), major)
    offset = offset + major_bytes

    local minor, minor_bytes = read_uvarint(buffer, offset)
    if not minor then return 0 end
    subtree:add(f.hello_server_version_minor, buffer(offset, minor_bytes), minor)
    offset = offset + minor_bytes

    local revision, revision_bytes = read_uvarint(buffer, offset)
    if not revision then return 0 end
    subtree:add(f.hello_server_revision, buffer(offset, revision_bytes), revision)
    offset = offset + revision_bytes

    -- New logic matching TCPHandler::sendHello()
    if revision >= REVISIONS.DBMS_MIN_REVISION_WITH_VERSIONED_PARALLEL_REPLICAS_PROTOCOL then
        local pr_version, pr_bytes = read_uvarint(buffer, offset)
        if not pr_version then return 0 end
        subtree:add(f.hello_server_parallel_replicas_proto_version, buffer(offset, pr_bytes), pr_version)
        offset = offset + pr_bytes
    end

    if revision >= REVISIONS.DBMS_MIN_REVISION_WITH_SERVER_TIMEZONE then
        local tz, tz_bytes = read_ch_string(buffer, offset)
        if not tz then return 0 end
        subtree:add(f.hello_server_timezone, buffer(offset, tz_bytes), tz)
        offset = offset + tz_bytes
    end

    if revision >= REVISIONS.DBMS_MIN_REVISION_WITH_SERVER_DISPLAY_NAME then
        local display_name, dn_bytes = read_ch_string(buffer, offset)
        if not display_name then return 0 end
        subtree:add(f.hello_server_display_name, buffer(offset, dn_bytes), display_name)
        offset = offset + dn_bytes
    end

    if revision >= REVISIONS.DBMS_MIN_REVISION_WITH_VERSION_PATCH then
        local patch, patch_bytes = read_uvarint(buffer, offset)
        if not patch then return 0 end
        subtree:add(f.hello_server_version_patch, buffer(offset, patch_bytes), patch)
        offset = offset + patch_bytes
    end

    if revision >= REVISIONS.DBMS_MIN_PROTOCOL_VERSION_WITH_CHUNKED_PACKETS then
        local cap_send, cap_send_bytes = read_ch_string(buffer, offset)
        if not cap_send then return 0 end
        subtree:add(f.hello_server_proto_cap_send, buffer(offset, cap_send_bytes), cap_send)
        offset = offset + cap_send_bytes

        local cap_recv, cap_recv_bytes = read_ch_string(buffer, offset)
        if not cap_recv then return 0 end
        subtree:add(f.hello_server_proto_cap_recv, buffer(offset, cap_recv_bytes), cap_recv)
        offset = offset + cap_recv_bytes
    end

    if revision >= REVISIONS.DBMS_MIN_PROTOCOL_VERSION_WITH_PASSWORD_COMPLEXITY_RULES then
        local count, count_bytes = read_uvarint(buffer, offset)
        if not count then return 0 end
        subtree:add(f.hello_server_password_complexity_rules_count, buffer(offset, count_bytes), count)
        offset = offset + count_bytes
        
        for i = 1, count do
            local pattern, pattern_bytes = read_ch_string(buffer, offset)
            if not pattern then break end
            subtree:add(f.hello_server_password_complexity_rule_pattern, buffer(offset, pattern_bytes), pattern)
            offset = offset + pattern_bytes
            
            local message, message_bytes = read_ch_string(buffer, offset)
            if not message then break end
            subtree:add(f.hello_server_password_complexity_rule_message, buffer(offset, message_bytes), message)
            offset = offset + message_bytes
        end
    end

    if revision >= REVISIONS.DBMS_MIN_REVISION_WITH_INTERSERVER_SECRET_V2 then
        if offset + 8 <= buffer:len() then
            subtree:add(f.hello_server_nonce, buffer(offset, 8))
            offset = offset + 8
        
        end
    end

    if revision >= REVISIONS.DBMS_MIN_REVISION_WITH_SERVER_SETTINGS then
        -- Settings are complex, but the code says Settings::writeEmpty(*out) or session->...write(...)
        -- For now, we add a placeholder or skip if it's empty (0)
        local settings_count, settings_bytes = read_uvarint(buffer, offset)
        if settings_count then
            subtree:add(f.hello_server_settings_empty, buffer(offset, settings_bytes), settings_count == 0)
            offset = offset + settings_bytes
            -- Parsing full settings is complex; we stop here for now or skip them
        end
    end

    if revision >= REVISIONS.DBMS_MIN_REVISION_WITH_QUERY_PLAN_SERIALIZATION then
        local qp_version, qp_bytes = read_uvarint(buffer, offset)
        if qp_version then
            subtree:add(f.hello_server_query_plan_serialization_version, buffer(offset, qp_bytes), qp_version)
            offset = offset + qp_bytes
        end
    end

    if revision >= REVISIONS.DBMS_MIN_REVISION_WITH_VERSIONED_CLUSTER_FUNCTION_PROTOCOL then
        local cp_version, cp_bytes = read_uvarint(buffer, offset)
        if cp_version then
            subtree:add(f.hello_server_cluster_processing_protocol_version, buffer(offset, cp_bytes), cp_version)
            offset = offset + cp_bytes
        end
    end
    
    return offset - initial_offset
end

--------------------------------------------------------------------------------
-- Main Entry Point
--------------------------------------------------------------------------------
function clickhouse_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = clickhouse_protocol.name

    local subtree = tree:add(clickhouse_protocol, buffer(), "ClickHouse Native Protocol")
    local offset = 0
    
    -- Packet type is UVarInt
    local packet_type, type_bytes = read_uvarint(buffer, offset)
    
    local is_client = pinfo.dst_port == CLICKHOUSE_PORT
    local packet_info = is_client and PACKET_TYPES.CLIENT or PACKET_TYPES.SERVER
    local type_name = packet_info[packet_type]
    
    -- Add packet type to tree
    local type_item = subtree:add(f.packet_type, buffer(offset, type_bytes), packet_type)
    if type_name then
        type_item:append_text(" (" .. type_name .. ")")
    end
    pinfo.cols.info:set(type_name or "Unknown (" .. packet_type .. ")")
    offset = offset + type_bytes

    -- Dissect packet body
    local packet_dissector = is_client and dissectors.client[packet_type] or dissectors.server[packet_type]
    if packet_dissector then
        packet_dissector(buffer, offset, subtree)
    end
end

-- Register protocol
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(CLICKHOUSE_PORT, clickhouse_protocol)

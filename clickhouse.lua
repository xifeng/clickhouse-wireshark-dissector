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
        [0] = "Hello",
        [1] = "Query",
        [2] = "Data",
        [3] = "Cancel",
        [4] = "Ping",
        [5] = "TableStatus"
    },
    SERVER = {
        [0] = "Hello",
        [1] = "Data",
        [2] = "Exception",
        [3] = "Progress",
        [4] = "Pong",
        [5] = "EndOfStream",
        [6] = "ProfileInfo",
        [7] = "Totals",
        [8] = "Extremes",
        [10] = "Log"
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

--------------------------------------------------------------------------------
-- Query (Client) Fields
--------------------------------------------------------------------------------
f.query_id = ProtoField.string("clickhouse.query.id", "Query ID")
f.query_body = ProtoField.string("clickhouse.query.body", "Query Body")
f.query_stage = ProtoField.uint64("clickhouse.query.stage", "Stage")
f.query_compression = ProtoField.bool("clickhouse.query.compression", "Compression")
f.query_setting_key = ProtoField.string("clickhouse.query.setting.key", "Setting Key")
f.query_setting_value = ProtoField.string("clickhouse.query.setting.value", "Setting Value")
f.query_param_name = ProtoField.string("clickhouse.query.param.name", "Parameter Name")
f.query_param_value = ProtoField.string("clickhouse.query.param.value", "Parameter Value")

--------------------------------------------------------------------------------
-- Data (Client/Server) Fields
--------------------------------------------------------------------------------
f.data_table_name = ProtoField.string("clickhouse.data.table_name", "Table Name")
f.data_block_info_is_overflows = ProtoField.bool("clickhouse.data.block_info.is_overflows", "Is Overflows")
f.data_block_info_bucket_num = ProtoField.uint32("clickhouse.data.block_info.bucket_num", "Bucket Number")
f.data_block_info_has_all_columns = ProtoField.bool("clickhouse.data.block_info.has_all_columns", "Has All Columns")
f.data_block_info_num_columns = ProtoField.uint64("clickhouse.data.block_info.num_columns", "Number of Columns")
f.data_block_info_num_rows = ProtoField.uint64("clickhouse.data.block_info.num_rows", "Number of Rows")
f.data_column_name = ProtoField.string("clickhouse.data.column.name", "Column Name")
f.data_column_type = ProtoField.string("clickhouse.data.column.type", "Column Type")
f.data_column_size = ProtoField.uint64("clickhouse.data.column.size", "Column Size")

--------------------------------------------------------------------------------
-- Exception (Server) Fields
--------------------------------------------------------------------------------
f.exception_code = ProtoField.int32("clickhouse.exception.code", "Exception Code")
f.exception_name = ProtoField.string("clickhouse.exception.name", "Exception Name")
f.exception_message = ProtoField.string("clickhouse.exception.message", "Exception Message")
f.exception_stack_trace = ProtoField.string("clickhouse.exception.stack_trace", "Stack Trace")
f.exception_nested_count = ProtoField.uint32("clickhouse.exception.nested_count", "Nested Exception Count")

--------------------------------------------------------------------------------
-- Progress (Server) Fields
--------------------------------------------------------------------------------
f.progress_rows = ProtoField.uint64("clickhouse.progress.rows", "Rows")
f.progress_bytes = ProtoField.uint64("clickhouse.progress.bytes", "Bytes")
f.progress_total_rows = ProtoField.uint64("clickhouse.progress.total_rows", "Total Rows")
f.progress_total_bytes = ProtoField.uint64("clickhouse.progress.total_bytes", "Total Bytes")
f.progress_write_rows = ProtoField.uint64("clickhouse.progress.write_rows", "Written Rows")
f.progress_write_bytes = ProtoField.uint64("clickhouse.progress.write_bytes", "Written Bytes")
f.progress_elapsed = ProtoField.double("clickhouse.progress.elapsed", "Elapsed Seconds")

--------------------------------------------------------------------------------
-- ProfileInfo (Server) Fields
--------------------------------------------------------------------------------
f.profile_info_rows = ProtoField.uint64("clickhouse.profile_info.rows", "Rows")
f.profile_info_bytes = ProtoField.uint64("clickhouse.profile_info.bytes", "Bytes")
f.profile_info_blocks = ProtoField.uint64("clickhouse.profile_info.blocks", "Blocks")
f.profile_info_applied_limit = ProtoField.bool("clickhouse.profile_info.applied_limit", "Applied Limit")
f.profile_info_rows_before_limit = ProtoField.uint64("clickhouse.profile_info.rows_before_limit", "Rows Before Limit")
f.profile_info_calculated_rows_before_limit = ProtoField.bool("clickhouse.profile_info.calculated_rows_before_limit", "Calculated Rows Before Limit")

--------------------------------------------------------------------------------
-- Log (Server) Fields
--------------------------------------------------------------------------------
f.log_time = ProtoField.uint64("clickhouse.log.time", "Timestamp")
f.log_timezone = ProtoField.string("clickhouse.log.timezone", "Timezone")
f.log_level = ProtoField.string("clickhouse.log.level", "Log Level")
f.log_source = ProtoField.string("clickhouse.log.source", "Source")
f.log_message = ProtoField.string("clickhouse.log.message", "Log Message")

--------------------------------------------------------------------------------
-- TableStatus (Client) Fields
--------------------------------------------------------------------------------
f.table_status_name = ProtoField.string("clickhouse.table_status.name", "Table Name")

--------------------------------------------------------------------------------
-- BlockInfo Fields
--------------------------------------------------------------------------------
f.block_info_min_index = ProtoField.int64("clickhouse.block_info.min_index", "Min Index")
f.block_info_max_index = ProtoField.int64("clickhouse.block_info.max_index", "Max Index")
f.block_info_is_overflows = ProtoField.bool("clickhouse.block_info.is_overflows", "Is Overflows")
f.block_info_bucket_num = ProtoField.int32("clickhouse.block_info.bucket_num", "Bucket Number")
f.block_info_has_all_columns = ProtoField.bool("clickhouse.block_info.has_all_columns", "Has All Columns")


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

-- Read VarInt (signed LEB128)
local function read_varint(buffer, offset)
    local result, bytes_read = read_uvarint(buffer, offset)
    if result == nil then return nil, 0 end
    local sign_bit = bit.band(result, 1)
    local value = bit.rshift(result, 1)
    if sign_bit == 1 then
        value = -value - 1
    end
    return value, bytes_read
end

-- Read fixed 64-bit unsigned integer
local function read_uint64(buffer, offset)
    if offset + 8 > buffer:len() then return nil, 0 end
    return buffer(offset, 8):uint64(), 8
end

-- Read fixed 64-bit signed integer
local function read_int64(buffer, offset)
    if offset + 8 > buffer:len() then return nil, 0 end
    return buffer(offset, 8):int64(), 8
end

-- Read fixed 32-bit signed integer
local function read_int32(buffer, offset)
    if offset + 4 > buffer:len() then return nil, 0 end
    return buffer(offset, 4):int(), 4
end

-- Read double (8 bytes)
local function read_double(buffer, offset)
    if offset + 8 > buffer:len() then return nil, 0 end
    return buffer(offset, 8):float(), 8
end

-- Read boolean (1 byte)
local function read_bool(buffer, offset)
    if offset + 1 > buffer:len() then return nil, 0 end
    return buffer(offset, 1):uint() ~= 0, 1
end

-- Skip bytes (for unimplemented parts)
local function skip_bytes(buffer, offset, count)
    if offset + count > buffer:len() then return 0 end
    return count
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
        local settings_count, settings_bytes = read_uvarint(buffer, offset)
        if settings_count then
            subtree:add(f.hello_server_settings_empty, buffer(offset, settings_bytes), settings_count == 0)
            offset = offset + settings_bytes
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
-- Client Packet Dissectors
--------------------------------------------------------------------------------

-- Query (Client)
dissectors.client[1] = function(buffer, offset, subtree)
    local initial_offset = offset

    local query_id, query_id_bytes = read_ch_string(buffer, offset)
    if not query_id then return 0 end
    subtree:add(f.query_id, buffer(offset, query_id_bytes), query_id)
    offset = offset + query_id_bytes

    local query_body, query_body_bytes = read_ch_string(buffer, offset)
    if not query_body then return 0 end
    subtree:add(f.query_body, buffer(offset, query_body_bytes), query_body)
    offset = offset + query_body_bytes

    local stage, stage_bytes = read_uint64(buffer, offset)
    if not stage then return 0 end
    subtree:add(f.query_stage, buffer(offset, stage_bytes), stage)
    offset = offset + stage_bytes

    local compression, compression_bytes = read_bool(buffer, offset)
    if compression == nil then return 0 end
    subtree:add(f.query_compression, buffer(offset, compression_bytes), compression)
    offset = offset + compression_bytes

    local settings_count, settings_count_bytes = read_uvarint(buffer, offset)
    if not settings_count then return 0 end
    local settings_subtree = subtree:add(buffer(offset, settings_count_bytes), "Settings: " .. settings_count .. " items")
    offset = offset + settings_count_bytes

    for i = 1, settings_count do
        local key, key_bytes = read_ch_string(buffer, offset)
        if not key then break end
        offset = offset + key_bytes

        local value, value_bytes = read_ch_string(buffer, offset)
        if not value then break end
        local setting_item = settings_subtree:add(buffer(offset - key_bytes - value_bytes, key_bytes + value_bytes), key .. " = " .. value)
        setting_item:add(f.query_setting_key, buffer(offset - key_bytes - value_bytes, key_bytes), key)
        setting_item:add(f.query_setting_value, buffer(offset, value_bytes), value)
        offset = offset + value_bytes
    end

    local params_count, params_count_bytes = read_uvarint(buffer, offset)
    if not params_count then return 0 end
    local params_subtree = subtree:add(buffer(offset, params_count_bytes), "Parameters: " .. params_count .. " items")
    offset = offset + params_count_bytes

    for i = 1, params_count do
        local name, name_bytes = read_ch_string(buffer, offset)
        if not name then break end
        offset = offset + name_bytes

        local value_len, value_len_bytes = read_uvarint(buffer, offset)
        if not value_len then break end
        offset = offset + value_len_bytes

        if offset + value_len <= buffer:len() then
            local value_subtree = params_subtree:add(buffer(offset - name_bytes - value_len_bytes - value_len, name_bytes + value_len_bytes + value_len), "Parameter: " .. name)
            value_subtree:add(f.query_param_name, buffer(offset - name_bytes - value_len_bytes - value_len, name_bytes), name)
            value_subtree:add(f.query_param_value, buffer(offset, value_len))
            offset = offset + value_len
        end
    end

    return offset - initial_offset
end

-- Data (Client)
dissectors.client[2] = function(buffer, offset, subtree)
    local initial_offset = offset

    local table_name, table_name_bytes = read_ch_string(buffer, offset)
    if not table_name then return 0 end
    subtree:add(f.data_table_name, buffer(offset, table_name_bytes), table_name)
    offset = offset + table_name_bytes

    return dissect_data_block(buffer, offset, subtree)
end

-- Cancel (Client)
dissectors.client[3] = function(buffer, offset, subtree)
    return 0
end

-- Ping (Client)
dissectors.client[4] = function(buffer, offset, subtree)
    return 0
end

-- TableStatus (Client)
dissectors.client[5] = function(buffer, offset, subtree)
    local initial_offset = offset

    local table_name, table_name_bytes = read_ch_string(buffer, offset)
    if not table_name then return 0 end
    subtree:add(f.table_status_name, buffer(offset, table_name_bytes), table_name)
    offset = offset + table_name_bytes

    return offset - initial_offset
end

--------------------------------------------------------------------------------
-- Server Packet Dissectors
--------------------------------------------------------------------------------

-- Data (Server)
dissectors.server[1] = function(buffer, offset, subtree)
    return dissect_data_block(buffer, offset, subtree)
end

-- Exception (Server)
dissectors.server[2] = function(buffer, offset, subtree)
    local initial_offset = offset

    local code, code_bytes = read_int32(buffer, offset)
    if not code then return 0 end
    subtree:add(f.exception_code, buffer(offset, code_bytes), code)
    offset = offset + code_bytes

    local name, name_bytes = read_ch_string(buffer, offset)
    if not name then return 0 end
    subtree:add(f.exception_name, buffer(offset, name_bytes), name)
    offset = offset + name_bytes

    local message, message_bytes = read_ch_string(buffer, offset)
    if not message then return 0 end
    subtree:add(f.exception_message, buffer(offset, message_bytes), message)
    offset = offset + message_bytes

    local stack_trace, stack_trace_bytes = read_ch_string(buffer, offset)
    if not stack_trace then return 0 end
    subtree:add(f.exception_stack_trace, buffer(offset, stack_trace_bytes), stack_trace)
    offset = offset + stack_trace_bytes

    local nested_count, nested_count_bytes = read_uvarint(buffer, offset)
    if nested_count then
        subtree:add(f.exception_nested_count, buffer(offset, nested_count_bytes), nested_count)
        offset = offset + nested_count_bytes

        for i = 1, nested_count do
            local nested_subtree = subtree:add(buffer(offset), "Nested Exception " .. i)
            local nested_len = dissectors.server[2](buffer, offset, nested_subtree)
            if nested_len == 0 then break end
            offset = offset + nested_len
        end
    end

    return offset - initial_offset
end

-- Progress (Server)
dissectors.server[3] = function(buffer, offset, subtree)
    local initial_offset = offset

    local rows, rows_bytes = read_uint64(buffer, offset)
    if not rows then return 0 end
    subtree:add(f.progress_rows, buffer(offset, rows_bytes), rows)
    offset = offset + rows_bytes

    local bytes, bytes_bytes = read_uint64(buffer, offset)
    if not bytes then return 0 end
    subtree:add(f.progress_bytes, buffer(offset, bytes_bytes), bytes)
    offset = offset + bytes_bytes

    local total_rows, total_rows_bytes = read_uint64(buffer, offset)
    if not total_rows then return 0 end
    subtree:add(f.progress_total_rows, buffer(offset, total_rows_bytes), total_rows)
    offset = offset + total_rows_bytes

    local total_bytes, total_bytes_bytes = read_uint64(buffer, offset)
    if not total_bytes then return 0 end
    subtree:add(f.progress_total_bytes, buffer(offset, total_bytes_bytes), total_bytes)
    offset = offset + total_bytes_bytes

    local write_rows, write_rows_bytes = read_uint64(buffer, offset)
    if not write_rows then return 0 end
    subtree:add(f.progress_write_rows, buffer(offset, write_rows_bytes), write_rows)
    offset = offset + write_rows_bytes

    local write_bytes, write_bytes_bytes = read_uint64(buffer, offset)
    if not write_bytes then return 0 end
    subtree:add(f.progress_write_bytes, buffer(offset, write_bytes_bytes), write_bytes)
    offset = offset + write_bytes_bytes

    local elapsed, elapsed_bytes = read_double(buffer, offset)
    if elapsed then
        subtree:add(f.progress_elapsed, buffer(offset, elapsed_bytes), elapsed)
        offset = offset + elapsed_bytes
    end

    return offset - initial_offset
end

-- Pong (Server)
dissectors.server[4] = function(buffer, offset, subtree)
    return 0
end

-- EndOfStream (Server)
dissectors.server[5] = function(buffer, offset, subtree)
    return 0
end

-- ProfileInfo (Server)
dissectors.server[6] = function(buffer, offset, subtree)
    local initial_offset = offset

    local rows, rows_bytes = read_uint64(buffer, offset)
    if not rows then return 0 end
    subtree:add(f.profile_info_rows, buffer(offset, rows_bytes), rows)
    offset = offset + rows_bytes

    local bytes, bytes_bytes = read_uint64(buffer, offset)
    if not bytes then return 0 end
    subtree:add(f.profile_info_bytes, buffer(offset, bytes_bytes), bytes)
    offset = offset + bytes_bytes

    local blocks, blocks_bytes = read_uint64(buffer, offset)
    if not blocks then return 0 end
    subtree:add(f.profile_info_blocks, buffer(offset, blocks_bytes), blocks)
    offset = offset + blocks_bytes

    local applied_limit, applied_limit_bytes = read_bool(buffer, offset)
    if applied_limit == nil then return 0 end
    subtree:add(f.profile_info_applied_limit, buffer(offset, applied_limit_bytes), applied_limit)
    offset = offset + applied_limit_bytes

    local rows_before_limit, rows_before_limit_bytes = read_uint64(buffer, offset)
    if not rows_before_limit then return 0 end
    subtree:add(f.profile_info_rows_before_limit, buffer(offset, rows_before_limit_bytes), rows_before_limit)
    offset = offset + rows_before_limit_bytes

    local calculated_rows_before_limit, calc_bytes = read_bool(buffer, offset)
    if calculated_rows_before_limit == nil then return 0 end
    subtree:add(f.profile_info_calculated_rows_before_limit, buffer(offset, calc_bytes), calculated_rows_before_limit)
    offset = offset + calc_bytes

    return offset - initial_offset
end

-- Totals (Server)
dissectors.server[7] = function(buffer, offset, subtree)
    return dissect_data_block(buffer, offset, subtree)
end

-- Extremes (Server)
dissectors.server[8] = function(buffer, offset, subtree)
    local initial_offset = offset

    local extremes_subtree = subtree:add(buffer(offset), "Extremes")
    
    local min_block = extremes_subtree:add(buffer(offset), "Min Block")
    local min_len = dissect_data_block(buffer, offset, min_block)
    if min_len == 0 then return 0 end
    offset = offset + min_len

    local max_block = extremes_subtree:add(buffer(offset), "Max Block")
    local max_len = dissect_data_block(buffer, offset, max_block)
    if max_len == 0 then return 0 end
    offset = offset + max_len

    return offset - initial_offset
end

-- Log (Server)
dissectors.server[10] = function(buffer, offset, subtree)
    local initial_offset = offset

    local time, time_bytes = read_uint64(buffer, offset)
    if not time then return 0 end
    subtree:add(f.log_time, buffer(offset, time_bytes), time)
    offset = offset + time_bytes

    local timezone, timezone_bytes = read_ch_string(buffer, offset)
    if not timezone then return 0 end
    subtree:add(f.log_timezone, buffer(offset, timezone_bytes), timezone)
    offset = offset + timezone_bytes

    local level, level_bytes = read_ch_string(buffer, offset)
    if not level then return 0 end
    subtree:add(f.log_level, buffer(offset, level_bytes), level)
    offset = offset + level_bytes

    local source, source_bytes = read_ch_string(buffer, offset)
    if not source then return 0 end
    subtree:add(f.log_source, buffer(offset, source_bytes), source)
    offset = offset + source_bytes

    local message, message_bytes = read_ch_string(buffer, offset)
    if not message then return 0 end
    subtree:add(f.log_message, buffer(offset, message_bytes), message)
    offset = offset + message_bytes

    return offset - initial_offset
end

--------------------------------------------------------------------------------
-- Helper: Dissect Data Block
--------------------------------------------------------------------------------
function dissect_data_block(buffer, offset, subtree)
    local initial_offset = offset

    local block_info_subtree = subtree:add(buffer(offset), "Block Info")
    
    local min_index, min_index_bytes = read_int64(buffer, offset)
    if not min_index then return 0 end
    block_info_subtree:add(f.block_info_min_index, buffer(offset, min_index_bytes), min_index)
    offset = offset + min_index_bytes

    local max_index, max_index_bytes = read_int64(buffer, offset)
    if not max_index then return 0 end
    block_info_subtree:add(f.block_info_max_index, buffer(offset, max_index_bytes), max_index)
    offset = offset + max_index_bytes

    local is_overflows, is_overflows_bytes = read_bool(buffer, offset)
    if is_overflows == nil then return 0 end
    block_info_subtree:add(f.block_info_is_overflows, buffer(offset, is_overflows_bytes), is_overflows)
    offset = offset + is_overflows_bytes

    local bucket_num, bucket_num_bytes = read_int32(buffer, offset)
    if not bucket_num then return 0 end
    block_info_subtree:add(f.block_info_bucket_num, buffer(offset, bucket_num_bytes), bucket_num)
    offset = offset + bucket_num_bytes

    local has_all_columns, has_all_columns_bytes = read_bool(buffer, offset)
    if has_all_columns == nil then return 0 end
    block_info_subtree:add(f.block_info_has_all_columns, buffer(offset, has_all_columns_bytes), has_all_columns)
    offset = offset + has_all_columns_bytes

    local num_columns, num_columns_bytes = read_uvarint(buffer, offset)
    if not num_columns then return 0 end
    subtree:add(f.data_block_info_num_columns, buffer(offset, num_columns_bytes), num_columns)
    offset = offset + num_columns_bytes

    local num_rows, num_rows_bytes = read_uvarint(buffer, offset)
    if not num_rows then return 0 end
    subtree:add(f.data_block_info_num_rows, buffer(offset, num_rows_bytes), num_rows)
    offset = offset + num_rows_bytes

    for i = 1, num_columns do
        local col_name, col_name_bytes = read_ch_string(buffer, offset)
        if not col_name then break end
        offset = offset + col_name_bytes

        local col_type, col_type_bytes = read_ch_string(buffer, offset)
        if not col_type then break end
        offset = offset + col_type_bytes

        local col_size, col_size_bytes = read_uint64(buffer, offset)
        if not col_size then break end
        offset = offset + col_size_bytes

        local column_subtree = subtree:add(buffer(offset - col_name_bytes - col_type_bytes - col_size_bytes - col_size, 
            col_name_bytes + col_type_bytes + col_size_bytes + col_size), "Column: " .. col_name .. " (" .. col_type .. ")")
        column_subtree:add(f.data_column_name, buffer(offset - col_name_bytes - col_type_bytes - col_size_bytes - col_size, col_name_bytes), col_name)
        column_subtree:add(f.data_column_type, buffer(offset - col_type_bytes - col_size_bytes - col_size, col_type_bytes), col_type)
        column_subtree:add(f.data_column_size, buffer(offset - col_size_bytes - col_size, col_size_bytes), col_size)

        offset = offset + col_size
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

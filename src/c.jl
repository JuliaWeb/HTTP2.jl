@enum aws_io_errors::UInt32 begin
    AWS_IO_CHANNEL_ERROR_ERROR_CANT_ACCEPT_INPUT = 1024
    AWS_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE = 1025
    AWS_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW = 1026
    AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED = 1027
    AWS_IO_EVENT_LOOP_SHUTDOWN = 1028
    AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE = 1029
    AWS_IO_TLS_ERROR_NOT_NEGOTIATED = 1030
    AWS_IO_TLS_ERROR_WRITE_FAILURE = 1031
    AWS_IO_TLS_ERROR_ALERT_RECEIVED = 1032
    AWS_IO_TLS_CTX_ERROR = 1033
    AWS_IO_TLS_VERSION_UNSUPPORTED = 1034
    AWS_IO_TLS_CIPHER_PREF_UNSUPPORTED = 1035
    AWS_IO_MISSING_ALPN_MESSAGE = 1036
    AWS_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE = 1037
    AWS_IO_FILE_VALIDATION_FAILURE = 1038
    AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY = 1039
    AWS_ERROR_IO_ALREADY_SUBSCRIBED = 1040
    AWS_ERROR_IO_NOT_SUBSCRIBED = 1041
    AWS_ERROR_IO_OPERATION_CANCELLED = 1042
    AWS_IO_READ_WOULD_BLOCK = 1043
    AWS_IO_BROKEN_PIPE = 1044
    AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY = 1045
    AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE = 1046
    AWS_IO_SOCKET_CONNECTION_REFUSED = 1047
    AWS_IO_SOCKET_TIMEOUT = 1048
    AWS_IO_SOCKET_NO_ROUTE_TO_HOST = 1049
    AWS_IO_SOCKET_NETWORK_DOWN = 1050
    AWS_IO_SOCKET_CLOSED = 1051
    AWS_IO_SOCKET_NOT_CONNECTED = 1052
    AWS_IO_SOCKET_INVALID_OPTIONS = 1053
    AWS_IO_SOCKET_ADDRESS_IN_USE = 1054
    AWS_IO_SOCKET_INVALID_ADDRESS = 1055
    AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE = 1056
    AWS_IO_SOCKET_CONNECT_ABORTED = 1057
    AWS_IO_DNS_QUERY_FAILED = 1058
    AWS_IO_DNS_INVALID_NAME = 1059
    AWS_IO_DNS_NO_ADDRESS_FOR_HOST = 1060
    AWS_IO_DNS_HOST_REMOVED_FROM_CACHE = 1061
    AWS_IO_STREAM_INVALID_SEEK_POSITION = 1062
    AWS_IO_STREAM_READ_FAILED = 1063
    DEPRECATED_AWS_IO_INVALID_FILE_HANDLE = 1064
    AWS_IO_SHARED_LIBRARY_LOAD_FAILURE = 1065
    AWS_IO_SHARED_LIBRARY_FIND_SYMBOL_FAILURE = 1066
    AWS_IO_TLS_NEGOTIATION_TIMEOUT = 1067
    AWS_IO_TLS_ALERT_NOT_GRACEFUL = 1068
    AWS_IO_MAX_RETRIES_EXCEEDED = 1069
    AWS_IO_RETRY_PERMISSION_DENIED = 1070
    AWS_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED = 1071
    AWS_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED = 1072
    AWS_ERROR_PKCS11_VERSION_UNSUPPORTED = 1073
    AWS_ERROR_PKCS11_TOKEN_NOT_FOUND = 1074
    AWS_ERROR_PKCS11_KEY_NOT_FOUND = 1075
    AWS_ERROR_PKCS11_KEY_TYPE_UNSUPPORTED = 1076
    AWS_ERROR_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE = 1077
    AWS_ERROR_PKCS11_CKR_CANCEL = 1078
    AWS_ERROR_PKCS11_CKR_HOST_MEMORY = 1079
    AWS_ERROR_PKCS11_CKR_SLOT_ID_INVALID = 1080
    AWS_ERROR_PKCS11_CKR_GENERAL_ERROR = 1081
    AWS_ERROR_PKCS11_CKR_FUNCTION_FAILED = 1082
    AWS_ERROR_PKCS11_CKR_ARGUMENTS_BAD = 1083
    AWS_ERROR_PKCS11_CKR_NO_EVENT = 1084
    AWS_ERROR_PKCS11_CKR_NEED_TO_CREATE_THREADS = 1085
    AWS_ERROR_PKCS11_CKR_CANT_LOCK = 1086
    AWS_ERROR_PKCS11_CKR_ATTRIBUTE_READ_ONLY = 1087
    AWS_ERROR_PKCS11_CKR_ATTRIBUTE_SENSITIVE = 1088
    AWS_ERROR_PKCS11_CKR_ATTRIBUTE_TYPE_INVALID = 1089
    AWS_ERROR_PKCS11_CKR_ATTRIBUTE_VALUE_INVALID = 1090
    AWS_ERROR_PKCS11_CKR_ACTION_PROHIBITED = 1091
    AWS_ERROR_PKCS11_CKR_DATA_INVALID = 1092
    AWS_ERROR_PKCS11_CKR_DATA_LEN_RANGE = 1093
    AWS_ERROR_PKCS11_CKR_DEVICE_ERROR = 1094
    AWS_ERROR_PKCS11_CKR_DEVICE_MEMORY = 1095
    AWS_ERROR_PKCS11_CKR_DEVICE_REMOVED = 1096
    AWS_ERROR_PKCS11_CKR_ENCRYPTED_DATA_INVALID = 1097
    AWS_ERROR_PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE = 1098
    AWS_ERROR_PKCS11_CKR_FUNCTION_CANCELED = 1099
    AWS_ERROR_PKCS11_CKR_FUNCTION_NOT_PARALLEL = 1100
    AWS_ERROR_PKCS11_CKR_FUNCTION_NOT_SUPPORTED = 1101
    AWS_ERROR_PKCS11_CKR_KEY_HANDLE_INVALID = 1102
    AWS_ERROR_PKCS11_CKR_KEY_SIZE_RANGE = 1103
    AWS_ERROR_PKCS11_CKR_KEY_TYPE_INCONSISTENT = 1104
    AWS_ERROR_PKCS11_CKR_KEY_NOT_NEEDED = 1105
    AWS_ERROR_PKCS11_CKR_KEY_CHANGED = 1106
    AWS_ERROR_PKCS11_CKR_KEY_NEEDED = 1107
    AWS_ERROR_PKCS11_CKR_KEY_INDIGESTIBLE = 1108
    AWS_ERROR_PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED = 1109
    AWS_ERROR_PKCS11_CKR_KEY_NOT_WRAPPABLE = 1110
    AWS_ERROR_PKCS11_CKR_KEY_UNEXTRACTABLE = 1111
    AWS_ERROR_PKCS11_CKR_MECHANISM_INVALID = 1112
    AWS_ERROR_PKCS11_CKR_MECHANISM_PARAM_INVALID = 1113
    AWS_ERROR_PKCS11_CKR_OBJECT_HANDLE_INVALID = 1114
    AWS_ERROR_PKCS11_CKR_OPERATION_ACTIVE = 1115
    AWS_ERROR_PKCS11_CKR_OPERATION_NOT_INITIALIZED = 1116
    AWS_ERROR_PKCS11_CKR_PIN_INCORRECT = 1117
    AWS_ERROR_PKCS11_CKR_PIN_INVALID = 1118
    AWS_ERROR_PKCS11_CKR_PIN_LEN_RANGE = 1119
    AWS_ERROR_PKCS11_CKR_PIN_EXPIRED = 1120
    AWS_ERROR_PKCS11_CKR_PIN_LOCKED = 1121
    AWS_ERROR_PKCS11_CKR_SESSION_CLOSED = 1122
    AWS_ERROR_PKCS11_CKR_SESSION_COUNT = 1123
    AWS_ERROR_PKCS11_CKR_SESSION_HANDLE_INVALID = 1124
    AWS_ERROR_PKCS11_CKR_SESSION_PARALLEL_NOT_SUPPORTED = 1125
    AWS_ERROR_PKCS11_CKR_SESSION_READ_ONLY = 1126
    AWS_ERROR_PKCS11_CKR_SESSION_EXISTS = 1127
    AWS_ERROR_PKCS11_CKR_SESSION_READ_ONLY_EXISTS = 1128
    AWS_ERROR_PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS = 1129
    AWS_ERROR_PKCS11_CKR_SIGNATURE_INVALID = 1130
    AWS_ERROR_PKCS11_CKR_SIGNATURE_LEN_RANGE = 1131
    AWS_ERROR_PKCS11_CKR_TEMPLATE_INCOMPLETE = 1132
    AWS_ERROR_PKCS11_CKR_TEMPLATE_INCONSISTENT = 1133
    AWS_ERROR_PKCS11_CKR_TOKEN_NOT_PRESENT = 1134
    AWS_ERROR_PKCS11_CKR_TOKEN_NOT_RECOGNIZED = 1135
    AWS_ERROR_PKCS11_CKR_TOKEN_WRITE_PROTECTED = 1136
    AWS_ERROR_PKCS11_CKR_UNWRAPPING_KEY_HANDLE_INVALID = 1137
    AWS_ERROR_PKCS11_CKR_UNWRAPPING_KEY_SIZE_RANGE = 1138
    AWS_ERROR_PKCS11_CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 1139
    AWS_ERROR_PKCS11_CKR_USER_ALREADY_LOGGED_IN = 1140
    AWS_ERROR_PKCS11_CKR_USER_NOT_LOGGED_IN = 1141
    AWS_ERROR_PKCS11_CKR_USER_PIN_NOT_INITIALIZED = 1142
    AWS_ERROR_PKCS11_CKR_USER_TYPE_INVALID = 1143
    AWS_ERROR_PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 1144
    AWS_ERROR_PKCS11_CKR_USER_TOO_MANY_TYPES = 1145
    AWS_ERROR_PKCS11_CKR_WRAPPED_KEY_INVALID = 1146
    AWS_ERROR_PKCS11_CKR_WRAPPED_KEY_LEN_RANGE = 1147
    AWS_ERROR_PKCS11_CKR_WRAPPING_KEY_HANDLE_INVALID = 1148
    AWS_ERROR_PKCS11_CKR_WRAPPING_KEY_SIZE_RANGE = 1149
    AWS_ERROR_PKCS11_CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 1150
    AWS_ERROR_PKCS11_CKR_RANDOM_SEED_NOT_SUPPORTED = 1151
    AWS_ERROR_PKCS11_CKR_RANDOM_NO_RNG = 1152
    AWS_ERROR_PKCS11_CKR_DOMAIN_PARAMS_INVALID = 1153
    AWS_ERROR_PKCS11_CKR_CURVE_NOT_SUPPORTED = 1154
    AWS_ERROR_PKCS11_CKR_BUFFER_TOO_SMALL = 1155
    AWS_ERROR_PKCS11_CKR_SAVED_STATE_INVALID = 1156
    AWS_ERROR_PKCS11_CKR_INFORMATION_SENSITIVE = 1157
    AWS_ERROR_PKCS11_CKR_STATE_UNSAVEABLE = 1158
    AWS_ERROR_PKCS11_CKR_CRYPTOKI_NOT_INITIALIZED = 1159
    AWS_ERROR_PKCS11_CKR_CRYPTOKI_ALREADY_INITIALIZED = 1160
    AWS_ERROR_PKCS11_CKR_MUTEX_BAD = 1161
    AWS_ERROR_PKCS11_CKR_MUTEX_NOT_LOCKED = 1162
    AWS_ERROR_PKCS11_CKR_NEW_PIN_MODE = 1163
    AWS_ERROR_PKCS11_CKR_NEXT_OTP = 1164
    AWS_ERROR_PKCS11_CKR_EXCEEDED_MAX_ITERATIONS = 1165
    AWS_ERROR_PKCS11_CKR_FIPS_SELF_TEST_FAILED = 1166
    AWS_ERROR_PKCS11_CKR_LIBRARY_LOAD_FAILED = 1167
    AWS_ERROR_PKCS11_CKR_PIN_TOO_WEAK = 1168
    AWS_ERROR_PKCS11_CKR_PUBLIC_KEY_INVALID = 1169
    AWS_ERROR_PKCS11_CKR_FUNCTION_REJECTED = 1170
    AWS_ERROR_IO_PINNED_EVENT_LOOP_MISMATCH = 1171
    AWS_IO_ERROR_END_RANGE = 2047
    AWS_IO_INVALID_FILE_HANDLE = 50
end

const aws_allocator = Cvoid

function aws_default_allocator()
    ccall((:aws_default_allocator, libawscrt), Ptr{aws_allocator}, ())
end

function aws_mem_calloc(allocator, num, size)
    ccall((:aws_mem_calloc, libawscrt), Ptr{Cvoid}, (Ptr{aws_allocator}, Csize_t, Csize_t), allocator, num, size)
end

function aws_mem_acquire(allocator, size)
    ccall((:aws_mem_acquire, libawscrt), Ptr{Cvoid}, (Ptr{aws_allocator}, Csize_t), allocator, size)
end

function aws_mem_release(allocator, ptr)
    ccall((:aws_mem_release, libawscrt), Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}), allocator, ptr)
end

function aws_last_error()
    ccall((:aws_last_error, libawscrt), Cint, ())
end

function aws_error_debug_str(err)
    ccall((:aws_error_debug_str, libawscrt), Ptr{Cchar}, (Cint,), err)
end

struct AWSError <: Exception
    msg::String
end

aws_error() = AWSError(unsafe_string(aws_error_debug_str(aws_last_error())))
aws_throw_error() = throw(aws_error())

@enum aws_log_level::UInt32 begin
    AWS_LL_NONE = 0
    AWS_LL_FATAL = 1
    AWS_LL_ERROR = 2
    AWS_LL_WARN = 3
    AWS_LL_INFO = 4
    AWS_LL_DEBUG = 5
    AWS_LL_TRACE = 6
    AWS_LL_COUNT = 7
end

const aws_logger = Cvoid

mutable struct aws_logger_standard_options
    level::aws_log_level
    filename::Ptr{Cchar}
    file::Libc.FILE
end

aws_logger_standard_options(level, file) = aws_logger_standard_options(aws_log_level(level), C_NULL, file)

function aws_logger_set_log_level(logger, level)
    ccall((:aws_logger_set_log_level, libawscrt), Cint, (Ptr{aws_logger}, aws_log_level), logger, level)
end

function aws_logger_init_standard(logger, allocator, options)
    ccall((:aws_logger_init_standard, libawscrt), Cint, (Ptr{aws_logger}, Ptr{aws_allocator}, Ref{aws_logger_standard_options}), logger, allocator, options)
end

function aws_logger_set(logger)
    ccall((:aws_logger_set, libawscrt), Cvoid, (Ptr{aws_logger},), logger)
end

function aws_http_library_init(alloc)
    ccall((:aws_http_library_init, libawscrt), Cvoid, (Ptr{aws_allocator},), alloc)
end

struct aws_byte_cursor
    len::Csize_t
    ptr::Ptr{UInt8}
end

aws_byte_cursor() = aws_byte_cursor(0, C_NULL)
Base.String(cursor::aws_byte_cursor) = cursor.ptr == C_NULL ? "" : unsafe_string(cursor.ptr, cursor.len)

function aws_byte_cursor_from_c_str(c_str)
    ccall((:aws_byte_cursor_from_c_str, libawscrt), aws_byte_cursor, (Ptr{Cchar},), c_str)
end

Base.convert(::Type{aws_byte_cursor}, x::Union{aws_byte_cursor, AbstractString}) = x isa aws_byte_cursor ? x : aws_byte_cursor_from_c_str(x)

function aws_byte_cursor_from_array(bytes, len)
    ccall((:aws_byte_cursor_from_array, libawscrt), aws_byte_cursor, (Ptr{Cvoid}, Csize_t), bytes, len)
end

function aws_byte_cursor_eq(a, b)
    ccall((:aws_byte_cursor_eq, libawscrt), Bool, (Ptr{aws_byte_cursor}, Ptr{aws_byte_cursor}), a, b)
end

function aws_byte_cursor_eq_c_str_ignore_case(cursor, c_str)
    ccall((:aws_byte_cursor_eq_c_str_ignore_case, libawscrt), Bool, (Ref{aws_byte_cursor}, Ptr{Cchar}), cursor, c_str)
end

function aws_byte_cursor_eq_ignore_case(a, b)
    ccall((:aws_byte_cursor_eq_ignore_case, libawscrt), Bool, (Ref{aws_byte_cursor}, Ref{aws_byte_cursor}), a, b)
end

Base.isempty(cursor::aws_byte_cursor) = cursor.len == 0

function aws_hash_byte_cursor_ptr_ignore_case(item)
    ccall((:aws_hash_byte_cursor_ptr_ignore_case, libawscrt), UInt64, (Ref{aws_byte_cursor},), item)
end

Base.hash(cursor::aws_byte_cursor, h::UInt64) = aws_hash_byte_cursor_ptr_ignore_case(cursor)

const aws_input_stream = Cvoid

function aws_input_stream_new_from_cursor(allocator, cursor)
    ccall((:aws_input_stream_new_from_cursor, libawscrt), Ptr{aws_input_stream}, (Ptr{aws_allocator}, Ref{aws_byte_cursor}), allocator, cursor)
end

function aws_input_stream_new_from_open_file(allocator, file)
    ccall((:aws_input_stream_new_from_open_file, libawscrt), Ptr{aws_input_stream}, (Ptr{aws_allocator}, Ptr{Libc.FILE}), allocator, file)
end

function aws_input_stream_get_length(stream, out_length)
    ccall((:aws_input_stream_get_length, libawscrt), Cint, (Ptr{aws_input_stream}, Ptr{Int64}), stream, out_length)
end

function aws_input_stream_destroy(stream)
    ccall((:aws_input_stream_destroy, libawscrt), Cvoid, (Ptr{aws_input_stream},), stream)
end

struct aws_byte_buf
    len::Csize_t
    buffer::Ptr{UInt8}
    capacity::Csize_t
    allocator::Ptr{aws_allocator}
end

aws_byte_buf() = aws_byte_buf(0, C_NULL, 0, C_NULL)

mutable struct aws_uri
    self_size::Csize_t
    allocator::Ptr{aws_allocator}
    uri_str::aws_byte_buf
    scheme::aws_byte_cursor
    authority::aws_byte_cursor
    userinfo::aws_byte_cursor
    user::aws_byte_cursor
    password::aws_byte_cursor
    host_name::aws_byte_cursor
    port::UInt16
    path::aws_byte_cursor
    query_string::aws_byte_cursor
    path_and_query::aws_byte_cursor

    function aws_uri(url, allocator=ALLOCATOR[])
        uri_cursor = aws_byte_cursor_from_c_str(string(url))
        uri = new()
        aws_uri_init_parse(uri, allocator, uri_cursor) != 0 && aws_error()
        if uri.port == 0 && aws_byte_cursor_eq_c_str_ignore_case(uri.scheme, "http")
            uri.port = 80
        elseif uri.port == 0 && aws_byte_cursor_eq_c_str_ignore_case(uri.scheme, "https")
            uri.port = 443
        end
        finalizer(aws_uri_clean_up, uri)
        return uri
    end
    aws_uri() = new()
end

function URIs.URI(url::aws_uri)
    return URI(;
        scheme=String(url.scheme),
        userinfo=String(url.userinfo),
        host=String(url.host_name),
        port=string(url.port),
        path=String(url.path),
        query=String(url.query_string),
        fragment=String(url.path_and_query),
    )
end

function aws_uri_init_parse(uri, allocator, uri_str)
    ccall((:aws_uri_init_parse, libawscrt), Cint, (Ref{aws_uri}, Ptr{aws_allocator}, Ref{aws_byte_cursor}), uri, allocator, uri_str)
end

function aws_uri_clean_up(uri)
    ccall((:aws_uri_clean_up, libawscrt), Cvoid, (Ref{aws_uri},), uri)
end

const aws_event_loop_group = Cvoid

function aws_event_loop_group_new_default(alloc, max_threads, shutdown_options)
    ccall((:aws_event_loop_group_new_default, libawscrt), Ptr{aws_event_loop_group}, (Ptr{aws_allocator}, UInt16, Ptr{Cvoid}), alloc, max_threads, shutdown_options)
end

const aws_shutdown_callback_options = Cvoid

mutable struct aws_host_resolver_default_options
    max_entries::Csize_t
    el_group::Ptr{aws_event_loop_group}
    shutdown_options::Ptr{aws_shutdown_callback_options}
    system_clock_override_fn::Ptr{Cvoid}
end

const aws_host_resolver = Cvoid

function aws_host_resolver_new_default(allocator, options)
    ccall((:aws_host_resolver_new_default, libawscrt), Ptr{aws_host_resolver}, (Ptr{aws_allocator}, Ref{aws_host_resolver_default_options}), allocator, options)
end

struct aws_client_bootstrap_options
    event_loop_group::Ptr{aws_event_loop_group}
    host_resolver::Ptr{aws_host_resolver}
    host_resolution_config::Ptr{Cvoid} # Ptr{aws_host_resolution_config}
    on_shutdown_complete::Ptr{Cvoid}
    user_data::Ptr{Cvoid}
end

const aws_client_bootstrap = Cvoid

function aws_client_bootstrap_new(allocator, options)
    ccall((:aws_client_bootstrap_new, libawscrt), Ptr{aws_client_bootstrap}, (Ptr{aws_allocator}, Ref{aws_client_bootstrap_options}), allocator, options)
end

@enum aws_socket_type::UInt32 begin
    AWS_SOCKET_STREAM = 0
    AWS_SOCKET_DGRAM = 1
end

@enum aws_socket_domain::UInt32 begin
    AWS_SOCKET_IPV4 = 0
    AWS_SOCKET_IPV6 = 1
    AWS_SOCKET_LOCAL = 2
    AWS_SOCKET_VSOCK = 3
end

mutable struct aws_socket_options
    type::aws_socket_type
    domain::aws_socket_domain
    connect_timeout_ms::UInt32
    keep_alive_interval_sec::UInt16
    keep_alive_timeout_sec::UInt16
    keep_alive_max_failed_probes::UInt16
    keepalive::Bool
end

struct aws_string
    allocator::Ptr{aws_allocator}
    len::Csize_t
    bytes::NTuple{1, UInt8}
end

const aws_tls_ctx_options = Cvoid
const aws_tls_ctx = Cvoid

const aws_tls_connection_options = Cvoid

function aws_tls_connection_options_init_from_ctx(conn_options, ctx)
    ccall((:aws_tls_connection_options_init_from_ctx, libawscrt), Cvoid, (Ref{aws_tls_connection_options}, Ptr{aws_tls_ctx}), conn_options, ctx)
end

function aws_tls_client_ctx_new(alloc, options)
    ccall((:aws_tls_client_ctx_new, libawscrt), Ptr{aws_tls_ctx}, (Ptr{aws_allocator}, Ptr{aws_tls_ctx_options}), alloc, options)
end

function aws_tls_ctx_options_init_client_mtls_from_path(options, allocator, cert_path, pkey_path)
    ccall((:aws_tls_ctx_options_init_client_mtls_from_path, libawscrt), Cint, (Ptr{aws_tls_ctx_options}, Ptr{aws_allocator}, Ptr{Cchar}, Ptr{Cchar}), options, allocator, cert_path, pkey_path)
end

function aws_tls_ctx_options_init_client_mtls_from_system_path(options, allocator, cert_reg_path)
    ccall((:aws_tls_ctx_options_init_client_mtls_from_system_path, libawscrt), Cint, (Ptr{aws_tls_ctx_options}, Ptr{aws_allocator}, Ptr{Cchar}), options, allocator, cert_reg_path)
end

function aws_tls_ctx_options_override_default_trust_store_from_path(options, ca_path, ca_file)
    ccall((:aws_tls_ctx_options_override_default_trust_store_from_path, libawscrt), Cint, (Ptr{aws_tls_ctx_options}, Ptr{Cchar}, Ptr{Cchar}), options, ca_path, ca_file)
end

function aws_tls_ctx_options_init_default_client(options, allocator)
    ccall((:aws_tls_ctx_options_init_default_client, libawscrt), Cvoid, (Ptr{aws_tls_ctx_options}, Ptr{aws_allocator}), options, allocator)
end

function aws_tls_ctx_options_set_alpn_list(options, alpn_list)
    ccall((:aws_tls_ctx_options_set_alpn_list, libawscrt), Cint, (Ptr{aws_tls_ctx_options}, Ptr{Cchar}), options, alpn_list)
end

function aws_tls_ctx_options_set_verify_peer(options, verify_peer)
    ccall((:aws_tls_ctx_options_set_verify_peer, libawscrt), Cvoid, (Ptr{aws_tls_ctx_options}, Bool), options, verify_peer)
end

function aws_tls_connection_options_set_server_name(conn_options, allocator, server_name)
    ccall((:aws_tls_connection_options_set_server_name, libawscrt), Cint, (Ptr{aws_tls_connection_options}, Ptr{aws_allocator}, Ref{aws_byte_cursor}), conn_options, allocator, server_name)
end

function aws_tls_connection_options_clean_up(connection_options)
    ccall((:aws_tls_connection_options_clean_up, libawscrt), Cvoid, (Ref{aws_tls_connection_options},), connection_options)
end

function aws_tls_ctx_release(ctx)
    ccall((:aws_tls_ctx_release, libawscrt), Cvoid, (Ptr{aws_tls_ctx},), ctx)
end

function aws_tls_ctx_options_clean_up(options)
    ccall((:aws_tls_ctx_options_clean_up, libawscrt), Cvoid, (Ptr{aws_tls_ctx_options},), options)
end

mutable struct aws_http_connection_manager_options
    bootstrap::Ptr{aws_client_bootstrap}
    initial_window_size::Csize_t
    socket_options::aws_socket_options
    tls_connection_options::Ptr{aws_tls_connection_options}
    http2_prior_knowledge::Bool
    monitoring_options::Ptr{Cvoid} # Ptr{aws_http_connection_monitoring_options}
    host::aws_byte_cursor
    port::UInt16
    initial_settings_array::Ptr{Cvoid} # Ptr{aws_http2_setting}
    num_initial_settings::Csize_t
    max_closed_streams::Csize_t
    http2_conn_manual_window_management::Bool
    proxy_options::Ptr{Cvoid} # Ptr{aws_http_proxy_options}
    proxy_ev_settings::Ptr{Cvoid} # Ptr{proxy_env_var_settings}
    max_connections::Csize_t
    shutdown_complete_user_data::Ptr{Cvoid}
    shutdown_complete_callback::Ptr{Cvoid}
    enable_read_back_pressure::Bool
    max_connection_idle_in_milliseconds::UInt64
end

function aws_http_connection_manager_options(
    bootstrap::Ptr{aws_client_bootstrap},
    socket_options::aws_socket_options,
    tls_options::Ptr{aws_tls_connection_options},
    host_name::aws_byte_cursor,
    port,
    max_connections,
    max_connection_idle_in_milliseconds
)
    return aws_http_connection_manager_options(
        bootstrap,
        typemax(Csize_t),
        socket_options,
        tls_options,
        false,
        C_NULL, # monitoring_options
        host_name,
        port % UInt16,
        C_NULL,
        0,
        0,
        false,
        C_NULL, # proxy_options
        C_NULL, # proxy_ev_settings
        max_connections,
        C_NULL,
        C_NULL,
        false,
        max_connection_idle_in_milliseconds,
    )
end

const aws_http_connection_manager = Cvoid
const aws_http_connection = Cvoid

function aws_http_connection_manager_new(allocator, options)
    ccall((:aws_http_connection_manager_new, libawscrt), Ptr{aws_http_connection_manager}, (Ptr{aws_allocator}, Ref{aws_http_connection_manager_options}), allocator, options)
end

function aws_http_connection_manager_release(manager)
    ccall((:aws_http_connection_manager_release, libawscrt), Cvoid, (Ptr{aws_http_connection_manager},), manager)
end

function aws_http_connection_manager_acquire_connection(manager, callback, user_data)
    ccall((:aws_http_connection_manager_acquire_connection, libawscrt), Cvoid, (Ptr{aws_http_connection_manager}, Ptr{Cvoid}, Any), manager, callback, user_data)
end

function aws_http_connection_manager_release_connection(manager, connection)
    ccall((:aws_http_connection_manager_release_connection, libawscrt), Cint, (Ptr{aws_http_connection_manager}, Ptr{aws_http_connection}), manager, connection)
end

mutable struct aws_http_client_connection_options
    self_size::Csize_t #
    allocator::Ptr{aws_allocator} #
    bootstrap::Ptr{aws_client_bootstrap} #
    host_name::aws_byte_cursor #
    port::UInt16 #
    socket_options::aws_socket_options
    tls_options::Ptr{aws_tls_connection_options}
    proxy_options::Ptr{Cvoid} # Ptr{aws_http_proxy_options}
    proxy_ev_settings::Ptr{Cvoid} # Ptr{proxy_env_var_settings}
    monitoring_options::Ptr{Cvoid} # Ptr{aws_http_connection_monitoring_options}
    manual_window_management::Bool
    initial_window_size::Csize_t
    user_data::Any
    on_setup::Ptr{Cvoid} #
    on_shutdown::Ptr{Cvoid} #
    prior_knowledge_http2::Bool
    alpn_string_map::Ptr{Cvoid} # Ptr{aws_hash_table}
    http1_options::Ptr{Cvoid} # Ptr{aws_http1_connection_options}
    http2_options::Ptr{Cvoid} # Ptr{aws_http2_connection_options}
    requested_event_loop::Ptr{Cvoid} # Ptr{aws_event_loop_group}
    host_resolution_config::Ptr{Cvoid} # Ptr{aws_host_resolution_config}
end

function aws_http_client_connection_options(
    alloc::Ptr{aws_allocator},
    bootstrap::Ptr{aws_client_bootstrap},
    host_name::aws_byte_cursor,
    port,
    socket_options::aws_socket_options,
    tls_options::Ptr{aws_tls_connection_options},
    ctx::Any
)
return aws_http_client_connection_options(
    1,
    alloc,
    bootstrap,
    host_name,
    port % UInt16,
    socket_options,
    tls_options,
    C_NULL,
    C_NULL,
    C_NULL,
    false,
    typemax(Csize_t),
    ctx,
    on_setup[],
    on_shutdown[],
    false,
    C_NULL,
    C_NULL,
    C_NULL,
    C_NULL,
    C_NULL,
)
end

const aws_http_stream = Cvoid

@enum aws_http_version::UInt32 begin
    AWS_HTTP_VERSION_UNKNOWN = 0
    AWS_HTTP_VERSION_1_0 = 1
    AWS_HTTP_VERSION_1_1 = 2
    AWS_HTTP_VERSION_2 = 3
    AWS_HTTP_VERSION_COUNT = 4
end

function aws_http_connection_get_version(connection)
    ccall((:aws_http_connection_get_version, libawscrt), aws_http_version, (Ptr{aws_http_connection},), connection)
end

function aws_http_stream_release(stream)
    ccall((:aws_http_stream_release, libawscrt), Cvoid, (Ptr{aws_http_stream},), stream)
end

const aws_http_message = Cvoid

function aws_http2_message_new_request(allocator)
    ccall((:aws_http2_message_new_request, libawscrt), Ptr{aws_http_message}, (Ptr{aws_allocator},), allocator)
end

function aws_http_message_new_request(allocator)
    ccall((:aws_http_message_new_request, libawscrt), Ptr{aws_http_message}, (Ptr{aws_allocator},), allocator)
end

@enum aws_http_header_block::UInt32 begin
    AWS_HTTP_HEADER_BLOCK_MAIN = 0
    AWS_HTTP_HEADER_BLOCK_INFORMATIONAL = 1
    AWS_HTTP_HEADER_BLOCK_TRAILING = 2
end

@enum aws_http_header_compression::UInt32 begin
    AWS_HTTP_HEADER_COMPRESSION_USE_CACHE = 0
    AWS_HTTP_HEADER_COMPRESSION_NO_CACHE = 1
    AWS_HTTP_HEADER_COMPRESSION_NO_FORWARD_CACHE = 2
end

struct aws_http_header
    name::aws_byte_cursor
    value::aws_byte_cursor
    compression::aws_http_header_compression
end

function aws_http_stream_get_incoming_response_status(stream, out_status)
    ccall((:aws_http_stream_get_incoming_response_status, libawscrt), Cint, (Ptr{aws_http_stream}, Ptr{Cint}), stream, out_status)
end

function aws_http_message_set_request_method(request_message, method)
    ccall((:aws_http_message_set_request_method, libawscrt), Cint, (Ptr{aws_http_message}, aws_byte_cursor), request_message, method)
end

function aws_http_message_set_request_path(request_message, path)
    ccall((:aws_http_message_set_request_path, libawscrt), Cint, (Ptr{aws_http_message}, aws_byte_cursor), request_message, path)
end

const aws_http_headers = Cvoid

function aws_http_message_get_headers(message)
    ccall((:aws_http_message_get_headers, libawscrt), Ptr{aws_http_headers}, (Ptr{aws_http_message},), message)
end

function aws_http2_headers_set_request_scheme(h2_headers, scheme)
    ccall((:aws_http2_headers_set_request_scheme, libawscrt), Cint, (Ptr{aws_http_headers}, aws_byte_cursor), h2_headers, scheme)
end

function aws_http2_headers_set_request_authority(h2_headers, authority)
    ccall((:aws_http2_headers_set_request_authority, libawscrt), Cint, (Ptr{aws_http_headers}, aws_byte_cursor), h2_headers, authority)
end

function aws_http_message_add_header(message, header)
    ccall((:aws_http_message_add_header, libawscrt), Cint, (Ptr{aws_http_message}, aws_http_header), message, header)
end

function aws_http_message_set_body_stream(message, body_stream)
    ccall((:aws_http_message_set_body_stream, libawscrt), Cvoid, (Ptr{aws_http_message}, Ptr{aws_input_stream}), message, body_stream)
end

mutable struct aws_http_make_request_options
    self_size::Csize_t
    request::Ptr{aws_http_message}
    user_data::Any
    on_response_headers::Ptr{Cvoid}
    on_response_header_block_done::Ptr{Cvoid}
    on_response_body::Ptr{Cvoid}
    on_metrics::Ptr{Cvoid}
    on_complete::Ptr{Cvoid}
    on_destroy::Ptr{Cvoid}
    http2_use_manual_data_writes::Bool
end

function aws_http_make_request_options(request::Ptr{aws_http_message}, ctx::Any)
    return aws_http_make_request_options(
        1,
        request,
        ctx,
        on_response_headers[],
        on_response_header_block_done[],
        on_response_body[],
        on_metrics[],
        on_complete[],
        on_destroy[],
        false,
    )
end

function aws_http_connection_make_request(client_connection, options)
    ccall((:aws_http_connection_make_request, libawscrt), Ptr{aws_http_stream}, (Ptr{aws_http_connection}, Ref{aws_http_make_request_options}), client_connection, options)
end

function aws_http_stream_activate(stream)
    ccall((:aws_http_stream_activate, libawscrt), Cint, (Ptr{aws_http_stream},), stream)
end

function aws_http_connection_release(connection)
    ccall((:aws_http_connection_release, libawscrt), Cvoid, (Ptr{aws_http_connection},), connection)
end

function aws_http_client_connect(options)
    ccall((:aws_http_client_connect, libawscrt), Cint, (Ref{aws_http_client_connection_options},), options)
end

function aws_http_message_release(message)
    ccall((:aws_http_message_release, libawscrt), Ptr{aws_http_message}, (Ptr{aws_http_message},), message)
end

struct aws_uri_param
    key::aws_byte_cursor
    value::aws_byte_cursor
end

mutable struct aws_array_list
    alloc::Ptr{aws_allocator}
    current_size::Csize_t
    length::Csize_t
    item_size::Csize_t
    data::Ptr{Cvoid}
end

# aws_array_list(alloc) = aws_array_list(alloc, 0, 0, 0, C_NULL)

mutable struct aws_uri_builder_options
    scheme::aws_byte_cursor
    path::aws_byte_cursor
    host_name::aws_byte_cursor
    port::UInt16
    query_params::aws_array_list
    query_string::aws_byte_cursor
end

function aws_uri_init_from_builder_options(uri, allocator, options)
    ccall((:aws_uri_init_from_builder_options, libawscrt), Cint, (Ref{aws_uri}, Ptr{aws_allocator}, Ref{aws_uri_builder_options}), uri, allocator, options)
end

function aws_uri_query_string(uri)
    ccall((:aws_uri_query_string, libawscrt), Ptr{aws_byte_cursor}, (Ref{aws_uri},), uri)
end

function aws_array_list_init_static(list, raw_array, item_count, item_size)
    ccall((:aws_array_list_init_static, libawscrt), Cvoid, (Ref{aws_array_list}, Ptr{Cvoid}, Csize_t, Csize_t), list, raw_array, item_count, item_size)
end

function escapeuri(allocator, query_params)
    string_params = [string(k) => string(v) for (k, v) in (query_params isa NamedTuple ? pairs(query_params) : query_params)]
    GC.@preserve string_params begin
        params = [aws_uri_param(aws_byte_cursor_from_c_str(k), aws_byte_cursor_from_c_str(v)) for (k, v) in string_params]
        alist = aws_array_list(allocator, sizeof(params), length(params), sizeof(eltype(params)), pointer(params))
        #TODO: it's annoying we have to build a full builder_options + uri to just get the query string
        # at the end; we could probably do a PR to aws-c-common to expose this functionality directly
        builder_options = aws_uri_builder_options(
            aws_byte_cursor_from_c_str("https"),
            aws_byte_cursor_from_c_str("/"),
            aws_byte_cursor_from_c_str(""),
            0,
            alist,
            aws_byte_cursor_from_c_str(""),
        )
        uri = aws_uri()
        aws_uri_init_from_builder_options(uri, allocator, builder_options) != 0 && aws_throw_error()
        query_string_ptr = aws_uri_query_string(uri)
        query_string = unsafe_load(query_string_ptr)
        qs = unsafe_string(query_string.ptr, query_string.len)
        aws_uri_clean_up(uri)
        return qs
    end
end

function aws_http_headers_has(headers, name)
    ccall((:aws_http_headers_has, libawscrt), Bool, (Ptr{aws_http_headers}, aws_byte_cursor), headers, name)
end

@enum aws_exponential_backoff_jitter_mode::UInt32 begin
    AWS_EXPONENTIAL_BACKOFF_JITTER_DEFAULT = 0
    AWS_EXPONENTIAL_BACKOFF_JITTER_NONE = 1
    AWS_EXPONENTIAL_BACKOFF_JITTER_FULL = 2
    AWS_EXPONENTIAL_BACKOFF_JITTER_DECORRELATED = 3
end

struct aws_exponential_backoff_retry_options
    el_group::Ptr{aws_event_loop_group}
    max_retries::Csize_t
    backoff_scale_factor_ms::UInt32
    max_backoff_secs::UInt32
    jitter_mode::aws_exponential_backoff_jitter_mode
    generate_random::Ptr{Cvoid}
    generate_random_impl::Ptr{Cvoid}
    generate_random_user_data::Ptr{Cvoid}
    shutdown_options::Ptr{Cvoid}
end

mutable struct aws_standard_retry_options
    backoff_retry_options::aws_exponential_backoff_retry_options
    initial_bucket_capacity::Csize_t
end

function aws_standard_retry_options(
    max_retries::Integer,
    backoff_scale_factor_ms::Integer,
    max_backoff_secs::Integer,
    jitter_mode::aws_exponential_backoff_jitter_mode=AWS_EXPONENTIAL_BACKOFF_JITTER_DEFAULT,
    el_group=EVENT_LOOP_GROUP[]
)
    opts = aws_exponential_backoff_retry_options(
        el_group,
        max_retries,
        backoff_scale_factor_ms,
        max_backoff_secs,
        jitter_mode,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
    )
    return aws_standard_retry_options(opts, 0)
end

const aws_retry_strategy = Cvoid

function aws_retry_strategy_new_standard(allocator, config)
    ccall((:aws_retry_strategy_new_standard, libawsio), Ptr{aws_retry_strategy}, (Ptr{aws_allocator}, Ref{aws_standard_retry_options}), allocator, config)
end

function aws_retry_strategy_release(retry_strategy)
    ccall((:aws_retry_strategy_release, libawsio), Cvoid, (Ptr{aws_retry_strategy},), retry_strategy)
end

function aws_retry_strategy_acquire_retry_token(retry_strategy, partition_id, on_acquired, user_data, timeout_ms)
    ccall((:aws_retry_strategy_acquire_retry_token, libawsio), Cint, (Ptr{aws_retry_strategy}, Ref{aws_byte_cursor}, Ptr{Cvoid}, Any, UInt64), retry_strategy, partition_id, on_acquired, user_data, timeout_ms)
end

const aws_retry_token = Cvoid

@enum aws_retry_error_type::UInt32 begin
    AWS_RETRY_ERROR_TYPE_TRANSIENT = 0
    AWS_RETRY_ERROR_TYPE_THROTTLING = 1
    AWS_RETRY_ERROR_TYPE_SERVER_ERROR = 2
    AWS_RETRY_ERROR_TYPE_CLIENT_ERROR = 3
end

function aws_retry_strategy_schedule_retry(token, error_type, retry_ready, user_data)
    ccall((:aws_retry_strategy_schedule_retry, libawsio), Cint, (Ptr{aws_retry_token}, aws_retry_error_type, Ptr{Cvoid}, Any), token, error_type, retry_ready, user_data)
end

function aws_retry_token_record_success(token)
    ccall((:aws_retry_token_record_success, libawsio), Cint, (Ptr{aws_retry_token},), token)
end

function aws_retry_token_acquire(token)
    ccall((:aws_retry_token_acquire, libawsio), Cvoid, (Ptr{aws_retry_token},), token)
end

function aws_retry_token_release(token)
    ccall((:aws_retry_token_release, libawsio), Cvoid, (Ptr{aws_retry_token},), token)
end


const aws_allocator = Cvoid

function aws_default_allocator()
    ccall((:aws_default_allocator, libaws_c_common), Ptr{aws_allocator}, ())
end

function aws_mem_calloc(allocator, num, size)
    ccall((:aws_mem_calloc, libaws_c_common), Ptr{Cvoid}, (Ptr{aws_allocator}, Csize_t, Csize_t), allocator, num, size)
end

function aws_mem_acquire(allocator, size)
    ccall((:aws_mem_acquire, libaws_c_common), Ptr{Cvoid}, (Ptr{aws_allocator}, Csize_t), allocator, size)
end

function aws_mem_release(allocator, ptr)
    ccall((:aws_mem_release, libaws_c_common), Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}), allocator, ptr)
end

function aws_last_error()
    ccall((:aws_last_error, libaws_c_common), Cint, ())
end

function aws_error_debug_str(err)
    ccall((:aws_error_debug_str, libaws_c_common), Ptr{Cchar}, (Cint,), err)
end



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
    ccall((:aws_logger_set_log_level, libaws_c_common), Cint, (Ptr{aws_logger}, aws_log_level), logger, level)
end

function aws_logger_init_standard(logger, allocator, options)
    ccall((:aws_logger_init_standard, libaws_c_common), Cint, (Ptr{aws_logger}, Ptr{aws_allocator}, Ref{aws_logger_standard_options}), logger, allocator, options)
end

function aws_logger_set(logger)
    ccall((:aws_logger_set, libaws_c_common), Cvoid, (Ptr{aws_logger},), logger)
end

function aws_http_library_init(alloc)
    ccall((:aws_http_library_init, libaws_c_http), Cvoid, (Ptr{aws_allocator},), alloc)
end

struct aws_byte_cursor
    len::Csize_t
    ptr::Ptr{UInt8}
end

aws_byte_cursor() = aws_byte_cursor(0, C_NULL)
Base.String(cursor::aws_byte_cursor) = cursor.ptr == C_NULL ? "" : unsafe_string(cursor.ptr, cursor.len)

function aws_byte_cursor_from_c_str(c_str)
    ccall((:aws_byte_cursor_from_c_str, libaws_c_common), aws_byte_cursor, (Ptr{Cchar},), c_str)
end

Base.convert(::Type{aws_byte_cursor}, x::Union{aws_byte_cursor, AbstractString}) = x isa aws_byte_cursor ? x : aws_byte_cursor_from_c_str(x)

function aws_byte_cursor_from_array(bytes, len)
    ccall((:aws_byte_cursor_from_array, libaws_c_common), aws_byte_cursor, (Ptr{Cvoid}, Csize_t), bytes, len)
end

function aws_byte_cursor_eq(a, b)
    ccall((:aws_byte_cursor_eq, libaws_c_common), Bool, (Ptr{aws_byte_cursor}, Ptr{aws_byte_cursor}), a, b)
end

function aws_byte_cursor_eq_c_str_ignore_case(cursor, c_str)
    ccall((:aws_byte_cursor_eq_c_str_ignore_case, libaws_c_common), Bool, (Ref{aws_byte_cursor}, Ptr{Cchar}), cursor, c_str)
end

function aws_byte_cursor_eq_ignore_case(a, b)
    ccall((:aws_byte_cursor_eq_ignore_case, libaws_c_common), Bool, (Ref{aws_byte_cursor}, Ref{aws_byte_cursor}), a, b)
end

Base.isempty(cursor::aws_byte_cursor) = cursor.len == 0

function aws_hash_byte_cursor_ptr_ignore_case(item)
    ccall((:aws_hash_byte_cursor_ptr_ignore_case, libaws_c_common), UInt64, (Ref{aws_byte_cursor},), item)
end

Base.hash(cursor::aws_byte_cursor, h::UInt64) = aws_hash_byte_cursor_ptr_ignore_case(cursor)

const aws_input_stream = Cvoid

function aws_input_stream_new_from_cursor(allocator, cursor)
    ccall((:aws_input_stream_new_from_cursor, libaws_c_io), Ptr{aws_input_stream}, (Ptr{aws_allocator}, Ref{aws_byte_cursor}), allocator, cursor)
end

function aws_input_stream_new_from_open_file(allocator, file)
    ccall((:aws_input_stream_new_from_open_file, libaws_c_io), Ptr{aws_input_stream}, (Ptr{aws_allocator}, Ptr{Libc.FILE}), allocator, file)
end

function aws_input_stream_get_length(stream, out_length)
    ccall((:aws_input_stream_get_length, libaws_c_io), Cint, (Ptr{aws_input_stream}, Ptr{Int64}), stream, out_length)
end

function aws_input_stream_destroy(stream)
    ccall((:aws_input_stream_destroy, libaws_c_io), Cvoid, (Ptr{aws_input_stream},), stream)
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
    sch = String(url.scheme)
    ui = String(url.userinfo)
    q = String(url.query_string)
    return URI(;
        scheme=sch,
        userinfo=ui == "" ? URIs.absent : ui,
        host=String(url.host_name),
        port=sch == "https" && url.port == 443 ? URIs.absent : url.port == 80 ? URIs.absent : string(url.port),
        path=String(url.path),
        query=q == "" ? URIs.absent : q,
    )
end

function aws_uri_init_parse(uri, allocator, uri_str)
    ccall((:aws_uri_init_parse, libaws_c_common), Cint, (Ref{aws_uri}, Ptr{aws_allocator}, Ref{aws_byte_cursor}), uri, allocator, uri_str)
end

function aws_uri_clean_up(uri)
    ccall((:aws_uri_clean_up, libaws_c_common), Cvoid, (Ref{aws_uri},), uri)
end

const aws_event_loop_group = Cvoid

function aws_event_loop_group_new_default(alloc, max_threads, shutdown_options)
    ccall((:aws_event_loop_group_new_default, libaws_c_io), Ptr{aws_event_loop_group}, (Ptr{aws_allocator}, UInt16, Ptr{Cvoid}), alloc, max_threads, shutdown_options)
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
    ccall((:aws_host_resolver_new_default, libaws_c_io), Ptr{aws_host_resolver}, (Ptr{aws_allocator}, Ref{aws_host_resolver_default_options}), allocator, options)
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
    ccall((:aws_client_bootstrap_new, libaws_c_io), Ptr{aws_client_bootstrap}, (Ptr{aws_allocator}, Ref{aws_client_bootstrap_options}), allocator, options)
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
    ccall((:aws_tls_connection_options_init_from_ctx, libaws_c_io), Cvoid, (Ref{aws_tls_connection_options}, Ptr{aws_tls_ctx}), conn_options, ctx)
end

function aws_tls_client_ctx_new(alloc, options)
    ccall((:aws_tls_client_ctx_new, libaws_c_io), Ptr{aws_tls_ctx}, (Ptr{aws_allocator}, Ptr{aws_tls_ctx_options}), alloc, options)
end

function aws_tls_ctx_options_init_client_mtls_from_path(options, allocator, cert_path, pkey_path)
    ccall((:aws_tls_ctx_options_init_client_mtls_from_path, libaws_c_io), Cint, (Ptr{aws_tls_ctx_options}, Ptr{aws_allocator}, Ptr{Cchar}, Ptr{Cchar}), options, allocator, cert_path, pkey_path)
end

function aws_tls_ctx_options_init_client_mtls_from_system_path(options, allocator, cert_reg_path)
    ccall((:aws_tls_ctx_options_init_client_mtls_from_system_path, libaws_c_io), Cint, (Ptr{aws_tls_ctx_options}, Ptr{aws_allocator}, Ptr{Cchar}), options, allocator, cert_reg_path)
end

function aws_tls_ctx_options_override_default_trust_store_from_path(options, ca_path, ca_file)
    ccall((:aws_tls_ctx_options_override_default_trust_store_from_path, libaws_c_io), Cint, (Ptr{aws_tls_ctx_options}, Ptr{Cchar}, Ptr{Cchar}), options, ca_path, ca_file)
end

function aws_tls_ctx_options_init_default_client(options, allocator)
    ccall((:aws_tls_ctx_options_init_default_client, libaws_c_io), Cvoid, (Ptr{aws_tls_ctx_options}, Ptr{aws_allocator}), options, allocator)
end

function aws_tls_ctx_options_set_alpn_list(options, alpn_list)
    ccall((:aws_tls_ctx_options_set_alpn_list, libaws_c_io), Cint, (Ptr{aws_tls_ctx_options}, Ptr{Cchar}), options, alpn_list)
end

function aws_tls_ctx_options_set_verify_peer(options, verify_peer)
    ccall((:aws_tls_ctx_options_set_verify_peer, libaws_c_io), Cvoid, (Ptr{aws_tls_ctx_options}, Bool), options, verify_peer)
end

function aws_tls_connection_options_set_server_name(conn_options, allocator, server_name)
    ccall((:aws_tls_connection_options_set_server_name, libaws_c_io), Cint, (Ptr{aws_tls_connection_options}, Ptr{aws_allocator}, Ref{aws_byte_cursor}), conn_options, allocator, server_name)
end

function aws_tls_connection_options_clean_up(connection_options)
    ccall((:aws_tls_connection_options_clean_up, libaws_c_io), Cvoid, (Ref{aws_tls_connection_options},), connection_options)
end

function aws_tls_ctx_release(ctx)
    ccall((:aws_tls_ctx_release, libaws_c_io), Cvoid, (Ptr{aws_tls_ctx},), ctx)
end

function aws_tls_ctx_options_clean_up(options)
    ccall((:aws_tls_ctx_options_clean_up, libaws_c_io), Cvoid, (Ptr{aws_tls_ctx_options},), options)
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
    ccall((:aws_http_connection_manager_new, libaws_c_http), Ptr{aws_http_connection_manager}, (Ptr{aws_allocator}, Ref{aws_http_connection_manager_options}), allocator, options)
end

function aws_http_connection_manager_release(manager)
    ccall((:aws_http_connection_manager_release, libaws_c_http), Cvoid, (Ptr{aws_http_connection_manager},), manager)
end

function aws_http_connection_manager_acquire_connection(manager, callback, user_data)
    ccall((:aws_http_connection_manager_acquire_connection, libaws_c_http), Cvoid, (Ptr{aws_http_connection_manager}, Ptr{Cvoid}, Any), manager, callback, user_data)
end

function aws_http_connection_manager_release_connection(manager, connection)
    ccall((:aws_http_connection_manager_release_connection, libaws_c_http), Cint, (Ptr{aws_http_connection_manager}, Ptr{aws_http_connection}), manager, connection)
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
    ccall((:aws_http_connection_get_version, libaws_c_http), aws_http_version, (Ptr{aws_http_connection},), connection)
end

function aws_http_stream_release(stream)
    ccall((:aws_http_stream_release, libaws_c_http), Cvoid, (Ptr{aws_http_stream},), stream)
end

const aws_http_message = Cvoid

function aws_http2_message_new_request(allocator)
    ccall((:aws_http2_message_new_request, libaws_c_http), Ptr{aws_http_message}, (Ptr{aws_allocator},), allocator)
end

function aws_http_message_new_request(allocator)
    ccall((:aws_http_message_new_request, libaws_c_http), Ptr{aws_http_message}, (Ptr{aws_allocator},), allocator)
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
    ccall((:aws_http_stream_get_incoming_response_status, libaws_c_http), Cint, (Ptr{aws_http_stream}, Ptr{Cint}), stream, out_status)
end

function aws_http_message_set_request_method(request_message, method)
    ccall((:aws_http_message_set_request_method, libaws_c_http), Cint, (Ptr{aws_http_message}, aws_byte_cursor), request_message, method)
end

function aws_http_message_set_request_path(request_message, path)
    ccall((:aws_http_message_set_request_path, libaws_c_http), Cint, (Ptr{aws_http_message}, aws_byte_cursor), request_message, path)
end

const aws_http_headers = Cvoid

function aws_http_message_get_headers(message)
    ccall((:aws_http_message_get_headers, libaws_c_http), Ptr{aws_http_headers}, (Ptr{aws_http_message},), message)
end

function aws_http2_headers_set_request_scheme(h2_headers, scheme)
    ccall((:aws_http2_headers_set_request_scheme, libaws_c_http), Cint, (Ptr{aws_http_headers}, aws_byte_cursor), h2_headers, scheme)
end

function aws_http2_headers_set_request_authority(h2_headers, authority)
    ccall((:aws_http2_headers_set_request_authority, libaws_c_http), Cint, (Ptr{aws_http_headers}, aws_byte_cursor), h2_headers, authority)
end

function aws_http_message_add_header(message, header)
    ccall((:aws_http_message_add_header, libaws_c_http), Cint, (Ptr{aws_http_message}, aws_http_header), message, header)
end

function aws_http_message_set_body_stream(message, body_stream)
    ccall((:aws_http_message_set_body_stream, libaws_c_http), Cvoid, (Ptr{aws_http_message}, Ptr{aws_input_stream}), message, body_stream)
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
    ccall((:aws_http_connection_make_request, libaws_c_http), Ptr{aws_http_stream}, (Ptr{aws_http_connection}, Ref{aws_http_make_request_options}), client_connection, options)
end

function aws_http_stream_activate(stream)
    ccall((:aws_http_stream_activate, libaws_c_http), Cint, (Ptr{aws_http_stream},), stream)
end

function aws_http_connection_release(connection)
    ccall((:aws_http_connection_release, libaws_c_http), Cvoid, (Ptr{aws_http_connection},), connection)
end

function aws_http_client_connect(options)
    ccall((:aws_http_client_connect, libaws_c_http), Cint, (Ref{aws_http_client_connection_options},), options)
end

function aws_http_message_release(message)
    ccall((:aws_http_message_release, libaws_c_http), Ptr{aws_http_message}, (Ptr{aws_http_message},), message)
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
    ccall((:aws_uri_init_from_builder_options, libaws_c_common), Cint, (Ref{aws_uri}, Ptr{aws_allocator}, Ref{aws_uri_builder_options}), uri, allocator, options)
end

function aws_uri_query_string(uri)
    ccall((:aws_uri_query_string, libaws_c_common), Ptr{aws_byte_cursor}, (Ref{aws_uri},), uri)
end

function aws_array_list_init_static(list, raw_array, item_count, item_size)
    ccall((:aws_array_list_init_static, libaws_c_common), Cvoid, (Ref{aws_array_list}, Ptr{Cvoid}, Csize_t, Csize_t), list, raw_array, item_count, item_size)
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
    ccall((:aws_http_headers_has, libaws_c_http), Bool, (Ptr{aws_http_headers}, aws_byte_cursor), headers, name)
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
    ccall((:aws_retry_strategy_new_standard, libaws_c_io), Ptr{aws_retry_strategy}, (Ptr{aws_allocator}, Ref{aws_standard_retry_options}), allocator, config)
end

function aws_retry_strategy_release(retry_strategy)
    ccall((:aws_retry_strategy_release, libaws_c_io), Cvoid, (Ptr{aws_retry_strategy},), retry_strategy)
end

function aws_retry_strategy_acquire_retry_token(retry_strategy, partition_id, on_acquired, user_data, timeout_ms)
    ccall((:aws_retry_strategy_acquire_retry_token, libaws_c_io), Cint, (Ptr{aws_retry_strategy}, Ref{aws_byte_cursor}, Ptr{Cvoid}, Any, UInt64), retry_strategy, partition_id, on_acquired, user_data, timeout_ms)
end

const aws_retry_token = Cvoid

@enum aws_retry_error_type::UInt32 begin
    AWS_RETRY_ERROR_TYPE_TRANSIENT = 0
    AWS_RETRY_ERROR_TYPE_THROTTLING = 1
    AWS_RETRY_ERROR_TYPE_SERVER_ERROR = 2
    AWS_RETRY_ERROR_TYPE_CLIENT_ERROR = 3
end

function aws_retry_strategy_schedule_retry(token, error_type, retry_ready, user_data)
    ccall((:aws_retry_strategy_schedule_retry, libaws_c_io), Cint, (Ptr{aws_retry_token}, aws_retry_error_type, Ptr{Cvoid}, Any), token, error_type, retry_ready, user_data)
end

function aws_retry_token_record_success(token)
    ccall((:aws_retry_token_record_success, libaws_c_io), Cint, (Ptr{aws_retry_token},), token)
end

function aws_retry_token_acquire(token)
    ccall((:aws_retry_token_acquire, libaws_c_io), Cvoid, (Ptr{aws_retry_token},), token)
end

function aws_retry_token_release(token)
    ccall((:aws_retry_token_release, libaws_c_io), Cvoid, (Ptr{aws_retry_token},), token)
end

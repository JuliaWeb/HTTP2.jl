module HTTP2

using CodecZlib, URIs, Mmap
@static if isfile("/app/aws-crt/lib/libaws-c-io.so")
    const libaws_c_common = "/app/aws-crt/lib/libaws-c-common.so"
    const libaws_c_io = "/app/aws-crt/lib/libaws-c-io.so"
    const libaws_c_http = "/app/aws-crt/lib/libaws-c-http.so"
else
    const libaws_c_common = "/Users/jacob.quinn/aws-crt/lib/libaws-c-common.dylib"
    const libaws_c_io = "/Users/jacob.quinn/aws-crt/lib/libaws-c-io.dylib"
    const libaws_c_http = "/Users/jacob.quinn/aws-crt/lib/libaws-c-http.dylib"
end

include("utils.jl")
include("c.jl")

const RequestBodyTypes = Union{AbstractString, AbstractVector{UInt8}, IO, AbstractDict, NamedTuple, Nothing}

mutable struct Request
    method::String
    uri::URI
    _uri::aws_uri
    headers::Headers
    body::RequestBodyTypes

    function Request(method::AbstractString, url::AbstractString, headers, body::RequestBodyTypes, allocator::Ptr{aws_allocator}, query=nothing)
        _uri = aws_uri(String(url) * (query === nothing ? "" : ("?" * URIs.escapeuri(query))), allocator)
        return new(String(method), URI(_uri), _uri, something(headers, Header[]), body)
    end
end

Base.getproperty(x::Request, s::Symbol) = s == :url ? x.uri : getfield(x, s)
print_request(io::IO, r::Request) = print_request(io, r.method, r.uri.path, r.headers, r.body)
function Base.show(io::IO, r::Request)
    println(io, "HTTP2.Request:")
    print_request(io, r)
end

struct StreamMetrics
    send_start_timestamp_ns::Int64
    send_end_timestamp_ns::Int64
    sending_duration_ns::Int64
    receive_start_timestamp_ns::Int64
    receive_end_timestamp_ns::Int64
    receiving_duration_ns::Int64
    stream_id::UInt32
end

mutable struct RequestMetrics
    request_body_length::Int
    response_body_length::Int
    nretries::Int
    stream_metrics::Union{Nothing, StreamMetrics}
end

RequestMetrics() = RequestMetrics(0, 0, 0, nothing)

mutable struct Response
    status::Int
    headers::Headers
    body::Any # IO or Vector{UInt8}
    metrics::RequestMetrics
end

Response(body=UInt8[]) = Response(0, Header[], body, RequestMetrics())

print_response(io::IO, r::Response) = print_response(io, r.status, r.headers, r.body)
function Base.show(io::IO, r::Response)
    println(io, "HTTP2.Response:")
    print_response(io, r)
end

isredirect(r::Response) = isredirect(r.status)
isredirect(status::Integer) = status in (301, 302, 303, 307, 308)

# we use finalizers only because Clients are meant to be global consts and never
# short-lived, temporary objects that should clean themselves up efficiently
mutable struct Client
    scheme::SubString{String}
    host::SubString{String}
    port::UInt16
    allocator::Ptr{aws_allocator}
    retry_strategy::Ptr{Cvoid}
    retry_timeout_ms::Int
    connection_manager::Ptr{Cvoid}

    function Client(scheme::SubString{String}, host::SubString{String}, port::UInt16;
        allocator=ALLOCATOR[],
        bootstrap=CLIENT_BOOTSTRAP[],
        event_loop_group=EVENT_LOOP_GROUP[], # this should probably default to the elg from bootstrap
        # retry options
        max_retries::Integer=10,
        backoff_scale_factor_ms::Integer=25,
        max_backoff_secs::Integer=20,
        jitter_mode::aws_exponential_backoff_jitter_mode=AWS_EXPONENTIAL_BACKOFF_JITTER_DEFAULT,
        retry_timeout_ms::Integer=60000,
        # socket options
        socket_domain=:ipv4,
        connect_timeout_ms::Integer=3000,
        keep_alive_interval_sec::Integer=0,
        keep_alive_timeout_sec::Integer=0,
        keep_alive_max_failed_probes::Integer=0,
        keepalive::Bool=false,
        # tls options
        ssl_cert=nothing,
        ssl_key=nothing,
        ssl_capath=nothing,
        ssl_cacert=nothing,
        ssl_insecure=false,
        ssl_alpn_list="h2;http/1.1",
        # connection manager options
        max_connections::Integer=512,
        max_connection_idle_in_milliseconds::Integer=60000,
    )
        # retry strategy
        retry_opts = aws_standard_retry_options(
            max_retries,
            backoff_scale_factor_ms,
            max_backoff_secs,
            jitter_mode,
            event_loop_group
        )
        retry_strategy = aws_retry_strategy_new_standard(allocator, retry_opts)
        retry_strategy == C_NULL && aws_throw_error()
        # socket options
        socket_options = aws_socket_options(
            AWS_SOCKET_STREAM, # socket type
            socket_domain == :ipv4 ? AWS_SOCKET_IPV4 : AWS_SOCKET_IPV6, # socket domain
            connect_timeout_ms,
            keep_alive_interval_sec,
            keep_alive_timeout_sec,
            keep_alive_max_failed_probes,
            keepalive
        )
        # tls options
        tls_options = aws_mem_acquire(allocator, 64)
        tls_ctx_options = aws_mem_acquire(allocator, 512)
        tls_ctx = C_NULL
        connection_manager = C_NULL
        host_str = String(host)
        try
            if scheme == "https" || scheme == "wss"
                if ssl_cert !== nothing && ssl_key !== nothing
                    aws_tls_ctx_options_init_client_mtls_from_path(tls_ctx_options, allocator, ssl_cert, ssl_key) != 0 && aws_throw_error()
                elseif Sys.iswindows() && ssl_cert !== nothing && ssl_key === nothing
                    aws_tls_ctx_options_init_client_mtls_from_system_path(tls_ctx_options, allocator, ssl_cert) != 0 && aws_throw_error()
                else
                    aws_tls_ctx_options_init_default_client(tls_ctx_options, allocator)
                end
                if ssl_capath !== nothing && ssl_cacert !== nothing
                    aws_tls_ctx_options_override_default_trust_store_from_path(tls_ctx_options, ssl_capath, ssl_cacert) != 0 && aws_throw_error()
                end
                if ssl_insecure
                    aws_tls_ctx_options_set_verify_peer(tls_ctx_options, false)
                end
                aws_tls_ctx_options_set_alpn_list(tls_ctx_options, ssl_alpn_list) != 0 && aws_throw_error()
                tls_ctx = aws_tls_client_ctx_new(allocator, tls_ctx_options)
                tls_ctx == C_NULL && aws_throw_error()
                aws_tls_connection_options_init_from_ctx(tls_options, tls_ctx)
                aws_tls_connection_options_set_server_name(tls_options, allocator, aws_byte_cursor_from_c_str(host_str)) != 0 && aws_throw_error()
            else
                aws_mem_release(allocator, tls_options)
                aws_mem_release(allocator, tls_ctx_options)
                tls_options = C_NULL
            end
            http_connection_manager_options = aws_http_connection_manager_options(
                bootstrap,
                socket_options,
                tls_options,
                aws_byte_cursor_from_c_str(host_str),
                port,
                max_connections,
                max_connection_idle_in_milliseconds
            )
            connection_manager = aws_http_connection_manager_new(allocator, http_connection_manager_options)
        finally
            if scheme == "https" || scheme == "wss"
                aws_tls_connection_options_clean_up(tls_options)
                aws_tls_ctx_options_clean_up(tls_ctx_options)
                aws_tls_ctx_release(tls_ctx)
                aws_mem_release(allocator, tls_options)
                aws_mem_release(allocator, tls_ctx_options)
            end
        end
        connection_manager == C_NULL && aws_throw_error()
        client = new(scheme, host, port, allocator, retry_strategy, retry_timeout_ms, connection_manager)
        finalizer(client) do x
            if x.connection_manager != C_NULL
                aws_http_connection_manager_release(x.connection_manager)
                x.connection_manager = C_NULL
            end
            if x.retry_strategy != C_NULL
                aws_retry_strategy_release(x.retry_strategy)
                x.retry_strategy = C_NULL
            end
        end
        return client
    end
end

struct Clients
    lock::ReentrantLock
    clients::Dict{Tuple{SubString{String}, SubString{String}, UInt16}, Client}
end

Clients() = Clients(ReentrantLock(), Dict{Tuple{SubString{String}, SubString{String}, UInt16}, Client}())

const CLIENTS = Clients()

function getclient(key::Tuple{SubString{String}, SubString{String}, UInt16})
    Base.@lock CLIENTS.lock begin
        if haskey(CLIENTS.clients, key)
            return CLIENTS.clients[key]
        else
            client = Client(key...)
            CLIENTS.clients[key] = client
            return client
        end
    end
end

mutable struct RequestContext
    client::Client
    retry_token::Ptr{aws_retry_token}
    should_retry::Bool
    completed::Threads.Event
    error::Union{Nothing, Exception}
    request::Request
    request_body::Any
    response::Response
    temp_response_body::Any
    gzip_decompressing::Bool
    error_response_body::Union{Nothing, Vector{UInt8}}
    connection::Ptr{Cvoid}
    stream::Ptr{Cvoid}
    decompress::Union{Nothing, Bool}
    status_exception::Bool
    retry_non_idempotent::Bool
    modifier::Any # f(::Request) -> Nothing
    verbose::Int
end

function RequestContext(client, request, response, args...)
    return RequestContext(client, C_NULL, false, Threads.Event(), nothing, request, nothing, response, nothing, false, nothing, C_NULL, C_NULL, args...)
end

struct StatusError <: Exception
    request::Request
    response::Response
end

function Base.showerror(io::IO, e::StatusError)
    println(io, "HTTP2.StatusError:")
    println(io, "  request:")
    print_request(io, e.request)
    println(io, "  response:")
    print_response(io, e.response)
    return
end

const ALLOCATOR = Ref{Ptr{Cvoid}}(C_NULL)
const EVENT_LOOP_GROUP = Ref{Ptr{Cvoid}}(C_NULL)
const HOST_RESOLVER = Ref{Ptr{Cvoid}}(C_NULL)
const CLIENT_BOOTSTRAP = Ref{Ptr{Cvoid}}(C_NULL)
const LOGGER = Ref{Ptr{Cvoid}}(C_NULL)

#NOTE: this is global process logging in the aws-crt libraries; not appropriate for request-level
# logging, but more for debugging the library itself
function set_log_level!(level::Integer)
    @assert 0 <= level <= 7 "log level must be between 0 and 7"
    aws_logger_set_log_level(LOGGER[], aws_log_level(level)) != 0 && aws_throw_error()
    return
end

const USER_AGENT = Ref{Union{String, Nothing}}("HTTP2.jl/$VERSION")

"""
    setuseragent!(x::Union{String, Nothing})

Set the default User-Agent string to be used in each HTTP request.
Can be manually overridden by passing an explicit `User-Agent` header.
Setting `nothing` will prevent the default `User-Agent` header from being passed.
"""
function setuseragent!(x::Union{String, Nothing})
    USER_AGENT[] = x
    return
end

include("forms.jl"); using .Forms
include("redirects.jl"); 
include("client.jl")

function __init__()
    # populate default allocator
    ALLOCATOR[] = aws_default_allocator()
    @assert ALLOCATOR[] != C_NULL
    # populate default event loop group; 0 means one event loop per non-hyperthread core
    EVENT_LOOP_GROUP[] = aws_event_loop_group_new_default(ALLOCATOR[], 0, C_NULL)
    @assert EVENT_LOOP_GROUP[] != C_NULL
    # populate default host resolver
    resolver_options = aws_host_resolver_default_options(8, EVENT_LOOP_GROUP[], C_NULL, C_NULL)
    HOST_RESOLVER[] = aws_host_resolver_new_default(ALLOCATOR[], resolver_options)
    @assert HOST_RESOLVER[] != C_NULL
    # populate default client bootstrap w/ event loop, host resolver, and allocator
    bootstrap_options = aws_client_bootstrap_options(EVENT_LOOP_GROUP[], HOST_RESOLVER[], C_NULL, C_NULL, C_NULL)
    CLIENT_BOOTSTRAP[] = aws_client_bootstrap_new(ALLOCATOR[], bootstrap_options)
    @assert CLIENT_BOOTSTRAP[] != C_NULL
    # initialize logger
    LOGGER[] = aws_mem_acquire(ALLOCATOR[], 64)
    log_options = aws_logger_standard_options(0, Libc.FILE(Libc.RawFD(1), "w"))
    aws_logger_init_standard(LOGGER[], ALLOCATOR[], log_options) != 0 && aws_throw_error()
    aws_logger_set(LOGGER[])
    # intialize http library
    aws_http_library_init(ALLOCATOR[])
    on_acquired[] = @cfunction(c_on_acquired, Cvoid, (Ptr{Cvoid}, Cint, Ptr{Cvoid}, Any))
    on_shutdown[] = @cfunction(c_on_shutdown, Cvoid, (Ptr{Cvoid}, Cint, Any))
    on_setup[] = @cfunction(c_on_setup, Cvoid, (Ptr{Cvoid}, Cint, Any))
    on_response_headers[] = @cfunction(c_on_response_headers, Cint, (Ptr{Cvoid}, Cint, Ptr{Cvoid}, Csize_t, Any))
    on_response_header_block_done[] = @cfunction(c_on_response_header_block_done, Cint, (Ptr{Cvoid}, Cint, Any))
    on_response_body[] = @cfunction(c_on_response_body, Cint, (Ptr{Cvoid}, Ptr{aws_byte_cursor}, Any))
    on_metrics[] = @cfunction(c_on_metrics, Cvoid, (Ptr{Cvoid}, Ptr{StreamMetrics}, Any))
    on_complete[] = @cfunction(c_on_complete, Cvoid, (Ptr{Cvoid}, Cint, Any))
    on_destroy[] = @cfunction(c_on_destroy, Cvoid, (Any,))
    retry_ready[] = @cfunction(c_retry_ready, Cvoid, (Ptr{Cvoid}, Cint, Any))
    return
end

end

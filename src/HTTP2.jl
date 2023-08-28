module HTTP2

const libawscrt = "/Users/quinnj/aws-crt/lib/libaws-c-http"
const libawsio = "/Users/quinnj/aws-crt/lib/libaws-c-io"

const Header = Pair{String, String}
const Headers = Vector{Header}

ascii_lc(c::UInt8) = c in UInt8('A'):UInt8('Z') ? c + 0x20 : c
ascii_lc_isequal(a::UInt8, b::UInt8) = ascii_lc(a) == ascii_lc(b)
function ascii_lc_isequal(a, b)
    acu = codeunits(a)
    bcu = codeunits(b)
    len = length(acu)
    len != length(bcu) && return false
    for i = 1:len
        @inbounds !ascii_lc_isequal(acu[i], bcu[i]) && return false
    end
    return true
end

hasheader(h, k) = any(x -> ascii_lc_isequal(x.first, k), h)

include("c.jl")

const RequestBodyTypes = Union{AbstractString, AbstractVector{UInt8}, IO, AbstractDict, NamedTuple, Nothing}

mutable struct Request
    method::String
    uri::aws_uri
    headers::Headers
    body::RequestBodyTypes
end

Request(method, url, headers, body, allocator) =
    Request(method, aws_uri(url, allocator), something(headers, Header[]), body)

mutable struct Response
    status::Int
    headers::Headers
    body::Any # IO or Vector{UInt8}
end

Response(body=UInt8[]) = Response(0, Header[], body)

mutable struct RequestContext
    allocator::Ptr{aws_allocator}
    bootstrap::Ptr{aws_client_bootstrap}
    retry_token::Ptr{aws_retry_token}
    should_retry::Bool
    completed::Threads.Event
    error::Union{Nothing, Exception}
    request::Request
    response::Response
    temp_response_body::Any # Union{Nothing, IOBuffer}
    # keyword arguments
    # socket options
    socket_domain::Symbol
    connect_timeout_ms::Int
    keep_alive_interval_sec::Int
    keep_alive_timeout_sec::Int
    keep_alive_max_failed_probes::Int
    keepalive::Bool
    # tls options
    ssl_cert::Union{Nothing, String}
    ssl_key::Union{Nothing, String}
    ssl_capath::Union{Nothing, String}
    ssl_cacert::Union{Nothing, String}
    ssl_insecure::Bool
    ssl_alpn_list::String
    # connection manager options
    max_connections::Int
    max_connection_idle_in_milliseconds::Int
end

function RequestContext(allocator, bootstrap, request, response, args...)
    if response.body isa AbstractVector{UInt8} && length(response.body) > 0
        response_body = IOBuffer(response.body; write=true, maxsize=length(response.body))
    elseif response.body === nothing
        response_body = UInt8[]
        response.body = response_body
    else
        response_body = response.body
    end
    return RequestContext(allocator, bootstrap, C_NULL, false, Threads.Event(), nothing, request, response, response_body, args...)
end

struct StatusError <: Exception
    request::Request
    response::Response
end

const ALLOCATOR = Ref{Ptr{Cvoid}}(C_NULL)
const EVENT_LOOP_GROUP = Ref{Ptr{Cvoid}}(C_NULL)
const HOST_RESOLVER = Ref{Ptr{Cvoid}}(C_NULL)
const CLIENT_BOOTSTRAP = Ref{Ptr{Cvoid}}(C_NULL)
const DEFAULT_SOCKET_OPTIONS = aws_socket_options(
    AWS_SOCKET_STREAM, # socket type
    AWS_SOCKET_IPV4, # socket domain
    3000, # connect_timeout_ms
    0, # keep_alive_interval_sec
    0, # keep_alive_timeout_sec
    0, # keep_alive_max_failed_probes
    false # keepalive
)
const LOGGER = Ref{Ptr{Cvoid}}(C_NULL)
const CONNECTION_MANAGERS = Dict{String, Ptr{aws_http_connection_manager}}()

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
include("client.jl")

function __init__()
    # populate default allocator
    ALLOCATOR[] = aws_default_allocator()
    @assert ALLOCATOR[] != C_NULL
    # populate default event loop group; 0 means one event loop per non-hypterthread core
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
    log_options = aws_logger_standard_options(0, Libc.FILE(Libc.RawFD(1), "r+"))
    aws_logger_init_standard(LOGGER[], ALLOCATOR[], log_options) != 0 && aws_throw_error()
    aws_logger_set(LOGGER[])
    # intialize http library
    aws_http_library_init(ALLOCATOR[])
    on_acquired[] = @cfunction(c_on_acquired, Cvoid, (Ptr{Cvoid}, Cint, Ptr{Cvoid}, Ptr{Cvoid}))
    on_shutdown[] = @cfunction(c_on_shutdown, Cvoid, (Ptr{Cvoid}, Cint, Ptr{Cvoid}))
    on_setup[] = @cfunction(c_on_setup, Cvoid, (Ptr{Cvoid}, Cint, Ptr{Cvoid}))
    on_response_headers[] = @cfunction(c_on_response_headers, Cint, (Ptr{Cvoid}, Cint, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}))
    on_response_header_block_done[] = @cfunction(c_on_response_header_block_done, Cint, (Ptr{Cvoid}, Cint, Ptr{Cvoid}))
    on_response_body[] = @cfunction(c_on_response_body, Cint, (Ptr{Cvoid}, Ptr{aws_byte_cursor}, Ptr{Cvoid}))
    on_complete[] = @cfunction(c_on_complete, Cvoid, (Ptr{Cvoid}, Cint, Ptr{Cvoid}))
    return
end

end

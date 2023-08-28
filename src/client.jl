const on_setup = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_setup(conn, error_code, user_data)
    # println("on setup")
    ctx = unsafe_pointer_to_objref(user_data)
    if error_code != 0
        ctx.error = CapturedException(aws_error(), Base.backtrace())
        if erro_code == AWS_IO_DNS_INVALID_NAME || error_code == AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE
            ctx.should_retry = false
        else
            ctx.should_retry = true
        end
        Threads.notify(ctx.completed)
        return
    end
    # build request
    protocol_version = aws_http_connection_get_version(conn)
    request = protocol_version == AWS_HTTP_VERSION_2 ?
          aws_http2_message_new_request(ctx.allocator) :
          aws_http_message_new_request(ctx.allocator)
    if request == C_NULL
        ctx.error = CapturedException(aws_error(), Base.backtrace())
        ctx.should_retry = true
        Threads.notify(ctx.completed)
        return
    end
    # build up request headers
    headers = ctx.request.headers
    path = ctx.request.uri.path_and_query.len != 0 ? ctx.request.uri.path_and_query : aws_byte_cursor_from_c_str("/")
    if protocol_version == AWS_HTTP_VERSION_2
        # set method
        push!(headers, ":method" => ctx.request.method)
        # set path
        push!(headers, ":path" => String(path))
        # set scheme
        push!(headers, ":scheme" => String(ctx.request.uri.scheme))
        # set authority
        push!(headers, ":authority" => String(ctx.request.uri.host_name))
    else
        # set method
        aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str(ctx.request.method))
        # set path
        aws_http_message_set_request_path(request, path)
        # set host
        push!(headers, "host" => String(ctx.request.uri.host_name))
    end
    # accept header
    if !hasheader(headers, "accept")
        push!(headers, "accept" => "*/*")
    end
    # user-agent header
    if !hasheader(headers, "user-agent")
        push!(headers, "user-agent" => USER_AGENT[])
    end
    # accept-encoding
    if ctx.decompress === nothing || ctx.decompress
        push!(headers, "accept-encoding" => "gzip")
    end
    # add headers to request
    for (k, v) in headers
        header = aws_http_header(aws_byte_cursor_from_c_str(string(k)), aws_byte_cursor_from_c_str(string(v)), AWS_HTTP_HEADER_COMPRESSION_USE_CACHE)
        aws_http_message_add_header(request, header)
    end
    # set body
    if ctx.request.body !== nothing
        if ctx.request.body isa AbstractString
            cbody = aws_byte_cursor_from_c_str(ctx.request.body)
            input_stream = aws_input_stream_new_from_cursor(ctx.allocator, cbody)
        elseif ctx.request.body isa AbstractVector{UInt8}
            cbody = aws_byte_cursor(sizeof(ctx.request.body), pointer(ctx.request.body))
            input_stream = aws_input_stream_new_from_cursor(ctx.allocator, cbody)
        elseif ctx.request.body isa Union{AbstractDict, NamedTuple}
            # add application/x-www-form-urlencoded content-type header if not already present
            if !aws_http_headers_has(aws_http_message_get_headers(request), aws_byte_cursor_from_c_str("content-type"))
                # "Content-Type" => "application/x-www-form-urlencoded"
                content_type_header = aws_http_header(aws_byte_cursor_from_c_str("content-type"), aws_byte_cursor_from_c_str("application/x-www-form-urlencoded"), AWS_HTTP_HEADER_COMPRESSION_USE_CACHE)
                aws_http_message_add_header(request, content_type_header)
            end
            cbody = aws_byte_cursor_from_c_str(escapeuri(ctx.allocator, ctx.request.body))
            input_stream = aws_input_stream_new_from_cursor(ctx.allocator, cbody)
        elseif ctx.request.body isa IOStream
            input_stream = aws_input_stream_new_from_open_file(ctx.allocator, Libc.FILE(ctx.request.body))
        elseif ctx.request.body isa Form
            # add multipart content-type header if not already present
            if !aws_http_headers_has(aws_http_message_get_headers(request), aws_byte_cursor_from_c_str("content-type"))
                # "Content-Type" => "multipart/form-data; boundary=..."
                content_type_header = aws_http_header(aws_byte_cursor_from_c_str("content-type"), aws_byte_cursor_from_c_str(contet_type(ctx.request.body)), AWS_HTTP_HEADER_COMPRESSION_USE_CACHE)
                aws_http_message_add_header(request, content_type_header)
            end
            # we set the request.body to the Form bytes in order to gc-preserve them
            ctx.request.body = read(ctx.request.body)
            cbody = aws_byte_cursor(sizeof(ctx.request.body), pointer(ctx.request.body))
            input_stream = aws_input_stream_new_from_cursor(ctx.allocator, cbody)
        elseif ctx.request.body isa IO
            # we set the request.body to the IO bytes in order to gc-preserve them
            bytes = readavailable(ctx.request.body)
            while !eof(ctx.request.body)
                append!(bytes, readavailable(ctx.request.body))
            end
            ctx.request.body = bytes
            cbody = aws_byte_cursor(sizeof(ctx.request.body), pointer(ctx.request.body))
            input_stream = aws_input_stream_new_from_cursor(ctx.allocator, cbody)
        else
            throw(ArgumentError("request body must be a string, vector of UInt8, or IOStream"))
        end
        data_len_ref = Ref(0)
        aws_input_stream_get_length(input_stream, data_len_ref) != 0 && aws_throw_error()
        data_len = data_len_ref[]
        if data_len > 0
            content_length_header = aws_http_header(aws_byte_cursor_from_c_str("content-length"), aws_byte_cursor_from_c_str(string(data_len)), AWS_HTTP_HEADER_COMPRESSION_USE_CACHE)
            aws_http_message_add_header(request, content_length_header)
            aws_http_message_set_body_stream(request, input_stream)
        else
            aws_input_stream_destroy(input_stream)
        end
    end

    final_request = aws_http_make_request_options(request, ctx)
    stream = aws_http_connection_make_request(conn, final_request)
    if stream == C_NULL
        ctx.error = CapturedException(aws_error(), Base.backtrace())
        ctx.should_retry = true
        Threads.notify(ctx.completed)
        return
    end
    aws_http_message_release(request)
    aws_http_stream_activate(stream)
    aws_http_connection_release(conn)
    return
end

const on_shutdown = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_shutdown(conn, error_code, user_data)
    ctx = unsafe_pointer_to_objref(user_data)
    if error_code != 0
        ctx.error = CapturedException(aws_error(), Base.backtrace())
        ctx.should_retry = true
    end
    Threads.notify(ctx.completed)
    return
end

const on_response_headers = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_response_headers(stream, header_block, header_array, num_headers, user_data)
    ctx = unsafe_pointer_to_objref(user_data)
    headers = unsafe_wrap(Array, Ptr{aws_http_header}(header_array), num_headers)
    for header in headers
        name = unsafe_string(header.name.ptr, header.name.len)
        value = unsafe_string(header.value.ptr, header.value.len)
        push!(ctx.response.headers, name => value)
    end
    return Cint(0)
end

const on_response_header_block_done = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_response_header_block_done(stream, header_block, user_data)
    ctx = unsafe_pointer_to_objref(user_data)
    ref = Ref{Cint}()
    aws_http_stream_get_incoming_response_status(stream, ref)
    ctx.response.status = ref[]
    if ctx.decompress === true || (ctx.decompress === nothing && getheader(ctx.response.headers, "content-encoding") == "gzip")
        if ctx.temp_response_body isa Vector{UInt8}
            io = IOBuffer(ctx.temp_response_body; write=true)
            ctx.temp_response_body = CodecZlibNG.GzipDecompressorStream(io)
        else
            ctx.temp_response_body = CodecZlibNG.GzipDecompressorStream(ctx.temp_response_body)
        end
    end
    if hasheader(ctx.response.headers, "content-length") && ctx.temp_response_body isa Vector{UInt8}
        resize!(ctx.temp_response_body, parse(Int, getheader(ctx.response.headers, "content-length")))
    end
    if ctx.status_exception && ctx.response.status >= 299
        ctx.error = StatusError(ctx.request, ctx.response)
        ctx.should_retry = true # TODO: only retry non-idempotent, certain status codes, etc.
    end
    return Cint(0)
end

const on_response_body = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_response_body(stream, data::Ptr{aws_byte_cursor}, user_data)
    ctx = unsafe_pointer_to_objref(user_data)
    bc = unsafe_load(data)
    body = ctx.temp_response_body
    if body isa IOBuffer
        unsafe_write(body, bc.ptr, bc.len)
    elseif body isa Base.GenericIOBuffer{SubArray{UInt8, 1, Vector{UInt8}, Tuple{UnitRange{Int64}}, true}}
        unsafe_write(body, bc.ptr, bc.len)
    elseif body isa Vector{UInt8}
        unsafe_copyto!(pointer(body) + length(body) - bc.len, bc.ptr, bc.len)
    else
        unsafe_write(body, bc.ptr, bc.len)
    end
    return Cint(0)
end

const on_complete = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_complete(stream, error_code, user_data)
    ctx = unsafe_pointer_to_objref(user_data)
    if ctx.temp_response_body isa CodecZlibNG.GzipDecompressorStream
        close(ctx.temp_response_body)
    end
    aws_http_stream_release(stream)
    Threads.notify(ctx.completed)
    return
end

request(method, url, headers=Header[], body::RequestBodyTypes=nothing; allocator=ALLOCATOR[], kw...) =
    request(Request(method, url, headers, body, allocator); allocator, kw...)

# main entrypoint for making an HTTP request
# can provide method, url, headers, body, along with various keyword arguments
function request(req::Request;
    allocator=ALLOCATOR[],
    bootstrap=CLIENT_BOOTSTRAP[],
    event_loop_group=EVENT_LOOP_GROUP[],
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
    # response options
    response_body=nothing,
    decompress::Union{Nothing, Bool}=nothing,
    status_exception::Bool=true,
    verbose=0, # 1-6
)
    # enable logging
    if verbose > 0
        aws_logger_set_log_level(LOGGER[], aws_log_level(verbose))
    end

    # create a request context for shared state that we pass between all the callbacks
    ctx = RequestContext(allocator, bootstrap, req, Response(response_body),
        socket_domain,
        connect_timeout_ms,
        keep_alive_interval_sec,
        keep_alive_timeout_sec,
        keep_alive_max_failed_probes,
        keepalive,
        # tls options
        ssl_cert,
        ssl_key,
        ssl_capath,
        ssl_cacert,
        ssl_insecure,
        ssl_alpn_list,
        # connection manager options
        max_connections,
        max_connection_idle_in_milliseconds,
        decompress,
        status_exception
    )

    # retry options
    retry_opts = aws_standard_retry_options(
        max_retries,
        backoff_scale_factor_ms,
        max_backoff_secs,
        jitter_mode,
        event_loop_group
    )
    retry_strategy = aws_retry_strategy_new_standard(allocator, retry_opts)
    aws_retry_strategy_acquire_retry_token(retry_strategy, req.uri.host_name, on_acquired[], ctx, retry_timeout_ms) != 0 && aws_throw_error()

    # eventually, one of our callbacks will notify ctx.completed, at which point we can return
@label request_wait
    wait(ctx.completed)
    # check if successful or if we should retry
    if ctx.error !== nothing && ctx.should_retry
        aws_retry_strategy_schedule_retry(
            ctx.retry_token,
            error_type,
            retry_ready[],
            ctx
        ) != 0 && aws_throw_error()
        @goto request_wait
    end
    # cleanup logging
    if verbose > 0
        aws_logger_set_log_level(LOGGER[], aws_log_level(0))
    end
    
    # release our retry token
    ctx.error === nothing && aws_retry_token_record_success(ctx.retry_token)
    aws_retry_token_release(ctx.retry_token)
    ctx.retry_token = C_NULL
    ctx.error !== nothing && throw(ctx.error)
    return ctx.response
end

const retry_ready = Ref{Ptr{Cvoid}}(C_NULL)

function c_retry_ready(token::Ptr{aws_retry_token}, error_code::Cint, user_data)
    if error_code != 0
        ctx.error = CapturedException(aws_error(), Base.backtrace())
        ctx.should_retry = false # don't retry if our retry_schedule failed
        Threads.notify(ctx.completed)
        return
    end
    #TODO: do we need to _reset_ anything in the RequestContext here so the request
    # can be retried again?
    c_on_acquired(C_NULL, 0, token, user_data)
    return
end

const on_acquired = Ref{Ptr{Cvoid}}(C_NULL)

function c_on_acquired(retry_strategy, error_code, retry_token::Ptr{aws_retry_token}, user_data)
    if error_code != 0
        ctx.error = CapturedException(aws_error(), Base.backtrace())
        ctx.should_retry = false # don't retry if we failed to get an initial retry_token
        Threads.notify(ctx.completed)
        return
    end
    ctx = unsafe_pointer_to_objref(user_data)
    ctx.retry_token = retry_token
    # if port is given explicitly then use it, otherwise use 80 for http and 443 for https
    req = ctx.request
    uri = req.uri
    port = UInt16(uri.port != 0 ? uri.port : aws_byte_cursor_eq_c_str_ignore_case(uri.scheme, "http") ? 80 : 443)

    try
        connection_manager = get!(CONNECTION_MANAGERS, unsafe_string(uri.host_name.ptr, uri.host_name.len)) do
            socket_options = DEFAULT_SOCKET_OPTIONS
            # if any non-default socket options are given, create a new socket options object
            if ctx.socket_domain != :ipv4 ||
                ctx.connect_timeout_ms != 3000 ||
                ctx.keep_alive_interval_sec != 0 ||
                ctx.keep_alive_timeout_sec != 0 ||
                ctx.keep_alive_max_failed_probes != 0 ||
                ctx.keepalive != false
                socket_options = aws_socket_options(
                    AWS_SOCKET_STREAM,
                    ctx.socket_domain == :ipv4 ? AWS_SOCKET_IPV4 : AWS_SOCKET_IPV6,
                    ctx.connect_timeout_ms,
                    ctx.keep_alive_interval_sec,
                    ctx.keep_alive_timeout_sec,
                    ctx.keep_alive_max_failed_probes,
                    ctx.keepalive
                )
            end
            # figure out tls_options
            if port == 443
                tls_options = aws_mem_acquire(ctx.allocator, 64)
                tls_ctx_options = aws_mem_acquire(ctx.allocator, 512)
                if ctx.ssl_cert !== nothing && ctx.ssl_key !== nothing
                    aws_tls_ctx_options_init_client_mtls_from_path(tls_ctx_options, ctx.allocator, ctx.ssl_cert, ctx.ssl_key) != 0 && aws_throw_error()
                elseif Sys.iswindows() && ctx.ssl_cert !== nothing && ctx.ssl_key === nothing
                    aws_tls_ctx_options_init_client_mtls_from_system_path(tls_ctx_options, ctx.allocator, ctx.ssl_cert) != 0 && aws_throw_error()
                else
                    aws_tls_ctx_options_init_default_client(tls_ctx_options, ctx.allocator)
                end
                if ctx.ssl_capath !== nothing && ctx.ssl_cacert !== nothing
                    aws_tls_ctx_options_override_default_trust_store_from_path(tls_ctx_options, ctx.ssl_capath, ctx.ssl_cacert) != 0 && aws_throw_error()
                end
                if ctx.ssl_insecure
                    aws_tls_ctx_options_set_verify_peer(tls_ctx_options, false)
                end
                aws_tls_ctx_options_set_alpn_list(tls_ctx_options, ctx.ssl_alpn_list) != 0 && aws_throw_error()
                tls_ctx = aws_tls_client_ctx_new(ctx.allocator, tls_ctx_options)
                tls_ctx == C_NULL && aws_throw_error()
                aws_tls_connection_options_init_from_ctx(tls_options, tls_ctx)
                aws_tls_connection_options_set_server_name(tls_options, ctx.allocator, uri.host_name) != 0 && aws_throw_error()
            end
            http_connection_manager_options = aws_http_connection_manager_options(
                ctx.bootstrap,
                socket_options,
                tls_options,
                uri.host_name,
                port,
                ctx.max_connections,
                ctx.max_connection_idle_in_milliseconds
            )
            cm = aws_http_connection_manager_new(ctx.allocator, http_connection_manager_options)
            # cleanup tls_options
            if tls_options != C_NULL
                aws_tls_connection_options_clean_up(tls_options)
                aws_tls_ctx_release(tls_ctx)
                aws_tls_ctx_options_clean_up(tls_ctx_options)
            end
            cm == C_NULL && aws_throw_error()
            return cm
        end
        # initiate the remote connection, which will then kick off the cascade of callbacks
        # println("acquiring connection")
        aws_http_connection_manager_acquire_connection(connection_manager, on_setup[], ctx)
    catch e
        ctx.error = e
        ctx.should_retry = false # don't retry since it's probably some kind of configuration problem
        Threads.notify(ctx.completed)
    end
end

get(a...; kw...) = request("GET", a...; kw...)
put(a...; kw...) = request("PUT", a...; kw...)
post(a...; kw...) = request("POST", a...; kw...)
delete(a...; kw...) = request("DELETE", a...; kw...)
patch(a...; kw...) = request("PATCH", a...; kw...)
head(a...; kw...) = request("HEAD", a...; kw...)
options(a...; kw...) = request("OPTIONS", a...; kw...)

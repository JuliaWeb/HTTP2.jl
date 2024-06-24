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
function getheader(h, k, d="")
    i = findfirst(x -> ascii_lc_isequal(x.first, k), h)
    return i === nothing ? d : h[i].second
end
# backwards compat
const header = getheader

function setheader(h, k, v)
    i = findfirst(x -> ascii_lc_isequal(x.first, k), h)
    if i === nothing
        push!(h, k => v)
    else
        h[i] = k => v
    end
    return
end

setheader(h, p::Pair) = setheader(h, p.first, p.second)

function removeheader(h, k)
    i = findfirst(x -> ascii_lc_isequal(x.first, k), h)
    i === nothing && return
    deleteat!(h, i)
    return
end

isbytes(x) = x isa AbstractVector{UInt8} || x isa AbstractString

resource(uri::URI) = string( isempty(uri.path)     ? "/" :     uri.path,
                            !isempty(uri.query)    ? "?" : "", uri.query,
                            !isempty(uri.fragment) ? "#" : "", uri.fragment)

function print_request(io, method, version, path, headers, body)
    write(io, "\"\"\"\n")
    write(io, string(method, " ", path, " HTTP/$version\r\n"))
    for h in headers
        write(io, string(h.first, ": ", h.second, "\r\n"))
    end
    write(io, "\r\n")
    write(io, string(body))
    write(io, "\n\"\"\"\n")
    return
end

function print_response(io, status, version, headers, body)
    write(io, "\"\"\"\n")
    write(io, string("HTTP/$version ", status, "\r\n"))
    for h in headers
        write(io, string(h.first, ": ", h.second, "\r\n"))
    end
    write(io, "\r\n")
    write(io, something(body, ""))
    write(io, "\n\"\"\"\n")
    return
end

str(bc::aws_byte_cursor) = bc.ptr == C_NULL || bc.len == 0 ? "" : unsafe_string(bc.ptr, bc.len)

function print_uri(io, uri::aws_uri)
    print(io, "scheme: ", str(uri.scheme), "\n")
    print(io, "userinfo: ", str(uri.userinfo), "\n")
    print(io, "host_name: ", str(uri.host_name), "\n")
    print(io, "port: ", uri.port, "\n")
    print(io, "path: ", str(uri.path), "\n")
    print(io, "query: ", str(uri.query_string), "\n")
    return
end

const URI_SCHEME_HTTPS = "https"
const URI_SCHEME_WSS = "wss"
function getport(uri::aws_uri)
    sch = Ref(uri.scheme)
    GC.@preserve sch begin
        return UInt32(uri.port != 0 ? uri.port :
        (aws_byte_cursor_eq_c_str_ignore_case(sch, URI_SCHEME_HTTPS) ||
            aws_byte_cursor_eq_c_str_ignore_case(sch, URI_SCHEME_WSS)) ? 443 : 80)
    end
end

function makeuri(u::aws_uri)
    return URIs.URI(
        scheme=str(u.scheme),
        userinfo=isempty(str(u.userinfo)) ? URIs.absent : str(u.userinfo),
        host=str(u.host_name),
        port=u.port == 0 ? URIs.absent : u.port,
        path=isempty(str(u.path)) ? URIs.absent : str(u.path),
        query=isempty(str(u.query_string)) ? URIs.absent : str(u.query_string),
    )
end

struct AWSError <: Exception
    msg::String
end

aws_error() = AWSError(unsafe_string(aws_error_debug_str(aws_last_error())))
aws_throw_error() = throw(aws_error())

struct FieldRef{T, S}
    x::T
    field::Symbol
end

FieldRef(x::T, field::Symbol) where {T} = FieldRef{T, fieldtype(T, field)}(x, field)

function Base.unsafe_convert(P::Union{Type{Ptr{T}},Type{Ptr{Cvoid}}}, x::FieldRef{S, T}) where {T, S}
    @assert isconcretetype(S) && ismutabletype(S) "only fields of mutable types are supported with FieldRef"
    return P(pointer_from_objref(x.x) + fieldoffset(S, Base.fieldindex(S, x.field)))
end

Base.pointer(x::FieldRef{S, T}) where {S, T} = Base.unsafe_convert(Ptr{T}, x)

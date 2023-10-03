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

function setheader(h, k, v)
    i = findfirst(x -> ascii_lc_isequal(x.first, k), h)
    if i === nothing
        push!(h, k => v)
    else
        h[i] = k => v
    end
    return
end

function deleteheader(h, k)
    i = findfirst(x -> ascii_lc_isequal(x.first, k), h)
    i === nothing && return
    deleteat!(h, i)
    return
end

resource(uri::URI) = string( isempty(uri.path)     ? "/" :     uri.path,
                            !isempty(uri.query)    ? "?" : "", uri.query,
                            !isempty(uri.fragment) ? "#" : "", uri.fragment)

function print_request(io, method, path, headers, body)
    write(io, "\"\"\"\n")
    write(io, string(method, " ", path, " HTTP/1.1\r\n"))
    for h in headers
        write(io, string(h.first, ": ", h.second, "\r\n"))
    end
    write(io, "\r\n")
    write(io, body)
    write(io, "\n\"\"\"\n")
    return
end

function print_response(io, status, headers, body)
    write(io, "\"\"\"\n")
    write(io, string("HTTP/1.1 ", status, "\r\n"))
    for h in headers
        write(io, string(h.first, ": ", h.second, "\r\n"))
    end
    write(io, "\r\n")
    write(io, body)
    write(io, "\n\"\"\"\n")
    return
end
@testset "Client.jl" begin
    isok(r) = r.status == 200
    @testset "GET, HEAD, POST, PUT, DELETE, PATCH" begin
        @test isok(HTTP2.get("https://$httpbin/ip"))
        @test isok(HTTP2.head("https://$httpbin/ip"))
        @test HTTP2.post("https://$httpbin/patch"; status_exception=false).status == 405
        @test isok(HTTP2.post("https://$httpbin/post"))
        @test isok(HTTP2.put("https://$httpbin/put"))
        @test isok(HTTP2.delete("https://$httpbin/delete"))
        @test isok(HTTP2.patch("https://$httpbin/patch"))
    end

    @testset "decompress" begin
        r = HTTP2.get("https://$httpbin/gzip")
        @test isok(r)
        @test isascii(String(r.body))
        r = HTTP2.get("https://$httpbin/gzip"; decompress=false)
        @test isok(r)
        @test !isascii(String(r.body))
        r = HTTP2.get("https://$httpbin/gzip"; decompress=true)
        @test isok(r)
        @test isascii(String(r.body))
    end

    # @testset "ASync Client Requests" begin
    #     @test isok(fetch(@async HTTP2.get("https://$httpbin/ip")))
    #     @test isok(HTTP2.get("https://$httpbin/encoding/utf8"))
    # end

    # @testset "Query to URI" begin
    #     r = HTTP2.get(URI(HTTP2.URI("https://$httpbin/response-headers"); query=Dict("hey"=>"dude")))
    #     h = Dict(r.headers)
    #     @test (haskey(h, "Hey") ? h["Hey"] == "dude" : h["hey"] == "dude")
    # end

    # @testset "Cookie Requests" begin
    #     empty!(HTTP2.COOKIEJAR)
    #     url = "https://$httpbin/cookies"
    #     r = HTTP2.get(url, cookies=true)
    #     @test String(r.body) == "{}"
    #     cookies = HTTP2.Cookies.getcookies!(HTTP2.COOKIEJAR, URI(url))
    #     @test isempty(cookies)

    #     url = "https://$httpbin/cookies/set?hey=sailor&foo=bar"
    #     r = HTTP2.get(url, cookies=true)
    #     @test isok(r)
    #     cookies = HTTP2.Cookies.getcookies!(HTTP2.COOKIEJAR, URI(url))
    #     @test length(cookies) == 2

    #     url = "https://$httpbin/cookies/delete?hey"
    #     r = HTTP2.get(url)
    #     cookies = HTTP2.Cookies.getcookies!(HTTP2.COOKIEJAR, URI(url))
    #     @test length(cookies) == 1
    # end

    # @testset "Client Streaming Test" begin
    #     r = HTTP2.post("https://$httpbin/post"; body="hey")
    #     @test isok(r)

    #     # stream, but body is too small to actually stream
    #     r = HTTP2.post("https://$httpbin/post"; body="hey", stream=true)
    #     @test isok(r)

    #     r = HTTP2.get("https://$httpbin/stream/100")
    #     @test isok(r)

    #     bytes = r.body
    #     a = [JSON.parse(l) for l in split(chomp(String(bytes)), "\n")]
    #     totallen = length(bytes) # number of bytes to expect

    #     io = IOBuffer()
    #     r = HTTP2.get("https://$httpbin/stream/100"; response_stream=io)
    #     seekstart(io)
    #     @test isok(r)

    #     b = [JSON.parse(l) for l in eachline(io)]
    #     @test all(zip(a, b)) do (x, y)
    #         x["args"] == y["args"] &&
    #         x["id"] == y["id"] &&
    #         x["url"] == y["url"] &&
    #         x["origin"] == y["origin"] &&
    #         x["headers"]["Content-Length"] == y["headers"]["Content-Length"] &&
    #         x["headers"]["Host"] == y["headers"]["Host"] &&
    #         x["headers"]["User-Agent"] == y["headers"]["User-Agent"]
    #     end

    #     # pass pre-allocated buffer
    #     body = zeros(UInt8, 100)
    #     r = HTTP2.get("https://$httpbin/bytes/100"; response_stream=body)
    #     @test body === r.body

    #     # wrapping pre-allocated buffer in IOBuffer will write to buffer directly
    #     io = IOBuffer(body; write=true)
    #     r = HTTP2.get("https://$httpbin/bytes/100"; response_stream=io)
    #     @test body === r.body.data

    #     # if provided buffer is too small, we won't grow it for user
    #     body = zeros(UInt8, 10)
    #     @test_throws HTTP2.RequestError HTTP2.get("https://$httpbin/bytes/100"; response_stream=body, retry=false)

    #     # also won't shrink it if buffer provided is larger than response body
    #     body = zeros(UInt8, 10)
    #     r = HTTP2.get("https://$httpbin/bytes/5"; response_stream=body)
    #     @test body === r.body
    #     @test length(body) == 10
    #     @test HTTP2.header(r, "Content-Length") == "5"

    #     # but if you wrap it in a writable IOBuffer, we will grow it
    #     io = IOBuffer(body; write=true)
    #     r = HTTP2.get("https://$httpbin/bytes/100"; response_stream=io)
    #     # same Array, though it was resized larger
    #     @test body === r.body.data
    #     @test length(body) == 100

    #     # and you can reuse it
    #     seekstart(io)
    #     r = HTTP2.get("https://$httpbin/bytes/100"; response_stream=io)
    #     # same Array, though it was resized larger
    #     @test body === r.body.data
    #     @test length(body) == 100

    #     # we respect ptr and size
    #     body = zeros(UInt8, 100)
    #     io = IOBuffer(body; write=true, append=true) # size=100, ptr=1
    #     r = HTTP2.get("https://$httpbin/bytes/100"; response_stream=io)
    #     @test length(body) == 200

    #     body = zeros(UInt8, 100)
    #     io = IOBuffer(body, write=true, append=false)
    #     write(io, body) # size=100, ptr=101
    #     r = HTTP2.get("https://$httpbin/bytes/100"; response_stream=io)
    #     @test length(body) == 200

    # end

    # @testset "Client Body Posting - Vector{UTF8}, String, IOStream, IOBuffer, BufferStream, Dict, NamedTuple" begin
    #     @test isok(HTTP2.post("https://$httpbin/post"; body="hey"))
    #     @test isok(HTTP2.post("https://$httpbin/post"; body=UInt8['h','e','y']))
    #     io = IOBuffer("hey"); seekstart(io)
    #     @test isok(HTTP2.post("https://$httpbin/post"; body=io))
    #     tmp = tempname()
    #     open(f->write(f, "hey"), tmp, "w")
    #     io = open(tmp)
    #     @test isok(HTTP2.post("https://$httpbin/post"; body=io, enablechunked=false))
    #     close(io); rm(tmp)
    #     f = Base.BufferStream()
    #     write(f, "hey")
    #     close(f)
    #     @test isok(HTTP2.post("https://$httpbin/post"; body=f, enablechunked=false))
    #     resp = HTTP2.post("https://$httpbin/post"; body=Dict("name" => "value"))
    #     @test isok(resp)
    #     x = JSON.parse(IOBuffer(resp.body))
    #     @test x["form"] == Dict("name" => ["value"])
    #     resp = HTTP2.post("https://$httpbin/post"; body=(name="value with spaces",))
    #     @test isok(resp)
    #     x = JSON.parse(IOBuffer(resp.body))
    #     @test x["form"] == Dict("name" => ["value with spaces"])
    # end

    # @testset "Chunksize" begin
    #     #     https://github.com/JuliaWeb/HTTP2.jl/issues/60
    #     #     Currently $httpbin responds with 411 status and “Length Required”
    #     #     message to any POST/PUT requests that are sent using chunked encoding
    #     #     See https://github.com/kennethreitz/httpbin/issues/340#issuecomment-330176449
    #     @test isok(HTTP2.post("https://$httpbin/post"; body="hey", #=chunksize=2=#))
    #     @test isok(HTTP2.post("https://$httpbin/post"; body=UInt8['h','e','y'], #=chunksize=2=#))
    #     io = IOBuffer("hey"); seekstart(io)
    #     @test isok(HTTP2.post("https://$httpbin/post"; body=io, #=chunksize=2=#))
    #     tmp = tempname()
    #     open(f->write(f, "hey"), tmp, "w")
    #     io = open(tmp)
    #     @test isok(HTTP2.post("https://$httpbin/post"; body=io, #=chunksize=2=#))
    #     close(io); rm(tmp)
    #     f = Base.BufferStream()
    #     write(f, "hey")
    #     close(f)
    #     @test isok(HTTP2.post("https://$httpbin/post"; body=f, #=chunksize=2=#))
    # end

    # @testset "ASync Client Request Body" begin
    #     f = Base.BufferStream()
    #     write(f, "hey")
    #     t = @async HTTP2.post("https://$httpbin/post"; body=f, enablechunked=false)
    #     #fetch(f) # fetch for the async call to write it's first data
    #     write(f, " there ") # as we write to f, it triggers another chunk to be sent in our async request
    #     write(f, "sailor")
    #     close(f) # setting eof on f causes the async request to send a final chunk and return the response
    #     @test isok(fetch(t))
    # end

    # @testset "Client Redirect Following - $read_method" for read_method in ["GET", "HEAD"]
    #     @test isok(HTTP2.request(read_method, "https://$httpbin/redirect/1"))
    #     @test HTTP2.request(read_method, "https://$httpbin/redirect/1", redirect=false).status == 302
    #     @test HTTP2.request(read_method, "https://$httpbin/redirect/6").status == 302 #over max number of redirects
    #     @test isok(HTTP2.request(read_method, "https://$httpbin/relative-redirect/1"))
    #     @test isok(HTTP2.request(read_method, "https://$httpbin/absolute-redirect/1"))
    #     @test isok(HTTP2.request(read_method, "https://$httpbin/redirect-to?url=http%3A%2F%2Fgoogle.com"))
    # end

    # @testset "Client Basic Auth" begin
    #     @test isok(HTTP2.get("https://user:pwd@$httpbin/basic-auth/user/pwd"))
    #     @test isok(HTTP2.get("https://user:pwd@$httpbin/hidden-basic-auth/user/pwd"))
    #     @test isok(HTTP2.get("https://test:%40test@$httpbin/basic-auth/test/%40test"))
    # end

    # @testset "Misc" begin
    #     @test isok(HTTP2.post("https://$httpbin/post"; body="√"))
    #     r = HTTP2.request("GET", "https://$httpbin/ip")
    #     @test isok(r)

    #     uri = HTTP2.URI("https://$httpbin/ip")
    #     r = HTTP2.request("GET", uri)
    #     @test isok(r)
    #     r = HTTP2.get(uri)
    #     @test isok(r)

    #     r = HTTP2.request("GET", "https://$httpbin/ip")
    #     @test isok(r)

    #     uri = HTTP2.URI("https://$httpbin/ip")
    #     r = HTTP2.request("GET", uri)
    #     @test isok(r)

    #     r = HTTP2.get("https://$httpbin/image/png")
    #     @test isok(r)

    #     # ensure we can use AbstractString for requests
    #     r = HTTP2.get(SubString("https://$httpbin/ip",1))

    #     # canonicalizeheaders
    #     @test isok(HTTP2.get("https://$httpbin/ip"; canonicalizeheaders=false))

    #     # Ensure HEAD requests stay the same through redirects by default
    #     r = HTTP2.head("https://$httpbin/redirect/1")
    #     @test r.request.method == "HEAD"
    #     @test iszero(length(r.body))
    #     # But if explicitly requested, GET can be used instead
    #     r = HTTP2.head("https://$httpbin/redirect/1"; redirect_method="GET")
    #     @test r.request.method == "GET"
    #     @test length(r.body) > 0
    # end
end
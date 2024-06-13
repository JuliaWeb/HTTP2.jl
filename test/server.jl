using Test, HTTP2

@testset "HTTP.serve" begin
    server = HTTP2.serve!(req -> HTTP2.Response(200, "Hello, World!"))
    @test server.state == :running
    resp = HTTP2.get("http://127.0.0.1:8080")
    @test resp.status == 200
    @test String(resp.body) == "Hello, World!"
end
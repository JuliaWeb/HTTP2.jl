using HTTP2, Test

@testset "Handlers" begin

    called = Ref{Bool}(false)
    middle = handler -> req -> begin
        called[] = true
        return handler(req)
    end
    r = HTTP2.Router(_ -> 0, _ -> -1, middle)
    HTTP2.register!(r, "/test", _ -> 1)
    @test r(HTTP2.Request("GET", "/test")) == 1
    @test called[]

    HTTP2.register!(r, "/path/to/greatness", _ -> 2)
    @test r(HTTP2.Request("GET", "/path/to/greatness")) == 2

    HTTP2.register!(r, "/next/path/to/greatness", _ -> 3)
    @test r(HTTP2.Request("GET", "/next/path/to/greatness")) == 3

    HTTP2.register!(r, "GET", "/sget", _ -> 4)
    HTTP2.register!(r, "POST", "/spost", _ -> 5)
    HTTP2.register!(r, "POST", "/tpost", _ -> 6)
    HTTP2.register!(r, "GET", "/tpost", _ -> 7)
    @test r(HTTP2.Request("GET", "/sget")) == 4
    called[] = false
    @test r(HTTP2.Request("POST", "/sget")) == -1
    @test !called[]
    @test r(HTTP2.Request("GET", "/spost")) == -1
    @test r(HTTP2.Request("POST", "/spost")) == 5
    @test r(HTTP2.Request("POST", "/tpost")) == 6
    @test r(HTTP2.Request("GET", "/tpost")) == 7

    HTTP2.register!(r, "/test/*", _ -> 8)
    HTTP2.register!(r, "/test/sarv/ghotra", _ -> 9)
    HTTP2.register!(r, "/test/*/ghotra/seven", _ -> 10)

    @test r(HTTP2.Request("GET", "/test/sarv")) == 8
    @test r(HTTP2.Request("GET", "/test/sarv/ghotra")) == 9
    @test r(HTTP2.Request("GET", "/test/sarv/ghotra/seven")) == 10
    @test r(HTTP2.Request("GET", "/test/foo")) == 8

    HTTP2.register!(r, "/api/issue/{issue_id}", req -> HTTP2.getparams(req)["issue_id"])
    @test r(HTTP2.Request("GET", "/api/issue/871")) == "871"

    HTTP2.register!(r, "/api/widgets/{id}", req -> HTTP2.getparam(req, "id"))
    @test r(HTTP2.Request("GET", "/api/widgets/11")) == "11"

    HTTP2.register!(r, "/api/widgets/{name}", req -> (req.context[:params]["name"], HTTP2.getroute(req)))
    @test r(HTTP2.Request("GET", "/api/widgets/11")) == ("11", "/api/widgets/{name}")

    HTTP2.register!(r, "/api/widgets/acme/{id:[a-z]+}", req -> req.context[:params]["id"])
    called[] = false
    @test r(HTTP2.Request("GET", "/api/widgets/acme/11")) == 0
    @test !called[]
    @test r(HTTP2.Request("GET", "/api/widgets/acme/abc")) == "abc"

    HTTP2.register!(r, "/test/**", _ -> 11)
    @test r(HTTP2.Request("GET", "/test/sarv")) == 8
    @test r(HTTP2.Request("GET", "/test/sarv/ghotra")) == 9
    @test r(HTTP2.Request("GET", "/test/sarv/ghotra/seven")) == 10
    @test r(HTTP2.Request("GET", "/test/foo")) == 8
    @test r(HTTP2.Request("GET", "/test/foo/foobar")) == 11
    @test r(HTTP2.Request("GET", "/test/foo/foobar/baz")) == 11
    @test r(HTTP2.Request("GET", "/test/foo/foobar/baz/sailor")) == 11

    @test_throws ErrorException HTTP2.register!(r, "/test/**/foo", _ -> 11)

    HTTP2.register!(r, "/api/widgets/{name:[a-z]+}/subwidgetsbyname", _ -> 12)
    HTTP2.register!(r, "/api/widgets/{id:[0-9]+}/subwidgetsbyid", _ -> 13)
    HTTP2.register!(r, "/api/widgets/{id}", _ -> 14)
    HTTP2.register!(r, "/api/widgets/{subId}/subwidget", _ -> 15)
    HTTP2.register!(r, "/api/widgets/{subName}/subwidgetname", _ -> 16)
    @test r(HTTP2.Request("GET", "/api/widgets/abc/subwidgetsbyname")) == 12
    @test r(HTTP2.Request("GET", "/api/widgets/123/subwidgetsbyid")) == 13
    @test r(HTTP2.Request("GET", "/api/widgets/234")) == 14
    @test r(HTTP2.Request("GET", "/api/widgets/abc/subwidget")) == 15
    @test r(HTTP2.Request("GET", "/api/widgets/abc/subwidgetname")) == 16

    # cookie = HTTP2.Cookie("abc", "def")
    # req = HTTP2.Request("GET", "/")
    # req.context[:cookies] = [cookie]
    # @test HTTP2.getcookies(req)[1] == cookie
end

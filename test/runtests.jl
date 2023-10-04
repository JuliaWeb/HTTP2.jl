using Test, HTTP2 # , JSONBase

const httpbin = get(ENV, "JULIA_TEST_HTTPBINGO_SERVER", "httpbingo.julialang.org")

include("utils.jl")
include("client.jl")
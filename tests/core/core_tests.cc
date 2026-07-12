#include <cassert>
#include <iostream>

#include "cookie_jar.h"
#include "header_list.h"
#include "redirect.h"
#include "url.h"

using namespace kathttp;
int main() {
    Url u;
    assert(parse_url("https://example.com/a?q=1#ignored", u));
    assert(u.host == "example.com" && u.request_target() == "/a?q=1");
    assert(!parse_url("http://example.com", u));
    assert(!parse_url("https://example.com:99999/", u));
    assert(parse_url("https://[::1]:443/", u));
    HeaderList h;
    h.add("Content-Type", "text/plain");
    assert(h.get("content-type") == "text/plain");
    Response response;
    response.status_code = 303;
    response.headers.add("location", "/next");
    Url from;
    assert(parse_url("https://example.com/a/b", from));
    RedirectPolicy redirects;
    auto d = redirects.evaluate("POST", from, response, true, 3);
    assert(d.follow && d.new_method == "GET" && d.new_url == "https://example.com/next");
    CookieJar jar;
    HeaderList set;
    set.add("set-cookie", "a=b; Secure; Path=/");
    jar.store(from, set);
    const auto cookie = jar.cookie_header(from);
    assert(cookie == "a=b");
    std::cout << "core tests passed\n";
}

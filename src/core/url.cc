#include "url.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdlib>

namespace kathttp3 {

uint16_t default_port(std::string_view scheme) {
    if (scheme == "https") return 443;
    if (scheme == "http") return 80;
    return 443;
}

std::string Url::authority() const {
    std::string a = host;
    uint16_t p = port ? port : default_port(scheme);
    // Omit the port when it is the scheme default.
    if (p != default_port(scheme)) {
        a += ':';
        a += std::to_string(p);
    }
    return a;
}

std::string Url::request_target() const {
    if (!path.empty()) {
        return query.empty() ? path : path + "?" + query;
    }
    return query.empty() ? "/" : ("/?" + query);
}

std::string Url::to_string() const {
    std::string s = scheme;
    s += "://";
    s += authority();
    s += request_target();
    return s;
}

bool parse_url(std::string_view raw, Url& out) {
    out = Url{};
    if (raw.empty()) return false;

    size_t pos = 0;
    // scheme
    auto colon = raw.find(':');
    if (colon == std::string_view::npos) return false;
    out.scheme = std::string(raw.substr(0, colon));
    std::transform(out.scheme.begin(), out.scheme.end(), out.scheme.begin(), ::tolower);
    pos = colon + 1;
    if (out.scheme != "https") return false;
    if (raw.substr(pos, 2) != "//") return false;
    pos += 2;

    // authority: up to '/', '?', '#' or end
    size_t auth_end = raw.find_first_of("/?#", pos);
    std::string_view auth = raw.substr(pos, auth_end - pos);
    if (auth.empty()) return false;

    size_t at = auth.find('@');
    if (at != std::string_view::npos) return false;

    bool ipv6 = false;
    if (auth.size() >= 2 && auth.front() == '[') {
        auto close = auth.find(']');
        if (close == std::string_view::npos) return false;
        out.host = std::string(auth.substr(1, close - 1));
        ipv6 = true;
        size_t p = close + 1;
        if (p < auth.size() && auth[p] == ':') {
            unsigned value = 0;
            auto ps = auth.substr(p + 1);
            auto rc = std::from_chars(ps.data(), ps.data() + ps.size(), value);
            if (ps.empty() || rc.ec != std::errc{} || rc.ptr != ps.data() + ps.size() ||
                value == 0 || value > 65535)
                return false;
            out.port = static_cast<uint16_t>(value);
        }
    } else {
        auto pcolon = auth.rfind(':');
        if (pcolon != std::string_view::npos) {
            out.host = std::string(auth.substr(0, pcolon));
            unsigned value = 0;
            auto ps = auth.substr(pcolon + 1);
            auto rc = std::from_chars(ps.data(), ps.data() + ps.size(), value);
            if (ps.empty() || rc.ec != std::errc{} || rc.ptr != ps.data() + ps.size() ||
                value == 0 || value > 65535)
                return false;
            out.port = static_cast<uint16_t>(value);
        } else {
            out.host = std::string(auth);
        }
    }
    (void)ipv6;

    if (out.host.empty()) return false;

    // path / query
    std::string_view rest = auth_end == std::string_view::npos ? "" : raw.substr(auth_end);
    auto fragment = rest.find('#');
    if (fragment != std::string_view::npos) rest = rest.substr(0, fragment);
    auto q = rest.find('?');
    if (q == std::string_view::npos) {
        out.path = std::string(rest);
    } else {
        out.path = std::string(rest.substr(0, q));
        out.query = std::string(rest.substr(q + 1));
    }
    return out.valid();
}

} /* namespace kathttp3 */

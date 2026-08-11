#include "url.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdlib>

namespace kathttp3 {

namespace {

bool ascii_alpha(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool ascii_digit(unsigned char c) {
    return c >= '0' && c <= '9';
}

bool hex_digit(unsigned char c) {
    return ascii_digit(c) || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

bool unreserved(unsigned char c) {
    return ascii_alpha(c) || ascii_digit(c) || c == '-' || c == '.' || c == '_' || c == '~';
}

bool sub_delimiter(unsigned char c) {
    return c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' || c == '*' ||
           c == '+' || c == ',' || c == ';' || c == '=';
}

bool valid_uri_component(std::string_view value, std::string_view extra) {
    for (size_t i = 0; i < value.size(); ++i) {
        const auto c = static_cast<unsigned char>(value[i]);
        if (c == '%') {
            if (i + 2 >= value.size() || !hex_digit(static_cast<unsigned char>(value[i + 1])) ||
                !hex_digit(static_cast<unsigned char>(value[i + 2]))) {
                return false;
            }
            i += 2;
            continue;
        }
        if (!unreserved(c) && !sub_delimiter(c) &&
            extra.find(static_cast<char>(c)) == std::string_view::npos) {
            return false;
        }
    }
    return true;
}

bool https_scheme(std::string_view scheme) {
    constexpr std::string_view expected = "https";
    if (scheme.size() != expected.size()) return false;
    for (size_t i = 0; i < scheme.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(scheme[i]);
        if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c + ('a' - 'A'));
        if (c != static_cast<unsigned char>(expected[i])) return false;
    }
    return true;
}

}  // namespace

uint16_t default_port(std::string_view scheme) {
    if (scheme == "https") return 443;
    if (scheme == "http") return 80;
    return 443;
}

std::string Url::authority() const {
    std::string a = host.find(':') == std::string::npos ? host : "[" + host + "]";
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
    if (!https_scheme(raw.substr(0, colon))) return false;
    out.scheme = "https";
    pos = colon + 1;
    if (raw.substr(pos, 2) != "//") return false;
    pos += 2;

    // authority: up to '/', '?', '#' or end
    size_t auth_end = raw.find_first_of("/?#", pos);
    std::string_view auth = raw.substr(pos, auth_end - pos);
    if (auth.empty()) return false;

    size_t at = auth.find('@');
    if (at != std::string_view::npos) return false;

    const bool bracketed_ipv6 = auth.size() >= 2 && auth.front() == '[';
    if (bracketed_ipv6) {
        auto close = auth.find(']');
        if (close == std::string_view::npos) return false;
        out.host = std::string(auth.substr(1, close - 1));
        in6_addr address{};
        if (inet_pton(AF_INET6, out.host.c_str(), &address) != 1) return false;
        size_t p = close + 1;
        if (p < auth.size()) {
            if (auth[p] != ':') return false;
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
            if (out.host.find(':') != std::string::npos) return false;
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
    if (out.host.empty()) return false;
    if (!bracketed_ipv6 && !valid_uri_component(out.host, "")) return false;

    // path / query
    std::string_view rest = auth_end == std::string_view::npos ? "" : raw.substr(auth_end);
    auto fragment = rest.find('#');
    if (fragment != std::string_view::npos) {
        if (!valid_uri_component(rest.substr(fragment + 1), ":@/?")) return false;
        rest = rest.substr(0, fragment);
    }
    auto q = rest.find('?');
    if (q == std::string_view::npos) {
        if (!valid_uri_component(rest, ":@/")) return false;
        out.path = std::string(rest);
    } else {
        if (!valid_uri_component(rest.substr(0, q), ":@/") ||
            !valid_uri_component(rest.substr(q + 1), ":@/?")) {
            return false;
        }
        out.path = std::string(rest.substr(0, q));
        out.query = std::string(rest.substr(q + 1));
    }
    return out.valid();
}

} /* namespace kathttp3 */

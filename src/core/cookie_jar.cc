#include "cookie_jar.h"

#include <arpa/inet.h>

#include <algorithm>
#include <charconv>
#include <ctime>
#include <string>

namespace kathttp3 {

static std::string to_lower(std::string_view s) {
    std::string o(s);
    std::transform(o.begin(), o.end(), o.begin(), [](unsigned char c) { return std::tolower(c); });
    return o;
}

static std::string_view trim(std::string_view s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string_view::npos) return "";
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

static bool valid_cookie_token(std::string_view value) {
    if (value.empty()) return false;
    for (char raw : value) {
        const auto c = static_cast<unsigned char>(raw);
        if (c <= 0x20 || c == 0x7f || c == ';' || c == ',' || c == '=') return false;
    }
    return true;
}

static bool ip_literal(std::string_view host) {
    std::string h(host);
    in_addr v4{};
    in6_addr v6{};
    return inet_pton(AF_INET, h.c_str(), &v4) == 1 || inet_pton(AF_INET6, h.c_str(), &v6) == 1;
}

static std::string default_path(const Url& url) {
    if (url.path.empty() || url.path.front() != '/') return "/";
    const auto slash = url.path.find_last_of('/');
    return slash == 0 || slash == std::string::npos ? "/" : url.path.substr(0, slash);
}

bool CookieJar::domain_matches(std::string_view cookie_domain, bool host_only,
                               std::string_view host) const {
    std::string h = to_lower(host);
    std::string cd = to_lower(cookie_domain);
    if (cd.empty()) return false;
    if (host_only) return h == cd;
    if (cd.front() == '.') cd.erase(0, 1);
    if (h == cd) return true;
    return h.size() > cd.size() && h[h.size() - cd.size() - 1] == '.' &&
           h.compare(h.size() - cd.size(), cd.size(), cd) == 0;
}

bool CookieJar::path_matches(std::string_view cookie_path, std::string_view req_path) const {
    if (cookie_path.empty()) return true;
    if (req_path.size() < cookie_path.size()) return false;
    if (!std::equal(cookie_path.begin(), cookie_path.end(), req_path.begin())) return false;
    return cookie_path.back() == '/' || req_path.size() == cookie_path.size() ||
           req_path[cookie_path.size()] == '/';
}

void CookieJar::store(const Url& url, const HeaderList& headers) {
    for (auto v : headers.get_all("set-cookie")) store(url, v);
}

void CookieJar::store(const Url& url, std::string_view set_cookie) {
    auto semi = set_cookie.find(';');
    std::string_view first = trim(set_cookie.substr(0, semi));
    auto eq = first.find('=');
    if (eq == std::string_view::npos) return;
    Cookie c;
    c.name = std::string(trim(first.substr(0, eq)));
    c.value = std::string(trim(first.substr(eq + 1)));
    if (!valid_cookie_token(c.name) || c.value.find_first_of("\r\n;") != std::string::npos) return;
    c.path = default_path(url);

    std::string_view rest = semi == std::string_view::npos ? "" : set_cookie.substr(semi + 1);
    while (!rest.empty()) {
        auto sc = rest.find(';');
        std::string_view attr = trim(rest.substr(0, sc));
        auto aeq = attr.find('=');
        std::string_view an = trim(attr.substr(0, aeq));
        std::string_view av = aeq == std::string_view::npos ? "" : trim(attr.substr(aeq + 1));
        std::string anl = to_lower(an);
        if (anl == "domain") {
            c.domain = std::string(trim(av));
            if (!c.domain.empty() && c.domain.front() == '.') c.domain.erase(0, 1);
            if (c.domain.empty() || ip_literal(url.host)) return;
            c.host_only = false;
        } else if (anl == "path") {
            c.path = (!av.empty() && av.front() == '/') ? std::string(av) : default_path(url);
        } else if (anl == "secure") {
            c.secure = true;
        } else if (anl == "httponly") {
            c.http_only = true;
        } else if (anl == "max-age") {
            int64_t secs = 0;
            const auto value = trim(av);
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), secs);
            if (!value.empty() && parsed.ec == std::errc{} &&
                parsed.ptr == value.data() + value.size()) {
                c.persistent = true;
                c.expiry = secs <= 0 ? 1
                                     : static_cast<uint64_t>(std::time(nullptr)) +
                                           static_cast<uint64_t>(secs);
            }
        } else if (anl == "expires") {
            // Best-effort: rely on max-age if present; otherwise store as
            // persistent and let it expire at process end (not parsing HTTP date
            // fully here).
            c.persistent = true;
        }
        if (sc == std::string_view::npos) break;
        rest = rest.substr(sc + 1);
    }

    if (c.domain.empty()) {
        c.domain = url.host;
        c.host_only = true;
    }
    if (!domain_matches(c.domain, c.host_only, url.host)) return;

    std::lock_guard<std::mutex> lk(mu_);
    // Replace any existing cookie with same name+domain+path.
    for (auto& existing : cookies_) {
        if (existing.name == c.name && existing.domain == c.domain && existing.path == c.path) {
            existing = std::move(c);
            return;
        }
    }
    size_t domain_count = 0;
    for (const auto& existing : cookies_)
        if (existing.domain == c.domain) ++domain_count;
    if (domain_count >= 50) return;
    if (cookies_.size() >= 300) cookies_.erase(cookies_.begin());
    cookies_.push_back(std::move(c));
}

std::string CookieJar::cookie_header(const Url& url) {
    std::lock_guard<std::mutex> lk(mu_);
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    std::vector<std::string> pairs;
    for (auto it = cookies_.begin(); it != cookies_.end();) {
        if (it->persistent && it->expiry && now >= it->expiry) {
            it = cookies_.erase(it);
        } else {
            ++it;
        }
    }
    for (const auto& c : cookies_) {
        if (c.secure && url.scheme != "https") continue;
        if (!domain_matches(c.domain, c.host_only, url.host)) continue;
        if (!path_matches(c.path, url.request_target())) continue;
        pairs.push_back(c.name + "=" + c.value);
    }
    std::string out;
    for (size_t i = 0; i < pairs.size(); ++i) {
        if (i) out += "; ";
        out += pairs[i];
    }
    return out;
}

} /* namespace kathttp3 */

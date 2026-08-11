#include "cookie_jar.h"

#include <arpa/inet.h>

#include <algorithm>
#include <charconv>
#include <ctime>
#include <limits>
#include <string>
#include <vector>

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

static bool cookie_date_delimiter(unsigned char c) {
    return c == 0x09 || (c >= 0x20 && c <= 0x2f) || (c >= 0x3b && c <= 0x40) ||
           (c >= 0x5b && c <= 0x60) || (c >= 0x7b && c <= 0x7e);
}

static bool parse_decimal(std::string_view token, size_t min_digits, size_t max_digits, int& out) {
    if (token.size() < min_digits || token.size() > max_digits) return false;
    for (const char c : token) {
        if (c < '0' || c > '9') return false;
    }
    const auto parsed = std::from_chars(token.data(), token.data() + token.size(), out);
    return parsed.ec == std::errc{} && parsed.ptr == token.data() + token.size();
}

static bool parse_cookie_time(std::string_view token, int& hour, int& minute, int& second) {
    const auto first = token.find(':');
    if (first == std::string_view::npos) return false;
    const auto second_colon = token.find(':', first + 1);
    if (second_colon == std::string_view::npos ||
        token.find(':', second_colon + 1) != std::string_view::npos) {
        return false;
    }
    return parse_decimal(token.substr(0, first), 1, 2, hour) &&
           parse_decimal(token.substr(first + 1, second_colon - first - 1), 1, 2, minute) &&
           parse_decimal(token.substr(second_colon + 1), 1, 2, second);
}

static int cookie_month(std::string_view token) {
    if (token.size() < 3) return 0;
    char prefix[3];
    for (size_t i = 0; i < 3; ++i) {
        unsigned char c = static_cast<unsigned char>(token[i]);
        if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c + ('a' - 'A'));
        prefix[i] = static_cast<char>(c);
    }
    constexpr const char* months[] = {"jan", "feb", "mar", "apr", "may", "jun",
                                      "jul", "aug", "sep", "oct", "nov", "dec"};
    for (int month = 1; month <= 12; ++month) {
        if (std::equal(prefix, prefix + 3, months[month - 1])) return month;
    }
    return 0;
}

static bool leap_year(int year) {
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int days_in_month(int year, int month) {
    constexpr int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return month == 2 && leap_year(year) ? 29 : days[month - 1];
}

static int64_t days_from_civil(int year, unsigned month, unsigned day) {
    year -= month <= 2;
    const int era = (year >= 0 ? year : year - 399) / 400;
    const unsigned year_of_era = static_cast<unsigned>(year - era * 400);
    const unsigned adjusted_month = month > 2 ? month - 3 : month + 9;
    const unsigned day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    const unsigned day_of_era =
        year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    return static_cast<int64_t>(era) * 146097 + static_cast<int64_t>(day_of_era) - 719468;
}

static bool parse_cookie_expiry(std::string_view value, uint64_t& expiry) {
    std::vector<std::string_view> tokens;
    for (size_t pos = 0; pos < value.size();) {
        while (pos < value.size() && cookie_date_delimiter(static_cast<unsigned char>(value[pos])))
            ++pos;
        const size_t begin = pos;
        while (pos < value.size() && !cookie_date_delimiter(static_cast<unsigned char>(value[pos])))
            ++pos;
        if (begin != pos) tokens.push_back(value.substr(begin, pos - begin));
    }

    bool found_time = false;
    bool found_day = false;
    bool found_month = false;
    bool found_year = false;
    int hour = 0;
    int minute = 0;
    int second = 0;
    int day = 0;
    int month = 0;
    int year = 0;
    for (const auto token : tokens) {
        if (!found_time && parse_cookie_time(token, hour, minute, second)) {
            found_time = true;
            continue;
        }
        if (!found_day && parse_decimal(token, 1, 2, day)) {
            found_day = true;
            continue;
        }
        if (!found_month && (month = cookie_month(token)) != 0) {
            found_month = true;
            continue;
        }
        if (!found_year && parse_decimal(token, 2, 4, year)) found_year = true;
    }
    if (!found_time || !found_day || !found_month || !found_year) return false;
    if (year >= 70 && year <= 99)
        year += 1900;
    else if (year <= 69)
        year += 2000;
    if (year < 1601 || day < 1 || day > days_in_month(year, month) || hour > 23 || minute > 59 ||
        second > 59) {
        return false;
    }

    const int64_t timestamp =
        days_from_civil(year, static_cast<unsigned>(month), static_cast<unsigned>(day)) * 86400 +
        hour * 3600 + minute * 60 + second;
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    expiry = timestamp <= now ? 1 : static_cast<uint64_t>(timestamp);
    return true;
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
    bool max_age_seen = false;

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
                max_age_seen = true;
                const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
                const uint64_t delta = secs > 0 ? static_cast<uint64_t>(secs) : 0;
                c.expiry = secs <= 0 ? 1
                                     : (delta > std::numeric_limits<uint64_t>::max() - now
                                            ? std::numeric_limits<uint64_t>::max()
                                            : now + delta);
            }
        } else if (anl == "expires") {
            uint64_t expiry = 0;
            if (!max_age_seen && parse_cookie_expiry(av, expiry)) {
                c.persistent = true;
                c.expiry = expiry;
            }
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
    std::vector<const Cookie*> selected;
    for (auto it = cookies_.begin(); it != cookies_.end();) {
        if (it->persistent && it->expiry && now >= it->expiry) {
            it = cookies_.erase(it);
        } else {
            ++it;
        }
    }
    std::string_view request_path = "/";
    if (!url.path.empty()) request_path = url.path;
    for (const auto& c : cookies_) {
        if (c.secure && url.scheme != "https") continue;
        if (!domain_matches(c.domain, c.host_only, url.host)) continue;
        if (!path_matches(c.path, request_path)) continue;
        selected.push_back(&c);
    }
    std::stable_sort(selected.begin(), selected.end(), [](const Cookie* lhs, const Cookie* rhs) {
        return lhs->path.size() > rhs->path.size();
    });
    std::string out;
    for (size_t i = 0; i < selected.size(); ++i) {
        if (i) out += "; ";
        out += selected[i]->name;
        out += '=';
        out += selected[i]->value;
    }
    return out;
}

} /* namespace kathttp3 */

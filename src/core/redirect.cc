#include "redirect.h"

#include "log.h"

namespace kathttp3 {

static bool is_redirect_status(int s) {
    return s == 301 || s == 302 || s == 303 || s == 307 || s == 308;
}

RedirectDecision RedirectPolicy::evaluate(const std::string& method, const Url& from,
                                          const Response& resp, bool auto_redirect,
                                          unsigned remaining) const {
    RedirectDecision d{false, false, "", method};
    if (!auto_redirect) return d;
    if (!is_redirect_status(resp.status_code)) return d;
    if (remaining == 0) {
        KATHTTP3_LOG_WARN("redirect budget exhausted for %s\n", from.host.c_str());
        return d;
    }

    std::string location(resp.headers.get("location"));
    if (location.empty()) return d;

    // Resolve relative references against `from`.
    Url to;
    if (location.find("://") != std::string::npos) {
        if (!parse_url(location, to)) return d;
    } else {
        to.scheme = from.scheme;
        to.host = from.host;
        to.port = from.port;
        if (!location.empty() && location.front() == '/') {
            to.path = location;
        } else {
            // relative path: replace the last segment of `from.path`
            auto slash = from.path.find_last_of('/');
            std::string base = slash == std::string::npos ? "/" : from.path.substr(0, slash + 1);
            to.path = base + location;
        }
        auto q = to.path.find('?');
        if (q != std::string::npos) {
            to.query = to.path.substr(q + 1);
            to.path = to.path.substr(0, q);
        }
    }
    // Refuse downgrades to plaintext (KatHttp3 is HTTPS-only).
    if (to.scheme != "https") return d;
    if (!to.valid()) return d;

    // 301/302/303 switch to GET (dropping the body); 307/308 preserve method.
    if ((resp.status_code == 301 || resp.status_code == 302 || resp.status_code == 303) &&
        method != "HEAD") {
        d.new_method = "GET";
    } else {
        d.new_method = method;
    }

    d.new_url = to.to_string();
    d.cross_origin = from.scheme != to.scheme || from.host != to.host ||
                     (from.port ? from.port : default_port(from.scheme)) !=
                         (to.port ? to.port : default_port(to.scheme));
    d.follow = true;
    return d;
}

} /* namespace kathttp3 */

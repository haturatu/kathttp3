#ifndef KATHTTP3_COOKIE_JAR_H
#define KATHTTP3_COOKIE_JAR_H

#include <mutex>
#include <string>
#include <vector>

#include "header_list.h"
#include "url.h"

namespace kathttp3 {

struct Cookie {
    std::string name;
    std::string value;
    std::string domain;
    std::string path = "/";
    bool secure = false;
    bool http_only = false;
    bool host_only = true; /* domain attribute absent => exact host only */
    bool persistent = false;
    uint64_t expiry = 0; /* unix seconds; 0 == session cookie */
};

/* Thread-safe cookie store. Parses Set-Cookie response headers and produces
 * the Cookie request header for a given URL (RFC 6265). */
class CookieJar {
   public:
    /* Ingest all Set-Cookie headers from `headers` for origin `url`. */
    void store(const Url& url, const HeaderList& headers);

    /* Append a single Set-Cookie value. */
    void store(const Url& url, std::string_view set_cookie);

    /* Build the "Cookie" header value for a request to `url`. */
    std::string cookie_header(const Url& url);

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        cookies_.clear();
    }

   private:
    bool domain_matches(std::string_view cookie_domain, bool host_only,
                        std::string_view host) const;
    bool path_matches(std::string_view cookie_path, std::string_view req_path) const;

    std::mutex mu_;
    std::vector<Cookie> cookies_;
};

} /* namespace kathttp3 */

#endif /* KATHTTP3_COOKIE_JAR_H */

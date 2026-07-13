#ifndef KATHTTP3_URL_H
#define KATHTTP3_URL_H

#include <cstdint>
#include <string>

namespace kathttp3 {

/* Minimal RFC 3986-ish URL parser. For HTTP/3 we only need
 * scheme / authority (host[:port]) / path?query. */
struct Url {
    std::string scheme;
    std::string host;
    uint16_t port = 0;
    std::string path;  /* includes the leading '/' and the query string */
    std::string query; /* without the leading '?' */

    bool valid() const {
        return !scheme.empty() && !host.empty();
    }

    /* authority = host[:port]; if port is 0 the scheme default is implied. */
    std::string authority() const;
    /* path-and-query; defaults to "/" when empty. */
    std::string request_target() const;
    /* Full normalized URL: scheme://authority + request_target(). */
    std::string to_string() const;
};

/* Returns the default port for a scheme (443 for https). */
uint16_t default_port(std::string_view scheme);

bool parse_url(std::string_view raw, Url& out);

} /* namespace kathttp3 */

#endif /* KATHTTP3_URL_H */

#ifndef KATHTTP3_REQUEST_H
#define KATHTTP3_REQUEST_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "header_list.h"

/* Engine-side definition of the opaque kathttp3_request handle. The C ABI
 * functions in request.cc operate on this type. */
struct kathttp3_request {
    std::string method;
    std::string url;
    kathttp3::HeaderList headers;
    std::vector<uint8_t> body;
    bool streaming_body = false;
    int64_t streaming_body_length = -1; /* -1 = unknown */
    int follow_redirects = 1;
    int streaming = 0; /* 1 = streaming (Flow) request: apply HTTP/3
                         receive flow-control (window extended only as
                         the application consumes body chunks) */
    /* Optional pre-resolved endpoints (IPv4/IPv6 string + port). When
     * non-empty the engine skips its own DNS resolver and races these. */
    std::vector<std::pair<std::string, uint16_t>> addresses;
};

#endif /* KATHTTP3_REQUEST_H */

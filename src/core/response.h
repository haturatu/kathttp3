#ifndef KATHTTP3_RESPONSE_H
#define KATHTTP3_RESPONSE_H

#include <cstdint>
#include <string>
#include <vector>

#include "header_list.h"
#include "url.h"

namespace kathttp3 {

/* Accumulated result of a single HTTP/3 exchange. Built incrementally by
 * Http3Session callbacks and handed to the engine's completion path. */
struct Response {
    int status_code = 0;
    HeaderList headers;
    std::vector<uint8_t> body;
    Url url; /* the URL that actually produced this response */
    bool headers_done = false;

    void add_header(std::string name, std::string value) {
        headers.add(std::move(name), std::move(value));
    }
};

} /* namespace kathttp3 */

#endif /* KATHTTP3_RESPONSE_H */

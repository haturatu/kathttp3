#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "cookie_jar.h"
#include "header_list.h"
#include "url.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    const size_t origin_len = static_cast<size_t>(data[0]) % size;
    const std::string_view origin(reinterpret_cast<const char*>(data), origin_len);
    const std::string_view set_cookie(reinterpret_cast<const char*>(data) + origin_len,
                                     size - origin_len);

    kathttp3::Url url;
    if (!kathttp3::parse_url("https://example.com:8443", url)) return 0;
    url.path = std::string(origin);

    kathttp3::CookieJar jar;
    jar.store(url, set_cookie);
    (void)jar.cookie_header(url);
    return 0;
}
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "redirect.h"
#include "url.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0;
    const size_t method_len = static_cast<size_t>(data[0]) % size;
    const size_t location_len = static_cast<size_t>(data[1]) % (size - method_len);
    const size_t base_len = size - method_len - location_len;

    const std::string method(reinterpret_cast<const char*>(data), method_len);
    const std::string location(reinterpret_cast<const char*>(data) + method_len, location_len);
    const std::string base(reinterpret_cast<const char*>(data) + method_len + location_len,
                           base_len);

    kathttp3::Url from;
    if (base_len == 0 || !kathttp3::parse_url(base, from)) return 0;

    kathttp3::Response response;
    constexpr int kRedirectStatuses[] = {301, 302, 303, 307, 308};
    response.status_code = kRedirectStatuses[data[2] % 5];
    response.headers.add("location", location);

    kathttp3::RedirectPolicy policy;
    (void)policy.evaluate(method, from, response, (data[3] & 1u) != 0, (data[3] >> 1) & 0x7fu);
    return 0;
}
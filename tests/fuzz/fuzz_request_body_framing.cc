#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "kathttp3.h"
#include "request.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 3) return 0;
    const size_t name_len = static_cast<size_t>(data[0]) % size;
    const size_t value_len = static_cast<size_t>(data[1]) % (size - name_len);
    const std::string name(reinterpret_cast<const char*>(data), name_len);
    const std::string value(reinterpret_cast<const char*>(data) + name_len, value_len);
    const size_t body_len = size - name_len - value_len;

    kathttp3_request* request = kathttp3_request_create("POST", "https://example.com/upload");
    if (request == nullptr) return 0;
    (void)kathttp3_request_add_header(request, name.c_str(), value.c_str());
    (void)kathttp3_request_set_body(request, data + name_len + value_len, body_len);
    (void)kathttp3::validate_request_body_framing(*request);
    kathttp3_request_destroy(request);
    return 0;
}
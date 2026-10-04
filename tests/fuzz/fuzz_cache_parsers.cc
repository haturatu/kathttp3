#include <cstddef>
#include <string>

#include "cache_control.h"
#include "http_date.h"

using namespace kathttp3;

extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data, size_t size) {
    const std::string value(reinterpret_cast<const char*>(data), size);
    HeaderList headers;
    headers.add("cache-control", value);
    headers.add("date", value);
    headers.add("expires", value);
    headers.add("age", value);
    (void)parse_cache_control(headers);
    (void)parse_http_date(value, 1791072000ULL);
    return 0;
}

#include <cstddef>
#include <cstdint>
#include <string>

#include "header_list.h"
#include "url.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string input(reinterpret_cast<const char*>(data), size);
    kathttp3::Url parsed;
    (void)kathttp3::parse_url(input, parsed);

    const size_t split = size == 0 ? 0 : static_cast<size_t>(data[0]) % (size + 1);
    std::string name = input.substr(0, split);
    std::string value = input.substr(split);
    kathttp3::HeaderList headers;
    headers.add(std::move(name), std::move(value));
    (void)headers.get(input);
    (void)headers.get_all(input);
    return 0;
}

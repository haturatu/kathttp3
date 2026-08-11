#include "request.h"

#include <cctype>
#include <charconv>
#include <cstring>
#include <exception>
#include <limits>
#include <new>

#include "kathttp3.h"
#include "log.h"

namespace {
bool token_char(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') || c == '!' || c == '#' || c == '$' || c == '%' ||
           c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
           c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

bool valid_token(const char* value) {
    if (!*value) return false;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(value); *p; ++p) {
        if (!token_char(*p)) return false;
    }
    return true;
}

bool valid_header(const char* name, const char* value) {
    if (!valid_token(name)) return false;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(value); *p; ++p) {
        if (*p != '\t' && (*p < 0x20 || *p == 0x7f)) return false;
    }
    return true;
}

std::string lower_header_name(const char* name) {
    std::string normalized(name);
    for (char& ch : normalized)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return normalized;
}

bool forbidden_http3_header(const std::string& name) {
    return name == "connection" || name == "proxy-connection" || name == "transfer-encoding" ||
           name == "keep-alive" || name == "upgrade" || name == "host";
}

bool valid_te_value(std::string_view value) {
    const auto begin = value.find_first_not_of(" \t");
    if (begin == std::string_view::npos) return false;
    const auto end = value.find_last_not_of(" \t");
    value = value.substr(begin, end - begin + 1);
    constexpr std::string_view trailers = "trailers";
    if (value.size() != trailers.size()) return false;
    for (size_t i = 0; i < value.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(value[i]);
        if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c + ('a' - 'A'));
        if (c != static_cast<unsigned char>(trailers[i])) return false;
    }
    return true;
}

void log_request_exception(const char* operation) noexcept {
    try {
        throw;
    } catch (const std::exception& error) {
        KATHTTP3_LOG_WARN("%s failed: %s\n", operation, error.what());
    } catch (...) {
        KATHTTP3_LOG_WARN("%s failed with a non-standard exception\n", operation);
    }
}
}  // namespace

namespace kathttp3 {

bool validate_request_body_framing(kathttp3_request& request) {
    bool saw_content_length = false;
    uint64_t content_length = 0;
    for (const auto& header : request.headers.list()) {
        if (header.name != "content-length") continue;
        uint64_t value = 0;
        const char* begin = header.value.data();
        const char* end = begin + header.value.size();
        const auto [parsed, error] = std::from_chars(begin, end, value);
        if (begin == end || error != std::errc{} || parsed != end ||
            value > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
            (saw_content_length && value != content_length)) {
            return false;
        }
        saw_content_length = true;
        content_length = value;
    }

    if (request.streaming_body) {
        if (!saw_content_length) return true;
        if (request.streaming_body_length >= 0 &&
            static_cast<uint64_t>(request.streaming_body_length) != content_length) {
            return false;
        }
        request.streaming_body_length = static_cast<int64_t>(content_length);
        return true;
    }

    return !saw_content_length || static_cast<uint64_t>(request.body.size()) == content_length;
}

} /* namespace kathttp3 */

extern "C" {

kathttp3_request* kathttp3_request_create(const char* method, const char* url) {
    if (!method || !url || !valid_token(method)) return nullptr;
    auto* r = new (std::nothrow) kathttp3_request();
    if (!r) return nullptr;
    try {
        r->method = method;
        r->url = url;
        return r;
    } catch (...) {
        log_request_exception("kathttp3_request_create");
        delete r;
        return nullptr;
    }
}

void kathttp3_request_destroy(kathttp3_request* request) {
    delete request;
}

int kathttp3_request_add_header(kathttp3_request* request, const char* name, const char* value) {
    if (!request || !name || !value || !valid_header(name, value)) return KATHTTP3_ERR_INVALID_ARG;
    try {
        std::string normalized_name = lower_header_name(name);
        if (forbidden_http3_header(normalized_name)) return KATHTTP3_ERR_INVALID_ARG;
        if (normalized_name == "te" && !valid_te_value(value)) return KATHTTP3_ERR_INVALID_ARG;
        request->headers.add(std::move(normalized_name), value);
        return KATHTTP3_OK;
    } catch (...) {
        log_request_exception("kathttp3_request_add_header");
        return KATHTTP3_ERR_NOMEM;
    }
}

int kathttp3_request_set_body(kathttp3_request* request, const uint8_t* data, size_t len) {
    if (!request) return KATHTTP3_ERR_INVALID_ARG;
    if (data && len) {
        try {
            request->body.assign(data, data + len);
        } catch (...) {
            log_request_exception("kathttp3_request_set_body");
            return KATHTTP3_ERR_NOMEM;
        }
    } else {
        request->body.clear();
    }
    request->streaming_body = false;
    request->streaming_body_length = -1;
    return KATHTTP3_OK;
}

int kathttp3_request_set_streaming_body(kathttp3_request* request, int64_t content_length) {
    if (!request || content_length < -1) return KATHTTP3_ERR_INVALID_ARG;
    request->body.clear();
    request->streaming_body = true;
    request->streaming_body_length = content_length;
    return KATHTTP3_OK;
}

void kathttp3_request_set_follow_redirects(kathttp3_request* request, int enable) {
    if (request) request->follow_redirects = enable ? 1 : 0;
}

void kathttp3_request_set_streaming(kathttp3_request* request, int enable) {
    if (request) request->streaming = enable ? 1 : 0;
}

int kathttp3_request_add_address(kathttp3_request* request, const char* ip, uint16_t port) {
    if (!request || !ip) return KATHTTP3_ERR_INVALID_ARG;
    try {
        request->addresses.emplace_back(std::string(ip), port);
        return KATHTTP3_OK;
    } catch (...) {
        log_request_exception("kathttp3_request_add_address");
        return KATHTTP3_ERR_NOMEM;
    }
}

} /* extern "C" */

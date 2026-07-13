#include "request.h"

#include <cstring>
#include <exception>
#include <new>

#include "kathttp3.h"
#include "log.h"

namespace {
bool valid_header(const char* name, const char* value) {
    if (!*name) return false;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(name); *p; ++p) {
        if (*p <= 32 || *p >= 127 || *p == ':' || (*p >= 'A' && *p <= 'Z')) return false;
    }
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(value); *p; ++p)
        if (*p == '\r' || *p == '\n' || *p == 0) return false;
    return std::strcmp(name, "connection") != 0 && std::strcmp(name, "proxy-connection") != 0 &&
           std::strcmp(name, "transfer-encoding") != 0 && std::strcmp(name, "upgrade") != 0 &&
           std::strcmp(name, "host") != 0;
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

extern "C" {

kathttp3_request* kathttp3_request_create(const char* method, const char* url) {
    if (!method || !url) return nullptr;
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
        request->headers.add(name, value);
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

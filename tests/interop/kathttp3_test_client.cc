#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

#include "kathttp3.h"

namespace {
struct Result {
    std::mutex mutex;
    std::condition_variable ready;
    bool terminal = false;
    int error = KATHTTP3_ERR_TIMEOUT;
    int status = 0;
    size_t body_bytes = 0;
};

void callback(void* userdata, const kathttp3_event* event) {
    auto* result = static_cast<Result*>(userdata);
    std::lock_guard<std::mutex> lock(result->mutex);
    if (event->type == KATHTTP3_EVENT_HEADERS)
        result->status = event->status_code;
    else if (event->type == KATHTTP3_EVENT_BODY)
        result->body_bytes += event->data_len;
    else if (event->type == KATHTTP3_EVENT_COMPLETE || event->type == KATHTTP3_EVENT_ERROR) {
        if (result->terminal) return;
        result->terminal = true;
        result->error = event->error_code;
        result->ready.notify_one();
    }
}

bool arg_value(int argc, char** argv, const char* flag, std::string* out) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], flag) == 0) {
            *out = argv[i + 1];
            return true;
        }
    }
    return false;
}
}  // namespace

int main(int argc, char** argv) {
    std::string url;
    std::string ca_cert;
    if (!arg_value(argc, argv, "--url", &url) || !arg_value(argc, argv, "--ca-cert", &ca_cert)) {
        std::fprintf(stderr, "usage: %s --url https://host:port/path --ca-cert cert.pem\n",
                     argv[0]);
        return 2;
    }
    kathttp3_client_options options;
    kathttp3_client_options_init(&options);
    options.trust_mode = KATHTTP3_TRUST_CUSTOM_CA;
    options.ca_cert_file = ca_cert.c_str();
    options.connect_timeout_ms = 5000;
    options.handshake_timeout_ms = 5000;
    options.response_headers_timeout_ms = 5000;
    options.call_timeout_ms = 10000;
    kathttp3_client* client = kathttp3_client_create(&options);
    if (!client) return 3;
    kathttp3_request* request = kathttp3_request_create("GET", url.c_str());
    if (!request) {
        kathttp3_client_destroy(client);
        return 4;
    }
    Result result;
    kathttp3_client_execute(client, request, 1, callback, &result);
    {
        std::unique_lock<std::mutex> lock(result.mutex);
        if (!result.ready.wait_for(lock, std::chrono::seconds(12),
                                   [&] { return result.terminal; })) {
            kathttp3_client_destroy(client);
            return 5;
        }
    }
    kathttp3_client_destroy(client);
    if (result.error != KATHTTP3_OK || result.status < 200 || result.status >= 400) return 6;
    std::printf("HTTP %d bytes=%zu\n", result.status, result.body_bytes);
    return 0;
}

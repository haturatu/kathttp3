#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "engine.h"
#include "request.h"
#include "response_cache.h"
#include "url.h"

namespace kathttp3 {

/* Keep the lifecycle tests at the Engine boundary without making cache and
 * registry test hooks part of the public C ABI. */
class EngineTestAccess {
   public:
    static ResponseCache& cache(Engine& engine) {
        assert(engine.http_cache_);
        return *engine.http_cache_;
    }

    static void prepare_cache(Engine& engine, Job* job) {
        engine.prepare_cache(job);
    }

    static void install_callback(Engine& engine, int64_t request_id,
                                 kathttp3_event_callback callback, void* user_data) {
        engine.registry_[request_id] =
            Engine::ReqEntry{callback, user_data, nullptr, false, false, 0};
    }
};

}  // namespace kathttp3

namespace {

using namespace kathttp3;

kathttp3_client_options test_options() {
    kathttp3_client_options options{};
    kathttp3_client_options_init_size(&options, sizeof(options));
    options.enable_http_cache = 1;
    options.http_cache_max_entries = 8;
    options.http_cache_max_bytes = 1 << 20;
    options.http_cache_max_entry_bytes = 1 << 16;
    return options;
}

std::unique_ptr<Job> make_job(int64_t id, const char* url) {
    auto job = std::make_unique<Job>();
    job->id = id;
    job->request = kathttp3_request_create("GET", url);
    assert(job->request);
    assert(parse_url(url, job->url));
    job->response.url = job->url;
    return job;
}

struct EventLog {
    std::vector<kathttp3_event_type> types;
    std::vector<int> statuses;
    std::vector<int> errors;
};

void record_event(void* user_data, const kathttp3_event* event) {
    auto* log = static_cast<EventLog*>(user_data);
    log->types.push_back(event->type);
    log->statuses.push_back(event->status_code);
    log->errors.push_back(event->error_code);
}

struct BlockingCallbackState {
    std::mutex mutex;
    std::condition_variable cv;
    bool headers_entered = false;
    bool release_headers = false;
};

void blocking_cached_event(void* user_data, const kathttp3_event* event) {
    auto* state = static_cast<BlockingCallbackState*>(user_data);
    if (event->type != KATHTTP3_EVENT_HEADERS) return;
    std::unique_lock<std::mutex> lock(state->mutex);
    state->headers_entered = true;
    state->cv.notify_all();
    state->cv.wait(lock, [state] { return state->release_headers; });
}

void full_response_removes_validation_target() {
    const kathttp3_client_options options = test_options();
    Engine engine(options);
    constexpr const char* kUrl = "https://cache.example/engine-full-response";

    HeaderList empty_headers;
    const CacheRequest stored_request{"GET", kUrl, empty_headers, false};
    Response cached_response;
    cached_response.status_code = 200;
    cached_response.headers.add("cache-control", "max-age=60");
    cached_response.headers.add("etag", "\"engine-v1\"");
    cached_response.body = {1, 2, 3};
    assert(EngineTestAccess::cache(engine).store(stored_request, cached_response));

    auto job = make_job(101, kUrl);
    assert(kathttp3_request_add_header(job->request, "cache-control", "no-cache") == KATHTTP3_OK);
    EngineTestAccess::prepare_cache(engine, job.get());
    assert(job->cache_validation);

    HeaderList full_response_headers;
    full_response_headers.add("cache-control", "no-store");
    engine.on_job_headers(job.get(), 200, full_response_headers);
    assert(!job->cache_validation);

    const CacheLookup after_full_response = EngineTestAccess::cache(engine).lookup(stored_request);
    assert(after_full_response.state == CacheState::Miss);
    engine.destroy();
}

void stale_fallback_precedes_body_length_validation() {
    const kathttp3_client_options options = test_options();
    Engine engine(options);
    constexpr const char* kUrl = "https://cache.example/engine-stale-error";

    HeaderList request_headers;
    const CacheRequest cache_request{"GET", kUrl, request_headers, false};
    Response cached_response;
    cached_response.status_code = 200;
    cached_response.headers.add("cache-control", "max-age=0, stale-if-error=60");
    cached_response.body = {4, 5, 6};
    assert(EngineTestAccess::cache(engine).store(cache_request, cached_response));

    auto job = make_job(102, kUrl);
    EngineTestAccess::prepare_cache(engine, job.get());
    assert(job->cache_validation);

    EventLog log;
    EngineTestAccess::install_callback(engine, job->id, record_event, &log);
    HeaderList error_headers;
    error_headers.add("content-length", "100");
    engine.on_job_headers(job.get(), 503, error_headers);
    assert(job->cache_validation && job->cache_validation->serve_stale_on_error);
    engine.on_job_complete(job.get());

    assert(log.types.size() == 3);
    assert(log.types[0] == KATHTTP3_EVENT_HEADERS && log.statuses[0] == 200);
    assert(log.types[1] == KATHTTP3_EVENT_BODY);
    assert(log.types[2] == KATHTTP3_EVENT_COMPLETE && log.errors[2] == 0);
    engine.destroy();
}

void cache_dispatcher_lifecycle_is_cancel_safe() {
    const kathttp3_client_options options = test_options();
    Engine engine(options);
    constexpr const char* kUrl = "https://cache.example/engine-dispatcher";

    HeaderList request_headers;
    const CacheRequest cache_request{"GET", kUrl, request_headers, false};
    Response cached_response;
    cached_response.status_code = 200;
    cached_response.headers.add("cache-control", "max-age=60");
    cached_response.body = {7};
    assert(EngineTestAccess::cache(engine).store(cache_request, cached_response));

    BlockingCallbackState callback_state;
    kathttp3_request* request = kathttp3_request_create("GET", kUrl);
    assert(request);
    engine.execute(request, 103, blocking_cached_event, &callback_state);
    {
        std::unique_lock<std::mutex> lock(callback_state.mutex);
        assert(callback_state.cv.wait_for(lock, std::chrono::seconds(5), [&callback_state] {
            return callback_state.headers_entered;
        }));
    }

    std::mutex completion_mutex;
    std::condition_variable completion_cv;
    unsigned completed = 0;
    std::thread destroy_thread([&] {
        engine.destroy();
        {
            std::lock_guard<std::mutex> lock(completion_mutex);
            ++completed;
        }
        completion_cv.notify_all();
    });
    std::thread cancel_thread([&] {
        engine.cancel(103);
        {
            std::lock_guard<std::mutex> lock(completion_mutex);
            ++completed;
        }
        completion_cv.notify_all();
    });

    {
        std::lock_guard<std::mutex> lock(callback_state.mutex);
        callback_state.release_headers = true;
    }
    callback_state.cv.notify_all();

    {
        std::unique_lock<std::mutex> lock(completion_mutex);
        assert(
            completion_cv.wait_for(lock, std::chrono::seconds(5), [&] { return completed == 2; }));
    }
    destroy_thread.join();
    cancel_thread.join();
}

}  // namespace

int main() {
    full_response_removes_validation_target();
    stale_fallback_precedes_body_length_validation();
    cache_dispatcher_lifecycle_is_cancel_safe();
    return 0;
}

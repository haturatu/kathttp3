#include <algorithm>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
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

    static void check_queue(Engine& engine, size_t jobs, size_t bytes,
                            const std::shared_ptr<const std::vector<uint8_t>>& body) {
        std::lock_guard<std::mutex> lock(engine.cache_dispatch_mutex_);
        assert(engine.cache_dispatch_jobs_.size() == jobs);
        assert(engine.cache_dispatch_queued_bytes_ == bytes);
        for (const auto& job : engine.cache_dispatch_jobs_) {
            assert(job->cached_response && job->cached_response->body == body);
        }
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
    const bool parsed = parse_url(url, job->url);
    assert(parsed);
    job->response.url = job->url;
    return job;
}

struct EventLog {
    std::vector<kathttp3_event_type> types;
    std::vector<int> statuses;
    std::vector<int> errors;
    HeaderList headers;
};

void record_event(void* user_data, const kathttp3_event* event) {
    auto* log = static_cast<EventLog*>(user_data);
    log->types.push_back(event->type);
    log->statuses.push_back(event->status_code);
    log->errors.push_back(event->error_code);
    if (event->type == KATHTTP3_EVENT_HEADERS) {
        for (size_t i = 0; i < event->header_count; ++i)
            log->headers.add(event->names[i], event->values[i]);
    }
}

struct BlockingCallbackState {
    std::mutex mutex;
    std::condition_variable cv;
    bool headers_entered = false;
    bool release_headers = false;
    size_t completed = 0;
    std::function<void()> before_release;
};

void blocking_cached_event(void* user_data, const kathttp3_event* event) {
    auto* state = static_cast<BlockingCallbackState*>(user_data);
    if (event->type != KATHTTP3_EVENT_HEADERS && event->type != KATHTTP3_EVENT_COMPLETE) return;
    std::unique_lock<std::mutex> lock(state->mutex);
    if (event->type == KATHTTP3_EVENT_COMPLETE) {
        ++state->completed;
        state->cv.notify_all();
        return;
    }
    state->headers_entered = true;
    state->cv.notify_all();
    state->cv.wait(lock, [state] { return state->release_headers; });
    auto action = std::move(state->before_release);
    lock.unlock();
    if (action) action();
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
    const bool stored = EngineTestAccess::cache(engine).store(stored_request, cached_response);
    assert(stored);

    auto job = make_job(101, kUrl);
    const int added = kathttp3_request_add_header(job->request, "cache-control", "no-cache");
    assert(added == KATHTTP3_OK);
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
    const bool stored = EngineTestAccess::cache(engine).store(cache_request, cached_response);
    assert(stored);

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

void cached_delivery_omits_set_cookie() {
    Engine engine(test_options());
    constexpr const char* kUrl = "https://cache.example/cookies";
    auto network_job = make_job(110, kUrl);
    EventLog network_log;
    EngineTestAccess::install_callback(engine, network_job->id, record_event, &network_log);
    HeaderList headers;
    headers.add("cache-control", "max-age=60");
    headers.add("Set-Cookie", "session=old; Max-Age=3600");
    headers.add("sEt-CoOkIe", "other=old; Max-Age=3600");
    headers.add("content-type", "application/octet-stream");
    engine.on_job_headers(network_job.get(), 200, headers);
    const uint8_t body[] = {1, 2};
    engine.on_job_body(network_job.get(), body, sizeof(body));
    engine.on_job_complete(network_job.get());
    assert(network_log.headers.get_all("set-cookie").size() == 2);

    auto hit = make_job(111, kUrl);
    EngineTestAccess::prepare_cache(engine, hit.get());
    assert(hit->cached_response);
    assert(hit->cached_response->headers.get_all("set-cookie").size() == 2);
    EventLog cached_log;
    EngineTestAccess::install_callback(engine, hit->id, record_event, &cached_log);
    engine.on_job_cached(hit.get());
    assert(cached_log.types.size() == 3 && cached_log.statuses[0] == 200);
    assert(cached_log.headers.get_all("set-cookie").empty());
    assert(cached_log.headers.get("content-type") == "application/octet-stream");
    assert(!cached_log.headers.get("age").empty());
    engine.destroy();
}

void cache_dispatcher_bounds_pending_hits(bool large_body) {
    auto options = test_options();
    if (large_body) {
        options.http_cache_max_bytes = 32 * 1024 * 1024;
        options.http_cache_max_entry_bytes = 5 * 1024 * 1024;
    }
    Engine engine(options);
    constexpr const char* kUrl = "https://cache.example/dispatcher-limits";
    HeaderList headers;
    const CacheRequest request{"GET", kUrl, headers};
    Response response;
    response.status_code = 200;
    response.headers.add("cache-control", "max-age=60");
    response.body.resize(large_body ? 4 * 1024 * 1024 : 1, 42);
    const bool stored = EngineTestAccess::cache(engine).store(request, response);
    assert(stored);
    const auto lookup = EngineTestAccess::cache(engine).lookup(request);
    assert(lookup.response);
    const size_t job_bytes = lookup.response->accounted_bytes;
    const size_t admitted = std::min<size_t>(128, options.http_cache_max_bytes / job_bytes);
    assert(admitted > 0 && (large_body ? admitted < 128 : admitted == 128));

    BlockingCallbackState state;
    engine.execute(kathttp3_request_create("GET", kUrl), 200, blocking_cached_event, &state);
    {
        std::unique_lock<std::mutex> lock(state.mutex);
        const bool ready =
            state.cv.wait_for(lock, std::chrono::seconds(5), [&] { return state.headers_entered; });
        assert(ready);
    }
    EventLog cancelled;
    engine.execute(kathttp3_request_create("GET", kUrl), 201, record_event, &cancelled);
    for (size_t i = 1; i < admitted; ++i) {
        engine.execute(kathttp3_request_create("GET", kUrl), 201 + i, blocking_cached_event,
                       &state);
    }
    EngineTestAccess::check_queue(engine, admitted, admitted * job_bytes, lookup.response->body);
    EventLog rejected;
    for (int64_t id : {1000, 1001}) {
        engine.execute(kathttp3_request_create("GET", kUrl), id, record_event, &rejected);
    }
    assert(rejected.types.size() == 2);
    for (size_t i = 0; i < rejected.types.size(); ++i) {
        assert(rejected.types[i] == KATHTTP3_EVENT_ERROR);
        assert(rejected.errors[i] == KATHTTP3_ERR_NOMEM);
    }
    EngineTestAccess::check_queue(engine, admitted, admitted * job_bytes, lookup.response->body);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        // Run inside the active callback, before the dispatcher can pop again.
        // The recursive callback lock preserves cancellation event ordering.
        state.before_release = [&] {
            engine.cancel(201);
            engine.cancel(201);  // repeated cancellation must not subtract quota twice
            assert(cancelled.types.size() == 1 && cancelled.types[0] == KATHTTP3_EVENT_ERROR);
            assert(cancelled.errors[0] == KATHTTP3_ERR_CANCELLED);
            EngineTestAccess::check_queue(engine, admitted - 1, (admitted - 1) * job_bytes,
                                          lookup.response->body);
            engine.execute(kathttp3_request_create("GET", kUrl), 1003, blocking_cached_event,
                           &state);
            EngineTestAccess::check_queue(engine, admitted, admitted * job_bytes,
                                          lookup.response->body);
        };
        state.release_headers = true;
    }
    state.cv.notify_all();
    {
        std::unique_lock<std::mutex> lock(state.mutex);
        const bool ready = state.cv.wait_for(lock, std::chrono::seconds(5),
                                             [&] { return state.completed == admitted + 1; });
        assert(ready);
    }
    EngineTestAccess::check_queue(engine, 0, 0, lookup.response->body);
    engine.execute(kathttp3_request_create("GET", kUrl), 1002, blocking_cached_event, &state);
    {
        std::unique_lock<std::mutex> lock(state.mutex);
        const bool ready = state.cv.wait_for(lock, std::chrono::seconds(5),
                                             [&] { return state.completed == admitted + 2; });
        assert(ready);
    }
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
    const bool stored = EngineTestAccess::cache(engine).store(cache_request, cached_response);
    assert(stored);

    BlockingCallbackState callback_state;
    kathttp3_request* request = kathttp3_request_create("GET", kUrl);
    assert(request);
    engine.execute(request, 103, blocking_cached_event, &callback_state);
    {
        std::unique_lock<std::mutex> lock(callback_state.mutex);
        const bool ready = callback_state.cv.wait_for(
            lock, std::chrono::seconds(5),
            [&callback_state] { return callback_state.headers_entered; });
        assert(ready);
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
        const bool ready =
            completion_cv.wait_for(lock, std::chrono::seconds(5), [&] { return completed == 2; });
        assert(ready);
    }
    destroy_thread.join();
    cancel_thread.join();
}

}  // namespace

int main() {
    cached_delivery_omits_set_cookie();
    cache_dispatcher_bounds_pending_hits(false);
    cache_dispatcher_bounds_pending_hits(true);
    full_response_removes_validation_target();
    stale_fallback_precedes_body_length_validation();
    cache_dispatcher_lifecycle_is_cancel_safe();
    return 0;
}

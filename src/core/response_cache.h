#ifndef KATHTTP3_RESPONSE_CACHE_H
#define KATHTTP3_RESPONSE_CACHE_H

#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "cache_control.h"
#include "response.h"

namespace kathttp3 {

class CacheClock {
   public:
    virtual ~CacheClock() = default;
    virtual std::optional<uint64_t> wall_seconds() const = 0;
    virtual uint64_t monotonic_ns() const = 0;
};

class SystemCacheClock final : public CacheClock {
   public:
    std::optional<uint64_t> wall_seconds() const override;
    uint64_t monotonic_ns() const override;
};

struct ResponseCacheConfig {
    size_t max_entries = 128;
    size_t max_bytes = 32 * 1024 * 1024;
    size_t max_entry_bytes = 4 * 1024 * 1024;
};

struct VaryKey {
    std::string name;
    std::vector<std::string> request_values;

    bool operator==(const VaryKey&) const = default;
};

struct CachedResponse {
    std::string url;
    int status_code = 0;
    HeaderList headers;
    std::vector<uint8_t> body;
    std::vector<VaryKey> vary;

    uint64_t stored_at_monotonic_ns = 0;
    uint64_t corrected_initial_age_seconds = 0;
    uint64_t freshness_lifetime_seconds = 0;

    std::optional<std::string> etag;
    std::optional<std::string> last_modified;
    bool requires_revalidation = false;
    bool must_revalidate = false;
    std::optional<uint64_t> stale_if_error_seconds;
    size_t accounted_bytes = 0;
};

struct CacheRequest {
    std::string_view method;
    std::string_view url;
    const HeaderList& headers;
    bool streaming = false;
    bool has_body = false;
};

enum class CacheState {
    Miss,
    Fresh,
    NeedsValidation,
};

struct CacheLookup {
    CacheState state = CacheState::Miss;
    std::optional<CachedResponse> response;
};

struct RevalidationResult {
    CachedResponse response;
    bool retain_in_cache = false;
};

/* RFC 9111 current_age after the resident time is added using a monotonic
 * clock. */
uint64_t current_age(const CachedResponse& response, uint64_t now_monotonic_ns);

class ResponseCache {
   public:
    explicit ResponseCache(ResponseCacheConfig config = {},
                           std::shared_ptr<const CacheClock> clock = nullptr);
    /* Compatibility constructor for callers of the disconnected prototype. */
    explicit ResponseCache(size_t max_entries);

    CacheLookup lookup(const CacheRequest& request);

    /* Returns true when this response may be captured before its body arrives.
     * The final store repeats all checks and also validates body size and
     * completion, so this is only an allocation/admission hint. */
    bool should_capture(const CacheRequest& request, int status,
                        const HeaderList& response_headers) const;

    bool store(const CacheRequest& request, const Response& response,
               std::optional<uint64_t> request_wall_seconds = std::nullopt);

    std::optional<RevalidationResult> merge_304(
        const CachedResponse& stored, const CacheRequest& request,
        const HeaderList& response_headers,
        std::optional<uint64_t> request_wall_seconds = std::nullopt);

    bool can_serve_stale_if_error(const CachedResponse& response) const;

    /* Return a delivery copy with an RFC 9111 Age field calculated at the
     * current monotonic time. The stored entry itself is not mutated. */
    CachedResponse response_with_current_age(const CachedResponse& response) const;

    void invalidate(std::string_view url);
    void clear();

    size_t size() const;
    size_t bytes() const;

    /* Legacy API retained as a source-compatible facade over the new cache.
     * It intentionally uses an empty request-header set, so Vary entries are
     * only useful through the CacheRequest API. */
    bool get(std::string_view method, std::string_view url, Response& out);
    void put(std::string_view method, std::string_view url, const Response& response);

   private:
    std::optional<CachedResponse> make_cached_response(const CacheRequest& request,
                                                       const Response& response,
                                                       std::optional<uint64_t> request_wall_seconds,
                                                       std::optional<uint64_t> now_wall_seconds,
                                                       uint64_t now_monotonic_ns,
                                                       bool require_cacheable = true) const;
    CacheLookup lookup_locked(const CacheRequest& request, const CacheControl& request_control,
                              std::optional<uint64_t> now_wall_seconds, uint64_t now_monotonic_ns);
    void insert_locked(CachedResponse response);

    std::shared_ptr<const CacheClock> clock_;
    size_t max_entries_;
    size_t max_bytes_;
    size_t max_entry_bytes_;
    mutable std::mutex mutex_;
    std::list<CachedResponse> entries_; /* front = most recently used */
    size_t total_bytes_ = 0;
};

} /* namespace kathttp3 */

#endif /* KATHTTP3_RESPONSE_CACHE_H */

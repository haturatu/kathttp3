#include "response_cache.h"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>

#include "http_date.h"
#include "time_util.h"

namespace kathttp3 {

namespace {

constexpr size_t kDefaultMaxEntries = 128;
constexpr size_t kDefaultMaxBytes = 32 * 1024 * 1024;
constexpr size_t kDefaultMaxEntryBytes = 4 * 1024 * 1024;
constexpr uint64_t kNanosecondsPerSecond = 1'000'000'000ULL;

bool ascii_iequals(std::string_view lhs, std::string_view rhs) {
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i) {
        unsigned char a = static_cast<unsigned char>(lhs[i]);
        unsigned char b = static_cast<unsigned char>(rhs[i]);
        if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b + ('a' - 'A'));
        if (a != b) return false;
    }
    return true;
}

std::string ascii_lower(std::string_view value) {
    std::string out(value);
    for (char& ch : out) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c >= 'A' && c <= 'Z') ch = static_cast<char>(c + ('a' - 'A'));
    }
    return out;
}

std::string_view trim_ows(std::string_view value) {
    const size_t begin = value.find_first_not_of(" \t");
    if (begin == std::string_view::npos) return {};
    const size_t end = value.find_last_not_of(" \t");
    return value.substr(begin, end - begin + 1);
}

bool is_get(std::string_view method) {
    return ascii_iequals(method, "GET");
}

bool has_header(const HeaderList& headers, std::string_view name) {
    return !headers.get_all(name).empty();
}

bool is_token_char(unsigned char ch) {
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
        return true;
    }
    switch (ch) {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            return true;
        default:
            return false;
    }
}

bool is_field_name(std::string_view name) {
    if (name.empty()) return false;
    for (const char raw : name) {
        if (!is_token_char(static_cast<unsigned char>(raw))) return false;
    }
    return true;
}

bool has_sensitive_request_header(const HeaderList& headers) {
    return has_header(headers, "authorization") || has_header(headers, "cookie");
}

bool request_cache_bypassed(const CacheRequest& request, const CacheControl& control) {
    return !is_get(request.method) || request.streaming || control.no_store ||
           has_sensitive_request_header(request.headers) || has_header(request.headers, "range");
}

std::vector<std::string> request_field_values(const HeaderList& headers, std::string_view name) {
    std::vector<std::string> values;
    for (const std::string_view value : headers.get_all(name)) values.emplace_back(value);
    return values;
}

std::vector<std::string_view> split_comma_list(std::string_view value) {
    std::vector<std::string_view> out;
    size_t begin = 0;
    bool quoted = false;
    bool escaped = false;
    for (size_t i = 0; i < value.size(); ++i) {
        const char ch = value[i];
        if (quoted) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                quoted = false;
            }
        } else if (ch == '"') {
            quoted = true;
        } else if (ch == ',') {
            out.push_back(value.substr(begin, i - begin));
            begin = i + 1;
        }
    }
    out.push_back(value.substr(begin));
    return out;
}

struct ParsedVary {
    bool valid = true;
    bool star = false;
    std::vector<std::string> names;
};

ParsedVary parse_vary(const HeaderList& headers) {
    ParsedVary out;
    for (const std::string_view field : headers.get_all("vary")) {
        for (const std::string_view raw_name : split_comma_list(field)) {
            const std::string_view name = trim_ows(raw_name);
            if (name.empty()) {
                out.valid = false;
                continue;
            }
            if (name == "*") {
                out.star = true;
                continue;
            }
            if (!is_field_name(name)) {
                out.valid = false;
                continue;
            }
            const std::string normalized = ascii_lower(name);
            if (std::find(out.names.begin(), out.names.end(), normalized) == out.names.end())
                out.names.push_back(normalized);
        }
    }
    return out;
}

bool vary_matches(const CachedResponse& cached, const HeaderList& request_headers) {
    for (const auto& key : cached.vary) {
        if (request_field_values(request_headers, key.name) != key.request_values) return false;
    }
    return true;
}

bool same_variant(const CachedResponse& lhs, const CachedResponse& rhs) {
    return lhs.url == rhs.url && lhs.vary == rhs.vary;
}

uint64_t saturating_add(uint64_t lhs, uint64_t rhs) {
    constexpr uint64_t kMax = std::numeric_limits<uint64_t>::max();
    return rhs > kMax - lhs ? kMax : lhs + rhs;
}

size_t saturating_size_add(size_t lhs, size_t rhs) {
    constexpr size_t kMax = std::numeric_limits<size_t>::max();
    return rhs > kMax - lhs ? kMax : lhs + rhs;
}

size_t accounted_bytes(const CachedResponse& response) {
    size_t total = sizeof(CachedResponse);
    total = saturating_size_add(total, response.url.size());
    total = saturating_size_add(total, response.body.size());
    for (const auto& header : response.headers.list()) {
        total = saturating_size_add(total, header.name.size());
        total = saturating_size_add(total, header.value.size());
    }
    for (const auto& key : response.vary) {
        total = saturating_size_add(total, key.name.size());
        for (const auto& value : key.request_values)
            total = saturating_size_add(total, value.size());
    }
    if (response.etag) total = saturating_size_add(total, response.etag->size());
    if (response.last_modified) total = saturating_size_add(total, response.last_modified->size());
    return total;
}

HeaderList headers_with_age(const HeaderList& headers, uint64_t age) {
    HeaderList out;
    for (const auto& header : headers.list()) {
        if (ascii_iequals(header.name, "age")) continue;
        out.add(header.name, header.value);
    }
    out.add("age", std::to_string(age));
    return out;
}

HeaderList merge_headers(const HeaderList& stored, const HeaderList& updated) {
    HeaderList out;
    for (const auto& old_header : stored.list()) {
        if (ascii_iequals(old_header.name, "content-length")) {
            /* A 304 describes metadata, not the size of the stored body. */
            out.add(old_header.name, old_header.value);
            continue;
        }
        bool replaced = false;
        for (const auto& new_header : updated.list()) {
            if (ascii_iequals(old_header.name, new_header.name)) {
                replaced = true;
                break;
            }
        }
        if (!replaced) out.add(old_header.name, old_header.value);
    }
    for (const auto& header : updated.list()) {
        if (ascii_iequals(header.name, "content-length")) continue;
        out.add(header.name, header.value);
    }
    return out;
}

std::optional<uint64_t> parse_age(const HeaderList& headers, bool& invalid) {
    const auto values = headers.get_all("age");
    if (values.empty()) return 0;
    uint64_t result = 0;
    for (const std::string_view value : values) {
        const auto parsed = parse_delta_seconds(value);
        if (!parsed) {
            invalid = true;
            return std::nullopt;
        }
        /* Multiple Age fields are not expected, but choosing the largest
         * value is the conservative result if an intermediary combined or
         * duplicated them. */
        result = std::max(result, *parsed);
    }
    return result;
}

}  // namespace

std::optional<uint64_t> SystemCacheClock::wall_seconds() const {
    return kathttp3::wall_clock_seconds();
}

uint64_t SystemCacheClock::monotonic_ns() const {
    return timestamp_now_ns();
}

uint64_t current_age(const CachedResponse& response, uint64_t now_monotonic_ns) {
    const uint64_t resident_seconds =
        elapsed_ns(now_monotonic_ns, response.stored_at_monotonic_ns) / kNanosecondsPerSecond;
    return saturating_add(response.corrected_initial_age_seconds, resident_seconds);
}

ResponseCache::ResponseCache(ResponseCacheConfig config, std::shared_ptr<const CacheClock> clock)
    : clock_(clock ? std::move(clock) : std::make_shared<SystemCacheClock>()),
      max_entries_(config.max_entries ? config.max_entries : kDefaultMaxEntries),
      max_bytes_(config.max_bytes ? config.max_bytes : kDefaultMaxBytes),
      max_entry_bytes_(config.max_entry_bytes ? config.max_entry_bytes : kDefaultMaxEntryBytes) {}

ResponseCache::ResponseCache(size_t max_entries)
    : ResponseCache(ResponseCacheConfig{max_entries, kDefaultMaxBytes, kDefaultMaxEntryBytes},
                    nullptr) {}

std::optional<CachedResponse> ResponseCache::make_cached_response(
    const CacheRequest& request, const Response& response,
    std::optional<uint64_t> request_wall_seconds, std::optional<uint64_t> now_wall_seconds,
    uint64_t now_monotonic_ns) const {
    const CacheControl request_control = parse_cache_control(request.headers);
    if (request_cache_bypassed(request, request_control) || request_control.invalid ||
        response.status_code != 200 || response.body.size() > max_entry_bytes_ ||
        now_monotonic_ns == 0) {
        return std::nullopt;
    }
    const CacheControl control = parse_cache_control(response.headers);
    if (control.no_store || control.invalid || control.conflicting_max_age) return std::nullopt;

    const ParsedVary vary = parse_vary(response.headers);
    if (!vary.valid || vary.star) return std::nullopt;

    const auto date_value = response.headers.get("date");
    const auto expires_value = response.headers.get("expires");
    const auto parsed_date = date_value.empty() ? std::nullopt : parse_http_date(date_value);
    const auto parsed_expires =
        expires_value.empty() ? std::nullopt : parse_http_date(expires_value);

    bool expires_invalid = !expires_value.empty() && !parsed_expires;
    std::optional<uint64_t> freshness_lifetime;
    if (control.max_age) {
        freshness_lifetime = *control.max_age;
    } else if (!expires_value.empty() && parsed_expires && parsed_date) {
        freshness_lifetime = *parsed_expires > *parsed_date
                                 ? static_cast<uint64_t>(*parsed_expires - *parsed_date)
                                 : 0;
    }

    const auto etag_value = response.headers.get("etag");
    const auto last_modified_value = response.headers.get("last-modified");
    const bool has_validator = !etag_value.empty() || !last_modified_value.empty();
    /* A no-cache response is useful only when it can be revalidated. */
    if (!freshness_lifetime.has_value() && !control.no_cache && !has_validator) return std::nullopt;
    if (expires_invalid && !control.max_age && !control.no_cache && !has_validator)
        return std::nullopt;

    bool invalid_age = false;
    const auto age_value = parse_age(response.headers, invalid_age);
    const uint64_t corrected_age =
        invalid_age ? std::numeric_limits<uint64_t>::max() : age_value.value_or(0);
    if (!now_wall_seconds) return std::nullopt;

    uint64_t apparent_age = 0;
    if (parsed_date) {
        if (*parsed_date <= 0) {
            const uint64_t date_magnitude =
                *parsed_date == std::numeric_limits<int64_t>::min()
                    ? static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1ULL
                    : static_cast<uint64_t>(-*parsed_date);
            apparent_age = saturating_add(*now_wall_seconds, date_magnitude);
        } else if (static_cast<uint64_t>(*parsed_date) < *now_wall_seconds) {
            apparent_age = *now_wall_seconds - static_cast<uint64_t>(*parsed_date);
        }
    }
    uint64_t response_delay = 0;
    if (request_wall_seconds && *now_wall_seconds >= *request_wall_seconds)
        response_delay = *now_wall_seconds - *request_wall_seconds;
    const uint64_t corrected_age_value = saturating_add(corrected_age, response_delay);

    CachedResponse cached;
    cached.url = std::string(request.url);
    cached.status_code = response.status_code;
    cached.headers = response.headers;
    cached.body = response.body;
    cached.stored_at_monotonic_ns = now_monotonic_ns;
    cached.corrected_initial_age_seconds = std::max(apparent_age, corrected_age_value);
    cached.freshness_lifetime_seconds = freshness_lifetime.value_or(0);
    for (const auto& name : vary.names)
        cached.vary.push_back({name, request_field_values(request.headers, name)});
    if (!etag_value.empty()) cached.etag = std::string(etag_value);
    if (!last_modified_value.empty()) cached.last_modified = std::string(last_modified_value);
    cached.must_revalidate = control.must_revalidate;
    cached.stale_if_error_seconds = control.stale_if_error;
    cached.accounted_bytes = accounted_bytes(cached);
    if (cached.accounted_bytes > max_entry_bytes_) return std::nullopt;
    return cached;
}

bool ResponseCache::should_capture(const CacheRequest& request, int status,
                                   const HeaderList& response_headers) const {
    const CacheControl request_control = parse_cache_control(request.headers);
    if (request_cache_bypassed(request, request_control) || request_control.invalid ||
        status != 200)
        return false;
    const CacheControl control = parse_cache_control(response_headers);
    if (control.no_store || control.invalid || control.conflicting_max_age) return false;
    const ParsedVary vary = parse_vary(response_headers);
    if (!vary.valid || vary.star) return false;
    const bool has_freshness =
        control.max_age.has_value() ||
        (!response_headers.get("expires").empty() && !response_headers.get("date").empty());
    const bool has_validator =
        !response_headers.get("etag").empty() || !response_headers.get("last-modified").empty();
    return has_freshness || (control.no_cache && has_validator);
}

void ResponseCache::insert_locked(CachedResponse response) {
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (!same_variant(*it, response)) continue;
        total_bytes_ -= std::min(total_bytes_, it->accounted_bytes);
        entries_.erase(it);
        break;
    }
    total_bytes_ = saturating_size_add(total_bytes_, response.accounted_bytes);
    entries_.push_front(std::move(response));
    while (entries_.size() > max_entries_ || total_bytes_ > max_bytes_) {
        auto last = std::prev(entries_.end());
        total_bytes_ -= std::min(total_bytes_, last->accounted_bytes);
        entries_.pop_back();
    }
}

bool ResponseCache::store(const CacheRequest& request, const Response& response,
                          std::optional<uint64_t> request_wall_seconds) {
    const auto now_wall_seconds = clock_->wall_seconds();
    if (!now_wall_seconds) return false;
    const auto cached = make_cached_response(request, response, request_wall_seconds,
                                             now_wall_seconds, clock_->monotonic_ns());
    if (!cached) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    insert_locked(*cached);
    return true;
}

CacheLookup ResponseCache::lookup_locked(const CacheRequest& request,
                                         const CacheControl& request_control,
                                         std::optional<uint64_t> now_wall_seconds,
                                         uint64_t now_monotonic_ns) {
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (it->url != request.url || !vary_matches(*it, request.headers)) continue;
        CachedResponse response = *it;
        entries_.splice(entries_.begin(), entries_, it);
        const uint64_t age = current_age(response, now_monotonic_ns);
        response.headers = headers_with_age(response.headers, age);

        const bool request_age_exceeded =
            request_control.max_age && age >= *request_control.max_age;
        const bool clock_unavailable = !now_wall_seconds || now_monotonic_ns == 0;
        if (!clock_unavailable && !request_control.no_cache && !request_age_exceeded &&
            age < response.freshness_lifetime_seconds) {
            return {CacheState::Fresh, std::move(response)};
        }
        return {CacheState::NeedsValidation, std::move(response)};
    }
    return {};
}

CacheLookup ResponseCache::lookup(const CacheRequest& request) {
    const CacheControl request_control = parse_cache_control(request.headers);
    if (request_cache_bypassed(request, request_control) || request_control.invalid) return {};
    const auto now_wall_seconds = clock_->wall_seconds();
    std::lock_guard<std::mutex> lock(mutex_);
    return lookup_locked(request, request_control, now_wall_seconds, clock_->monotonic_ns());
}

std::optional<CachedResponse> ResponseCache::merge_304(
    const CachedResponse& stored, const CacheRequest& request, const HeaderList& response_headers,
    std::optional<uint64_t> request_wall_seconds) {
    if (stored.url != request.url || !vary_matches(stored, request.headers)) return std::nullopt;
    Response merged;
    merged.status_code = stored.status_code;
    merged.headers = merge_headers(stored.headers, response_headers);
    merged.body = stored.body;
    const auto now_wall_seconds = clock_->wall_seconds();
    if (!now_wall_seconds) return std::nullopt;
    const auto refreshed = make_cached_response(request, merged, request_wall_seconds,
                                                now_wall_seconds, clock_->monotonic_ns());
    if (!refreshed) return std::nullopt;
    std::lock_guard<std::mutex> lock(mutex_);
    insert_locked(*refreshed);
    return refreshed;
}

bool ResponseCache::can_serve_stale_if_error(const CachedResponse& response) const {
    if (!response.stale_if_error_seconds || response.must_revalidate) return false;
    if (!clock_->wall_seconds()) return false;
    const uint64_t age = current_age(response, clock_->monotonic_ns());
    if (age < response.freshness_lifetime_seconds) return false;
    const uint64_t stale = age - response.freshness_lifetime_seconds;
    return stale <= *response.stale_if_error_seconds;
}

CachedResponse ResponseCache::response_with_current_age(const CachedResponse& response) const {
    CachedResponse out = response;
    out.headers = headers_with_age(response.headers, current_age(response, clock_->monotonic_ns()));
    return out;
}

void ResponseCache::invalidate(std::string_view url) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->url == url) {
            total_bytes_ -= std::min(total_bytes_, it->accounted_bytes);
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

void ResponseCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    total_bytes_ = 0;
}

size_t ResponseCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

size_t ResponseCache::bytes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_bytes_;
}

bool ResponseCache::get(std::string_view method, std::string_view url, Response& out) {
    HeaderList request_headers;
    const CacheLookup result = lookup({method, url, request_headers, false});
    if (result.state != CacheState::Fresh || !result.response) return false;
    out.status_code = result.response->status_code;
    out.headers = result.response->headers;
    out.body = result.response->body;
    return true;
}

void ResponseCache::put(std::string_view method, std::string_view url, const Response& response) {
    HeaderList request_headers;
    (void)store({method, url, request_headers, false}, response);
}

} /* namespace kathttp3 */

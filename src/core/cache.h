#ifndef KATHTTP3_CACHE_H
#define KATHTTP3_CACHE_H

#include <list>
#include <mutex>
#include <string>
#include <unordered_map>

#include "response.h"

namespace kathttp3 {

/* Simple in-memory LRU cache for cacheable GET responses. Honors the
 * most common Cache-Control directives (no-store, max-age). */
class ResponseCache {
   public:
    explicit ResponseCache(size_t max_entries) : max_entries_(max_entries) {}

    /* Returns true and fills `out` if a fresh entry exists for (method,url). */
    bool get(std::string_view method, std::string_view url, Response& out);

    /* Store a response if it is cacheable. */
    void put(std::string_view method, std::string_view url, const Response& resp);

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        map_.clear();
        lru_.clear();
    }

   private:
    bool cacheable(std::string_view method, const Response& resp) const;

    struct Entry {
        std::string key;
        Response resp;
        uint64_t cached_at = 0;
        uint64_t max_age = 0;
    };

    std::mutex mu_;
    size_t max_entries_;
    std::list<Entry> lru_;  // front = most recently used
    std::unordered_map<std::string, std::list<Entry>::iterator> map_;
};

} /* namespace kathttp3 */

#endif /* KATHTTP3_CACHE_H */

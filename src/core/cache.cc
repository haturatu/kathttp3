#include "cache.h"

#include <algorithm>
#include <ctime>

namespace kathttp3 {

bool ResponseCache::cacheable(std::string_view method, const Response& resp) const {
    if (method != "GET") return false;
    std::string cc(resp.headers.get("cache-control"));
    if (cc.empty()) return false;
    std::string lower;
    lower.reserve(cc.size());
    for (char c : cc) lower.push_back(static_cast<char>(std::tolower(c)));
    if (lower.find("no-store") != std::string_view::npos) return false;
    if (lower.find("private") != std::string_view::npos) return false;
    if (lower.find("max-age") == std::string_view::npos) return false;
    int s = resp.status_code;
    return s == 200 || s == 203 || s == 300 || s == 301;
}

bool ResponseCache::get(std::string_view method, std::string_view url, Response& out) {
    if (method != "GET") return false;
    std::string key(method);
    key += ' ';
    key += url;
    std::lock_guard<std::mutex> lk(mu_);
    auto it = map_.find(key);
    if (it == map_.end()) return false;
    Entry& e = *it->second;
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    if (e.max_age && now - e.cached_at > e.max_age) {
        lru_.erase(it->second);
        map_.erase(it);
        return false;
    }
    lru_.splice(lru_.begin(), lru_, it->second);
    out = e.resp;
    return true;
}

void ResponseCache::put(std::string_view method, std::string_view url, const Response& resp) {
    if (!cacheable(method, resp)) return;
    std::string key(method);
    key += ' ';
    key += url;

    uint64_t max_age = 0;
    std::string cc(resp.headers.get("cache-control"));
    auto pos = cc.find("max-age");
    if (pos != std::string::npos) {
        auto eq = cc.find('=', pos);
        if (eq != std::string::npos) {
            auto end = cc.find_first_of(",;", eq + 1);
            std::string v =
                cc.substr(eq + 1, end == std::string::npos ? std::string::npos : end - (eq + 1));
            max_age = strtoull(v.c_str(), nullptr, 10);
        }
    }

    std::lock_guard<std::mutex> lk(mu_);
    auto it = map_.find(key);
    if (it != map_.end()) {
        lru_.erase(it->second);
        map_.erase(it);
    }
    lru_.push_front(
        Entry{std::string(key), resp, static_cast<uint64_t>(std::time(nullptr)), max_age});
    map_.emplace(key, lru_.begin());
    while (max_entries_ && lru_.size() > max_entries_) {
        auto last = std::prev(lru_.end());
        map_.erase(last->key);
        lru_.pop_back();
    }
}

} /* namespace kathttp3 */

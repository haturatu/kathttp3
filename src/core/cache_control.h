#ifndef KATHTTP3_CACHE_CONTROL_H
#define KATHTTP3_CACHE_CONTROL_H

#include <cstdint>
#include <optional>
#include <string_view>

#include "header_list.h"

namespace kathttp3 {

/* The cache directives used by the native private HTTP cache. Unknown
 * directives are intentionally ignored after being parsed as complete
 * directives; substring matching is never used for policy decisions. */
struct CacheControl {
    bool no_store = false;
    bool no_cache = false;
    bool must_revalidate = false;
    bool is_private = false;

    std::optional<uint64_t> max_age;
    std::optional<uint64_t> stale_if_error;

    /* A recognized numeric directive was malformed or conflicting. Such a
     * response is never considered fresh or storable. */
    bool invalid = false;
    bool conflicting_max_age = false;
};

/* Parse a non-negative decimal delta-seconds value. Invalid characters return
 * nullopt. Valid decimal values larger than uint64_t saturate at UINT64_MAX. */
std::optional<uint64_t> parse_delta_seconds(std::string_view value);

CacheControl parse_cache_control(const HeaderList& headers);

} /* namespace kathttp3 */

#endif /* KATHTTP3_CACHE_CONTROL_H */

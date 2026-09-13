#ifndef KATHTTP3_HTTP_DATE_H
#define KATHTTP3_HTTP_DATE_H

#include <cstdint>
#include <optional>
#include <string_view>

namespace kathttp3 {

/* Parse IMF-fixdate and the two obsolete HTTP-date forms from RFC 9110.
 * Returned values are seconds since the Unix epoch. */
std::optional<int64_t> parse_http_date(std::string_view value);

} /* namespace kathttp3 */

#endif /* KATHTTP3_HTTP_DATE_H */

#ifndef KATHTTP3_HTTP_DATE_H
#define KATHTTP3_HTTP_DATE_H

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace kathttp3 {

/* Parse IMF-fixdate and the two obsolete HTTP-date forms from RFC 9110.
 * Returned values are seconds since the Unix epoch. RFC 850 two-digit years
 * require a reference wall time for the rolling 50-year future limit; without
 * that clock only the two four-digit-year formats can be parsed. Leap seconds
 * are normalized to the next Unix second. */
std::optional<int64_t> parse_http_date(std::string_view value,
                                       std::optional<uint64_t> reference_seconds = std::nullopt);

/* Format an IMF-fixdate in GMT. Values beyond the representable four-digit
 * HTTP-date year range are saturated to the latest representable date. */
std::string format_http_date(uint64_t seconds);

} /* namespace kathttp3 */

#endif /* KATHTTP3_HTTP_DATE_H */

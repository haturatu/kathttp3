#ifndef KATHTTP3_HTTP_DATE_H
#define KATHTTP3_HTTP_DATE_H

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace kathttp3 {

/* Parse IMF-fixdate and the two obsolete HTTP-date forms from RFC 9110.
 * Returned values are seconds since the Unix epoch. */
std::optional<int64_t> parse_http_date(std::string_view value);

/* Format an IMF-fixdate in GMT. Values beyond the representable four-digit
 * HTTP-date year range are saturated to the latest representable date. */
std::string format_http_date(uint64_t seconds);

} /* namespace kathttp3 */

#endif /* KATHTTP3_HTTP_DATE_H */

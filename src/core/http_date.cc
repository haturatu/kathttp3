#include "http_date.h"

#include <array>
#include <cctype>
#include <charconv>
#include <limits>
#include <string>
#include <vector>

namespace kathttp3 {

namespace {

std::string_view trim_ows(std::string_view value) {
    const size_t begin = value.find_first_not_of(" \t");
    if (begin == std::string_view::npos) return {};
    const size_t end = value.find_last_not_of(" \t");
    return value.substr(begin, end - begin + 1);
}

std::vector<std::string_view> split_spaces(std::string_view value) {
    std::vector<std::string_view> out;
    for (size_t pos = 0; pos < value.size();) {
        while (pos < value.size() && (value[pos] == ' ' || value[pos] == '\t')) ++pos;
        const size_t begin = pos;
        while (pos < value.size() && value[pos] != ' ' && value[pos] != '\t') ++pos;
        if (begin != pos) out.push_back(value.substr(begin, pos - begin));
    }
    return out;
}

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

bool valid_weekday(std::string_view value, bool long_form) {
    if (long_form) {
        constexpr std::array<std::string_view, 7> kLongWeekdays = {
            "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
        };
        for (const auto weekday : kLongWeekdays)
            if (ascii_iequals(value, weekday)) return true;
        return false;
    }
    constexpr std::array<std::string_view, 7> kShortWeekdays = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
    };
    for (const auto weekday : kShortWeekdays)
        if (ascii_iequals(value, weekday)) return true;
    return false;
}

bool parse_number(std::string_view value, size_t min_digits, size_t max_digits, int& out) {
    if (value.size() < min_digits || value.size() > max_digits) return false;
    for (const char raw : value) {
        const unsigned char ch = static_cast<unsigned char>(raw);
        if (ch < '0' || ch > '9') return false;
    }
    const auto result = std::from_chars(value.data(), value.data() + value.size(), out);
    return result.ec == std::errc{} && result.ptr == value.data() + value.size();
}

int month_number(std::string_view value) {
    if (value.size() != 3) return 0;
    constexpr std::array<std::string_view, 12> kMonths = {
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    };
    for (size_t i = 0; i < kMonths.size(); ++i) {
        if (ascii_iequals(value, kMonths[i])) return static_cast<int>(i + 1);
    }
    return 0;
}

bool parse_time(std::string_view value, int& hour, int& minute, int& second) {
    if (value.size() != 8 || value[2] != ':' || value[5] != ':') return false;
    return parse_number(value.substr(0, 2), 2, 2, hour) &&
           parse_number(value.substr(3, 2), 2, 2, minute) &&
           parse_number(value.substr(6, 2), 2, 2, second);
}

bool leap_year(int year) {
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

int days_in_month(int year, int month) {
    constexpr std::array<int, 12> kDays = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return month == 2 && leap_year(year) ? 29 : kDays[static_cast<size_t>(month - 1)];
}

int64_t days_from_civil(int year, unsigned month, unsigned day) {
    year -= month <= 2;
    const int era = (year >= 0 ? year : year - 399) / 400;
    const unsigned year_of_era = static_cast<unsigned>(year - era * 400);
    const unsigned adjusted_month = month > 2 ? month - 3 : month + 9;
    const unsigned day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    const unsigned day_of_era =
        year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    return static_cast<int64_t>(era) * 146097 + static_cast<int64_t>(day_of_era) - 719468;
}

void civil_from_days(int64_t days, int64_t& year, unsigned& month, unsigned& day) {
    days += 719468;
    const int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const unsigned day_of_era = static_cast<unsigned>(days - era * 146097);
    const unsigned year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    year = static_cast<int64_t>(year_of_era) + era * 400;
    const unsigned day_of_year =
        day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    const unsigned adjusted_month = (5 * day_of_year + 2) / 153;
    day = day_of_year - (153 * adjusted_month + 2) / 5 + 1;
    month = adjusted_month < 10 ? adjusted_month + 3 : adjusted_month - 9;
    year += month <= 2;
}

void append_fixed_decimal(std::string& out, uint64_t value, size_t width) {
    char buffer[32]{};
    const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value);
    const size_t digits = static_cast<size_t>(result.ptr - buffer);
    out.append(width > digits ? width - digits : 0, '0');
    out.append(buffer, digits);
}

std::optional<int64_t> make_timestamp(int year, int month, int day, int hour, int minute,
                                      int second) {
    if (year < 1601 || month < 1 || month > 12 || day < 1 || day > days_in_month(year, month) ||
        hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) {
        return std::nullopt;
    }
    const int64_t days =
        days_from_civil(year, static_cast<unsigned>(month), static_cast<unsigned>(day));
    constexpr int64_t kSecondsPerDay = 86400;
    if (days > std::numeric_limits<int64_t>::max() / kSecondsPerDay ||
        days < std::numeric_limits<int64_t>::min() / kSecondsPerDay) {
        return std::nullopt;
    }
    const int64_t day_seconds = days * kSecondsPerDay;
    const int64_t seconds_of_day = hour * 3600 + minute * 60 + second;
    if (day_seconds > std::numeric_limits<int64_t>::max() - seconds_of_day ||
        day_seconds < std::numeric_limits<int64_t>::min() + seconds_of_day) {
        return std::nullopt;
    }
    return day_seconds + seconds_of_day;
}

}  // namespace

std::optional<int64_t> parse_http_date(std::string_view value,
                                       std::optional<uint64_t> reference_seconds) {
    value = trim_ows(value);
    if (value.empty()) return std::nullopt;

    const size_t comma = value.find(',');
    if (comma != std::string_view::npos) {
        const std::string_view weekday = trim_ows(value.substr(0, comma));
        const auto fields = split_spaces(value.substr(comma + 1));
        if (fields.size() == 5) {
            int day = 0;
            int year = 0;
            int hour = 0;
            int minute = 0;
            int second = 0;
            if (!valid_weekday(weekday, false) || !parse_number(fields[0], 2, 2, day) ||
                month_number(fields[1]) == 0 || !parse_number(fields[2], 4, 4, year) ||
                !parse_time(fields[3], hour, minute, second) || !ascii_iequals(fields[4], "GMT")) {
                return std::nullopt;
            }
            /* IMF-fixdate ends in GMT; accept only that fixed zone. */
            return make_timestamp(year, month_number(fields[1]), day, hour, minute, second);
        }
        if (fields.size() == 3) {
            const size_t first_dash = fields[0].find('-');
            const size_t second_dash = fields[0].find('-', first_dash + 1);
            if (!valid_weekday(weekday, true) || first_dash == std::string_view::npos ||
                second_dash == std::string_view::npos ||
                fields[0].find('-', second_dash + 1) != std::string_view::npos ||
                !ascii_iequals(fields[2], "GMT")) {
                return std::nullopt;
            }
            int day = 0;
            int year = 0;
            int hour = 0;
            int minute = 0;
            int second = 0;
            if (!parse_number(fields[0].substr(0, first_dash), 2, 2, day) ||
                month_number(fields[0].substr(first_dash + 1, second_dash - first_dash - 1)) == 0 ||
                !parse_number(fields[0].substr(second_dash + 1), 2, 2, year) ||
                !parse_time(fields[1], hour, minute, second)) {
                return std::nullopt;
            }
            // Pick the latest matching year whose full date is at most 50
            // calendar years ahead of the injected clock (RFC 9110 5.6.7).
            constexpr uint64_t kMaxReferenceSeconds = 253402300799ULL;  // 9999-12-31
            if (!reference_seconds || *reference_seconds > kMaxReferenceSeconds)
                return std::nullopt;
            int64_t reference_year = 0;
            unsigned reference_month = 0;
            unsigned reference_day = 0;
            civil_from_days(static_cast<int64_t>(*reference_seconds / 86400), reference_year,
                            reference_month, reference_day);
            const int reference_time = static_cast<int>(*reference_seconds % 86400);
            year += static_cast<int>((reference_year + 50) / 100) * 100;
            const int month =
                month_number(fields[0].substr(first_dash + 1, second_dash - first_dash - 1));
            const std::array<int64_t, 6> candidate = {year, month, day, hour, minute, second};
            const std::array<int64_t, 6> future_limit = {reference_year + 50,
                                                         reference_month,
                                                         reference_day,
                                                         reference_time / 3600,
                                                         (reference_time / 60) % 60,
                                                         reference_time % 60};
            if (candidate > future_limit) year -= 100;
            return make_timestamp(
                year, month_number(fields[0].substr(first_dash + 1, second_dash - first_dash - 1)),
                day, hour, minute, second);
        }
        return std::nullopt;
    }

    /* asctime-date: Sun Nov  6 08:49:37 1994 */
    const auto fields = split_spaces(value);
    if (fields.size() != 5) return std::nullopt;
    int day = 0;
    int year = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    const int month = month_number(fields[1]);
    if (!valid_weekday(fields[0], false) || month == 0 || !parse_number(fields[2], 1, 2, day) ||
        !parse_time(fields[3], hour, minute, second) || !parse_number(fields[4], 4, 4, year)) {
        return std::nullopt;
    }
    return make_timestamp(year, month, day, hour, minute, second);
}

std::string format_http_date(uint64_t seconds) {
    constexpr int64_t kSecondsPerDay = 86400;
    constexpr int kMaxYear = 9999;
    const int64_t kMaxDateSeconds =
        days_from_civil(kMaxYear, 12, 31) * kSecondsPerDay + (kSecondsPerDay - 1);
    const uint64_t max_date_seconds = static_cast<uint64_t>(kMaxDateSeconds);
    if (seconds > max_date_seconds) seconds = max_date_seconds;

    const int64_t signed_seconds = static_cast<int64_t>(seconds);
    const int64_t days = signed_seconds / kSecondsPerDay;
    const unsigned seconds_of_day = static_cast<unsigned>(signed_seconds % kSecondsPerDay);
    int64_t year = 0;
    unsigned month = 0;
    unsigned day = 0;
    civil_from_days(days, year, month, day);

    constexpr std::array<std::string_view, 7> kWeekdays = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
    };
    constexpr std::array<std::string_view, 12> kMonths = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    const size_t weekday = static_cast<size_t>((days + 4) % 7);
    std::string out;
    out.reserve(29);
    out.append(kWeekdays[weekday]);
    out.append(", ");
    append_fixed_decimal(out, day, 2);
    out.push_back(' ');
    out.append(kMonths[month - 1]);
    out.push_back(' ');
    append_fixed_decimal(out, static_cast<uint64_t>(year), 4);
    out.push_back(' ');
    append_fixed_decimal(out, seconds_of_day / 3600, 2);
    out.push_back(':');
    append_fixed_decimal(out, (seconds_of_day / 60) % 60, 2);
    out.push_back(':');
    append_fixed_decimal(out, seconds_of_day % 60, 2);
    out.append(" GMT");
    return out;
}

} /* namespace kathttp3 */

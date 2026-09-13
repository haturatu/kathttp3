#include "http_date.h"

#include <array>
#include <charconv>
#include <cctype>
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

bool parse_number(std::string_view value, size_t min_digits, size_t max_digits, int& out) {
    if (value.size() < min_digits || value.size() > max_digits) return false;
    for (const unsigned char ch : value) {
        if (ch < '0' || ch > '9') return false;
    }
    const auto result = std::from_chars(value.data(), value.data() + value.size(), out);
    return result.ec == std::errc{} && result.ptr == value.data() + value.size();
}

int month_number(std::string_view value) {
    if (value.size() != 3) return 0;
    constexpr std::array<std::string_view, 12> kMonths = {
        "jan", "feb", "mar", "apr", "may", "jun",
        "jul", "aug", "sep", "oct", "nov", "dec",
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
    constexpr std::array<int, 12> kDays = {31, 28, 31, 30, 31, 30,
                                           31, 31, 30, 31, 30, 31};
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

std::optional<int64_t> make_timestamp(int year, int month, int day, int hour, int minute,
                                       int second) {
    if (year < 1601 || month < 1 || month > 12 || day < 1 ||
        day > days_in_month(year, month) || hour < 0 || hour > 23 || minute < 0 || minute > 59 ||
        second < 0 || second > 59) {
        return std::nullopt;
    }
    const int64_t days = days_from_civil(year, static_cast<unsigned>(month),
                                         static_cast<unsigned>(day));
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

std::optional<int64_t> parse_http_date(std::string_view value) {
    value = trim_ows(value);
    if (value.empty()) return std::nullopt;

    const size_t comma = value.find(',');
    if (comma != std::string_view::npos) {
        const std::string_view weekday = trim_ows(value.substr(0, comma));
        if (weekday.empty()) return std::nullopt;
        const auto fields = split_spaces(value.substr(comma + 1));
        if (fields.size() == 5) {
            int day = 0;
            int year = 0;
            int hour = 0;
            int minute = 0;
            int second = 0;
            if (!parse_number(fields[0], 2, 2, day) || month_number(fields[1]) == 0 ||
                !parse_number(fields[2], 4, 4, year) || !parse_time(fields[3], hour, minute, second) ||
                !ascii_iequals(fields[4], "GMT")) {
                return std::nullopt;
            }
            /* IMF-fixdate ends in GMT; accept only that fixed zone. */
            return make_timestamp(year, month_number(fields[1]), day, hour, minute, second);
        }
        if (fields.size() == 3) {
            const size_t first_dash = fields[0].find('-');
            const size_t second_dash = fields[0].find('-', first_dash + 1);
            if (first_dash == std::string_view::npos || second_dash == std::string_view::npos ||
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
            year += year >= 70 ? 1900 : 2000;
            return make_timestamp(year,
                                 month_number(fields[0].substr(first_dash + 1,
                                                                second_dash - first_dash - 1)),
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
    if (month == 0 || !parse_number(fields[2], 1, 2, day) ||
        !parse_time(fields[3], hour, minute, second) ||
        !parse_number(fields[4], 4, 4, year)) {
        return std::nullopt;
    }
    return make_timestamp(year, month, day, hour, minute, second);
}

} /* namespace kathttp3 */

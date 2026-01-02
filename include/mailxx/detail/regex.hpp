#pragma once

#include <string>
#include <mailxx/config.hpp>

#if MAILXX_USE_STD_REGEX
#include <regex>
#else
#include <boost/regex.hpp>
#endif

namespace mailxx::detail
{
#if MAILXX_USE_STD_REGEX
using regex = std::regex;
using smatch = std::smatch;
using match_flag_type = std::regex_constants::match_flag_type;

template<typename It>
using match_results = std::match_results<It>;

constexpr match_flag_type match_default = std::regex_constants::match_default;
constexpr match_flag_type match_not_null = std::regex_constants::match_not_null;

inline bool regex_match(const std::string& input, smatch& matches, const regex& pattern)
{
    return std::regex_match(input, matches, pattern);
}

template<typename It>
inline bool regex_search(It begin, It end, match_results<It>& matches, const regex& pattern, match_flag_type flags)
{
    return std::regex_search(begin, end, matches, pattern, flags);
}
#else
using regex = boost::regex;
using smatch = boost::smatch;
using match_flag_type = boost::match_flag_type;

template<typename It>
using match_results = boost::match_results<It>;

constexpr match_flag_type match_default = boost::match_default;
constexpr match_flag_type match_not_null = boost::match_not_null;

inline bool regex_match(const std::string& input, smatch& matches, const regex& pattern)
{
    return boost::regex_match(input, matches, pattern);
}

template<typename It>
inline bool regex_search(It begin, It end, match_results<It>& matches, const regex& pattern, match_flag_type flags)
{
    return boost::regex_search(begin, end, matches, pattern, flags);
}
#endif
} // namespace mailxx::detail

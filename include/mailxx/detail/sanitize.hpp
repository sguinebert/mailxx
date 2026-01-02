/*

sanitize.hpp
------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/


#pragma once

#include <string>
#include <string_view>
#include <mailxx/detail/result.hpp>

namespace mailxx
{
namespace detail
{

inline bool contains_crlf_or_nul(std::string_view value) noexcept
{
    for (char ch : value)
    {
        if (ch == '\r' || ch == '\n' || ch == '\0')
            return true;
    }
    return false;
}

inline mailxx::result<void> ensure_no_crlf_or_nul(std::string_view value, const char* field_name)
{
    if (!contains_crlf_or_nul(value))
        return mailxx::ok();

    std::string message = "Invalid ";
    message += field_name ? field_name : "value";
    message += ": CR/LF or NUL not allowed.";
    return mailxx::fail<void>(errc::codec_invalid_input, std::move(message));
}

} // namespace detail
} // namespace mailxx

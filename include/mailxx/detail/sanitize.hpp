/*

sanitize.hpp
------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once

#include <string>
#include <string_view>
#include <stdexcept>

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

inline void ensure_no_crlf_or_nul(std::string_view value, const char* field_name)
{
    if (!contains_crlf_or_nul(value))
        return;

    std::string message = "Invalid ";
    message += field_name ? field_name : "value";
    message += ": CR/LF or NUL not allowed.";
    throw std::invalid_argument(message);
}

} // namespace detail
} // namespace mailxx

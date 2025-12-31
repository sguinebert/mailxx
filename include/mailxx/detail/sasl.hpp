/*

sasl.hpp
--------

SASL authentication helpers for mailxx.
Implements encoding for PLAIN, LOGIN, and XOAUTH2 mechanisms.

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/

#pragma once

#include <string>
#include <string_view>
#include <mailxx/codec/base64.hpp>
#include <mailxx/detail/result.hpp>

namespace mailxx::detail
{

/**
 * Remove CR/LF characters from base64 encoded string.
 * Base64 encoders may add line breaks which break SASL auth.
 */
inline std::string strip_newlines(std::string_view encoded)
{
    std::string result;
    result.reserve(encoded.size());
    for (char c : encoded)
    {
        if (c != '\r' && c != '\n')
            result.push_back(c);
    }
    return result;
}

/**
 * Base64 encode without line breaks.
 * Uses NONE policy to avoid line wrapping, then strips any remaining newlines.
 * Returns error info on invalid base64 input.
 */
inline result<std::string> base64_encode_single_line(std::string_view input)
{
    // Use maximum line length to avoid wrapping
    base64 b64(static_cast<std::string::size_type>(codec::line_len_policy_t::NONE),
               static_cast<std::string::size_type>(codec::line_len_policy_t::NONE));
    auto encoded = b64.encode(input);
    if (!encoded)
        return encoded;
    return ok(strip_newlines(*encoded));
}

} // namespace mailxx::detail

namespace mailxx::sasl
{

/**
 * Encode credentials for SASL PLAIN mechanism.
 * Format: \0username\0password (then base64 encoded)
 * 
 * @param username The username/email
 * @param password The password
 * @return Result with base64 encoded PLAIN credentials
 */
inline result<std::string> encode_plain(std::string_view username, std::string_view password)
{
    std::string plain;
    plain.reserve(2 + username.size() + password.size());
    plain.push_back('\0');
    plain += username;
    plain.push_back('\0');
    plain += password;
    
    return ::mailxx::detail::base64_encode_single_line(plain);
}

/**
 * Encode text for SASL LOGIN mechanism.
 * Returns base64 encoded text (username or password separately).
 * 
 * @param text The text to encode (username or password)
 * @return Result with base64 encoded text
 */
inline result<std::string> encode_login(std::string_view text)
{
    return ::mailxx::detail::base64_encode_single_line(text);
}

/**
 * Encode credentials for XOAUTH2 mechanism (Google/Microsoft OAuth2).
 * Format: user=<email>\x01auth=Bearer <token>\x01\x01 (then base64 encoded)
 * 
 * @param username The email address
 * @param access_token The OAuth2 access token
 * @return Result with base64 encoded XOAUTH2 string
 */
inline result<std::string> encode_xoauth2(std::string_view username, std::string_view access_token)
{
    std::string xoauth2;
    xoauth2.reserve(5 + username.size() + 13 + access_token.size() + 2);
    xoauth2 += "user=";
    xoauth2 += username;
    xoauth2 += '\x01';
    xoauth2 += "auth=Bearer ";
    xoauth2 += access_token;
    xoauth2 += "\x01\x01";
    
    return ::mailxx::detail::base64_encode_single_line(xoauth2);
}

/**
 * Encode credentials for OAUTHBEARER mechanism (RFC 7628).
 * Format: n,a=<email>,\x01auth=Bearer <token>\x01\x01 (then base64 encoded)
 * 
 * @param username The email address
 * @param access_token The OAuth2 access token
 * @return Result with base64 encoded OAUTHBEARER string
 */
inline result<std::string> encode_oauthbearer(std::string_view username, std::string_view access_token)
{
    std::string bearer;
    bearer.reserve(4 + username.size() + 14 + access_token.size() + 2);
    bearer += "n,a=";
    bearer += username;
    bearer += ",\x01auth=Bearer ";
    bearer += access_token;
    bearer += "\x01\x01";
    
    return ::mailxx::detail::base64_encode_single_line(bearer);
}

} // namespace mailxx::sasl

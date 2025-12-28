/*

tls_options.hpp
---------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/

#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <openssl/ssl.h>
#include <mailxx/net/tls_mode.hpp>

namespace mailxx::net
{

enum class verify_mode
{
    none,
    peer
};

struct tls_options
{
    verify_mode verify = verify_mode::peer;
    bool verify_host = true;
    std::optional<int> min_tls_version = TLS1_2_VERSION;
    std::string cipher_list;
    bool use_default_verify_paths = true;
    std::vector<std::string> ca_files;
    std::vector<std::string> ca_paths;
    std::vector<std::string> pinned_spki_sha256;
    std::vector<std::string> pinned_cert_sha256;
    bool allow_self_signed = false;
    bool allow_expired = false;
};

[[nodiscard]] inline std::string normalize_fingerprint(std::string_view input)
{
    std::string compact;
    compact.reserve(input.size());
    for (char ch : input)
    {
        if (std::isspace(static_cast<unsigned char>(ch)))
            continue;
        compact.push_back(ch);
    }

    std::string hex_candidate;
    hex_candidate.reserve(compact.size());
    for (char ch : compact)
    {
        if (ch == ':' || ch == '-')
            continue;
        hex_candidate.push_back(ch);
    }

    auto is_hex_digit = [](char ch) noexcept
    {
        return (ch >= '0' && ch <= '9')
            || (ch >= 'a' && ch <= 'f')
            || (ch >= 'A' && ch <= 'F');
    };

    bool is_hex = !hex_candidate.empty();
    for (char ch : hex_candidate)
    {
        if (!is_hex_digit(ch))
        {
            is_hex = false;
            break;
        }
    }

    if (is_hex)
    {
        std::string normalized;
        normalized.reserve(hex_candidate.size());
        for (char ch : hex_candidate)
        {
            if (ch >= 'A' && ch <= 'F')
                normalized.push_back(static_cast<char>(ch + ('a' - 'A')));
            else
                normalized.push_back(ch);
        }
        return normalized;
    }

    std::string base64 = compact;
    std::size_t mod = base64.size() % 4;
    if (mod != 0)
        base64.append(4 - mod, '=');
    return base64;
}

[[nodiscard]] inline bool constant_time_equals(std::string_view a, std::string_view b) noexcept
{
    std::size_t diff = a.size() ^ b.size();
    const std::size_t max_len = std::max(a.size(), b.size());
    for (std::size_t i = 0; i < max_len; ++i)
    {
        const unsigned char ca = i < a.size()
            ? static_cast<unsigned char>(a[i])
            : static_cast<unsigned char>(0);
        const unsigned char cb = i < b.size()
            ? static_cast<unsigned char>(b[i])
            : static_cast<unsigned char>(0);
        diff |= static_cast<std::size_t>(ca ^ cb);
    }
    return diff == 0;
}

} // namespace mailxx::net

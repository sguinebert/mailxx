/*

token.hpp
---------

Lightweight OAuth2 token type for mailxx.

*/

#pragma once

#include <chrono>
#include <string>

namespace mailxx::oauth2
{

struct token
{
    std::string access_token;
    std::string refresh_token;
    std::chrono::system_clock::time_point expires_at{};

    [[nodiscard]] bool expired(std::chrono::system_clock::time_point now,
        std::chrono::seconds skew = std::chrono::seconds{30}) const noexcept
    {
        return expires_at <= now + skew;
    }
};

} // namespace mailxx::oauth2

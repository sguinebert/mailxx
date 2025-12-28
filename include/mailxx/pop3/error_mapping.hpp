/*

error_mapping.hpp
-----------------

Centralized mapping between POP3 responses and mailxx::errc.

*/

#pragma once

#include <string_view>

#include <mailxx/detail/result.hpp>

namespace mailxx::pop3
{

enum class error_kind
{
    response,
    auth,
    invalid_state
};

[[nodiscard]] constexpr errc map_pop3_error(error_kind kind, std::string_view status = {}) noexcept
{
    switch (kind)
    {
        case error_kind::auth: return errc::pop3_auth_failed;
        case error_kind::invalid_state: return errc::pop3_invalid_state;
        case error_kind::response:
            if (status == "-ERR")
                return errc::pop3_negative_response;
            return errc::pop3_negative_response;
    }
    return errc::pop3_negative_response;
}

[[nodiscard]] inline detail::error_detail make_pop3_detail(std::string_view command, std::string_view response_line = {})
{
    detail::error_detail detail;
    detail.add("proto", "pop3");
    detail.add("command", command);
    detail.add("response.line", response_line);
    return detail;
}

} // namespace mailxx::pop3

/*

asio_error.hpp
--------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

Utility functions to convert Asio error codes to mailxx::error.
This file bridges asio_decl.hpp and result.hpp.

*/

#pragma once

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/result.hpp>

namespace mailxx
{

/// Convert asio::error_code to mailxx::error
[[nodiscard]] inline error error_from_asio(const asio::error_code& ec)
{
    if (!ec)
        return error{};
    
    error_code code = error_code::socket_error;
    
    // Connection errors
    if (ec == asio::error::connection_refused ||
        ec == asio::error::host_unreachable ||
        ec == asio::error::network_unreachable)
    {
        code = error_code::connection_failed;
    }
    // Connection closed errors
    else if (ec == asio::error::eof ||
             ec == asio::error::connection_reset ||
             ec == asio::error::broken_pipe)
    {
        code = error_code::connection_closed;
    }
    // Timeout errors
    else if (ec == asio::error::timed_out)
    {
        code = error_code::connection_timeout;
    }
    // Cancelled operations
    else if (ec == asio::error::operation_aborted)
    {
        code = error_code::cancelled;
    }
    // DNS errors
    else if (ec == asio::error::host_not_found ||
             ec == asio::error::host_not_found_try_again)
    {
        code = error_code::dns_resolution_failed;
    }
    
    return error(code, ec.message());
}

/// Helper to convert asio tuple result to mailxx::result
template<typename T>
[[nodiscard]] inline result<T> to_result(const std::tuple<asio::error_code, T>& tuple)
{
    const auto& [ec, value] = tuple;
    if (ec)
        return fail<T>(error_from_asio(ec));
    return ok(value);
}

/// Helper for void operations
[[nodiscard]] inline result_void to_result(const std::tuple<asio::error_code>& tuple)
{
    const auto& [ec] = tuple;
    if (ec)
        return fail(error_from_asio(ec));
    return ok();
}

/// Helper for operations returning size_t (common in async_read/write)
[[nodiscard]] inline result<std::size_t> to_result(const std::tuple<asio::error_code, std::size_t>& tuple)
{
    const auto& [ec, bytes] = tuple;
    if (ec)
        return fail<std::size_t>(error_from_asio(ec));
    return ok(bytes);
}

} // namespace mailxx

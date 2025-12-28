/*

asio_error.hpp
--------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

Utility functions to convert Asio error codes to mailxx::error_info.
This file bridges asio_decl.hpp and result.hpp.

*/

#pragma once

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/result.hpp>
#include <mailxx/net/error_mapping.hpp>

namespace mailxx
{

/// Convert asio::error_code to mailxx::error_info
[[nodiscard]] inline error_info error_from_asio(
    const asio::error_code& ec,
    net::io_stage stage = net::io_stage::connect,
    bool timeout_triggered = false)
{
    if (!ec)
        return {};

    const errc code = net::map_net_error(stage, ec, timeout_triggered);

    return make_error(code, ec.message(), {}, ec);
}

/// Helper to convert asio tuple result to mailxx::result
template<typename T>
[[nodiscard]] inline result<T> to_result(
    const std::tuple<asio::error_code, T>& tuple,
    net::io_stage stage = net::io_stage::connect,
    bool timeout_triggered = false)
{
    const auto& [ec, value] = tuple;
    if (ec)
        return fail<T>(error_from_asio(ec, stage, timeout_triggered));
    return ok(value);
}

/// Helper for void operations
[[nodiscard]] inline result_void to_result(
    const std::tuple<asio::error_code>& tuple,
    net::io_stage stage = net::io_stage::connect,
    bool timeout_triggered = false)
{
    const auto& [ec] = tuple;
    if (ec)
        return fail<void>(error_from_asio(ec, stage, timeout_triggered));
    return ok();
}

/// Helper for operations returning size_t (common in async_read/write)
[[nodiscard]] inline result<std::size_t> to_result(
    const std::tuple<asio::error_code, std::size_t>& tuple,
    net::io_stage stage = net::io_stage::connect,
    bool timeout_triggered = false)
{
    const auto& [ec, bytes] = tuple;
    if (ec)
        return fail<std::size_t>(error_from_asio(ec, stage, timeout_triggered));
    return ok(bytes);
}

} // namespace mailxx

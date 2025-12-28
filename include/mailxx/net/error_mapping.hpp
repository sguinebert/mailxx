/*

error_mapping.hpp
-----------------

Centralized mapping between Asio error codes and mailxx::errc for network I/O.

*/

#pragma once

#include <string_view>
#include <system_error>

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/result.hpp>

namespace mailxx::net
{

enum class io_stage
{
    resolve,
    connect,
    read,
    write,
    handshake
};

[[nodiscard]] constexpr std::string_view stage_name(io_stage stage) noexcept
{
    switch (stage)
    {
        case io_stage::resolve: return "resolve";
        case io_stage::connect: return "connect";
        case io_stage::read: return "read";
        case io_stage::write: return "write";
        case io_stage::handshake: return "handshake";
    }
    return "unknown";
}

[[nodiscard]] inline errc map_net_error(io_stage stage, std::error_code ec, bool timeout_triggered) noexcept
{
    if (timeout_triggered || ec == mailxx::asio::error::timed_out)
        return errc::net_timeout;
    if (ec == mailxx::asio::error::operation_aborted)
        return errc::net_cancelled;
    if (ec == mailxx::asio::error::eof)
        return errc::net_eof;
    if (ec == mailxx::asio::error::connection_refused)
        return errc::net_connection_refused;
    if (ec == mailxx::asio::error::connection_reset ||
        ec == mailxx::asio::error::broken_pipe)
        return errc::net_connection_reset;
    if (ec == mailxx::asio::error::host_not_found ||
        ec == mailxx::asio::error::host_not_found_try_again)
        return errc::net_resolve_failed;

    switch (stage)
    {
        case io_stage::resolve: return errc::net_resolve_failed;
        case io_stage::connect: return errc::net_connect_failed;
        case io_stage::read: return errc::net_io_failed;
        case io_stage::write: return errc::net_io_failed;
        case io_stage::handshake: return errc::tls_handshake_failed;
    }
    return errc::net_io_failed;
}

[[nodiscard]] inline detail::error_detail make_net_detail(
    std::string_view proto,
    std::string_view host,
    std::string_view service,
    io_stage stage,
    std::string_view op)
{
    detail::error_detail detail;
    detail.add("proto", proto);
    detail.add("host", host);
    detail.add("service", service);
    detail.add("stage", stage_name(stage));
    detail.add("op", op);
    return detail;
}

} // namespace mailxx::net

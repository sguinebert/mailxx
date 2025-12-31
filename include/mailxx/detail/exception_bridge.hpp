/*

exception_bridge.hpp
--------------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

Helpers to bridge exception-based code into mailxx::result.

*/

#pragma once

#include <exception>
#include <functional>
#include <type_traits>
#include <utility>

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/awaitable_traits.hpp>
#include <mailxx/detail/result.hpp>
#include <mailxx/imap/error.hpp>
#include <mailxx/net/dialog.hpp>
#include <mailxx/pop3/error.hpp>
#include <mailxx/smtp/error.hpp>

namespace mailxx
{

[[nodiscard]] inline error_info from_exception(
    std::exception_ptr eptr,
    errc fallback,
    std::source_location where = std::source_location::current())
{
    if (!eptr)
        return make_error(fallback, "unknown exception", std::string{}, {}, where);

    try
    {
        std::rethrow_exception(eptr);
    }
    catch (const smtp::error& exc)
    {
        return make_error(fallback, exc.what(), exc.details(), {}, where);
    }
    catch (const pop3::error& exc)
    {
        return make_error(fallback, exc.what(), exc.details(), {}, where);
    }
    catch (const imap::error& exc)
    {
        return make_error(fallback, exc.what(), exc.details(), {}, where);
    }
    catch (const net::dialog_error& exc)
    {
        return make_error(fallback, exc.what(), exc.details(), {}, where);
    }
    catch (const std::system_error& exc)
    {
        return make_error(fallback, exc.what(), std::string{}, exc.code(), where);
    }
    catch (const std::exception& exc)
    {
        return make_error(fallback, exc.what(), std::string{}, {}, where);
    }
    catch (...)
    {
        return make_error(fallback, "unknown exception", std::string{}, {}, where);
    }
}

template<class F>
[[nodiscard]] auto protect(F&& f, errc fallback) -> result<std::invoke_result_t<F>>
{
    using ret_t = std::invoke_result_t<F>;
    try
    {
        if constexpr (std::is_void_v<ret_t>)
        {
            std::invoke(std::forward<F>(f));
            return ok();
        }
        else
        {
            return ok(std::invoke(std::forward<F>(f)));
        }
    }
    catch (...)
    {
        return detail::make_unexpected(from_exception(std::current_exception(), fallback, std::source_location::current()));
    }
}

template<class F>
[[nodiscard]] auto protect_awaitable(F&& f, errc fallback)
    -> mailxx::asio::awaitable<result<detail::awaitable_value_t<std::invoke_result_t<F>>>>
{
    using awaitable_t = std::invoke_result_t<F>;
    using value_t = detail::awaitable_value_t<awaitable_t>;
    try
    {
        if constexpr (std::is_void_v<value_t>)
        {
            co_await std::invoke(std::forward<F>(f));
            co_return ok();
        }
        else
        {
            co_return ok(co_await std::invoke(std::forward<F>(f)));
        }
    }
    catch (...)
    {
        co_return detail::make_unexpected(from_exception(std::current_exception(), fallback, std::source_location::current()));
    }
}

} // namespace mailxx

/*

result.hpp
----------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

Error handling types using expected (C++23).
No exceptions are thrown in mailxx - all errors are returned via result<T>.

*/

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <ostream>
#include <system_error>
#include <source_location>
#include <tuple>
#include <type_traits>
#include <utility>

#include <mailxx/detail/error_detail.hpp>

#if defined(__has_include)
#if __has_include(<expected>)
#include <expected>
#define MAILXX_HAS_STD_EXPECTED 1
#elif __has_include(<tl/expected.hpp>)
#include <tl/expected.hpp>
#define MAILXX_HAS_TL_EXPECTED 1
#endif
#endif

#if !defined(MAILXX_HAS_STD_EXPECTED) && !defined(MAILXX_HAS_TL_EXPECTED)
#error "mailxx requires <expected> or <tl/expected.hpp>."
#endif

namespace mailxx
{

namespace detail
{

#if defined(MAILXX_HAS_STD_EXPECTED)
template<class T, class E>
using expected = std::expected<T, E>;

template<class E>
using unexpected = std::unexpected<E>;

template<class E>
[[nodiscard]] constexpr unexpected<std::decay_t<E>> make_unexpected(E&& err)
{
    return std::unexpected<std::decay_t<E>>(std::forward<E>(err));
}
#else
template<class T, class E>
using expected = tl::expected<T, E>;

template<class E>
using unexpected = tl::unexpected<E>;

template<class E>
[[nodiscard]] constexpr unexpected<std::decay_t<E>> make_unexpected(E&& err)
{
    return tl::make_unexpected(std::forward<E>(err));
}
#endif

template<class Exp, class F>
[[nodiscard]] constexpr auto expected_transform(Exp&& exp, F&& f)
{
    if constexpr (requires { std::forward<Exp>(exp).transform(std::forward<F>(f)); })
        return std::forward<Exp>(exp).transform(std::forward<F>(f));
    return std::forward<Exp>(exp).map(std::forward<F>(f));
}

template<class Exp, class F>
[[nodiscard]] constexpr auto expected_transform_error(Exp&& exp, F&& f)
{
    if constexpr (requires { std::forward<Exp>(exp).transform_error(std::forward<F>(f)); })
        return std::forward<Exp>(exp).transform_error(std::forward<F>(f));
    return std::forward<Exp>(exp).map_error(std::forward<F>(f));
}

} // namespace detail

/// Error categories for mailxx operations
enum class errc : std::uint32_t
{
    ok = 0,

    net_resolve_failed,
    net_connect_failed,
    net_connection_refused,
    net_connection_reset,
    net_io_failed,
    net_timeout,
    net_eof,
    net_cancelled,

    tls_handshake_failed,
    tls_verify_failed,
    tls_pinning_failed,

    smtp_invalid_state,
    smtp_bad_reply,
    smtp_auth_failed,
    smtp_service_not_available,
    smtp_mail_from_rejected,
    smtp_rejected_recipient,
    smtp_data_rejected,
    smtp_temporary_failure,
    smtp_permanent_failure,

    pop3_invalid_state,
    pop3_negative_response,
    pop3_auth_failed,

    imap_invalid_state,
    imap_tagged_no,
    imap_tagged_bad,
    imap_parse_error,
    imap_continuation_expected,

    pool_invalid_state,
    pool_timeout,
    pool_exhausted,
    pool_config_error,

    codec_invalid_input,
    mime_parse_error,
};

/// Convert error code to string
[[nodiscard]] constexpr std::string_view to_string(errc code) noexcept
{
    switch (code)
    {
        case errc::ok: return "ok";
        case errc::net_resolve_failed: return "net_resolve_failed";
        case errc::net_connect_failed: return "net_connect_failed";
        case errc::net_connection_refused: return "net_connection_refused";
        case errc::net_connection_reset: return "net_connection_reset";
        case errc::net_io_failed: return "net_io_failed";
        case errc::net_timeout: return "net_timeout";
        case errc::net_eof: return "net_eof";
        case errc::net_cancelled: return "net_cancelled";
        case errc::tls_handshake_failed: return "tls_handshake_failed";
        case errc::tls_verify_failed: return "tls_verify_failed";
        case errc::tls_pinning_failed: return "tls_pinning_failed";
        case errc::smtp_invalid_state: return "smtp_invalid_state";
        case errc::smtp_bad_reply: return "smtp_bad_reply";
        case errc::smtp_auth_failed: return "smtp_auth_failed";
        case errc::smtp_service_not_available: return "smtp_service_not_available";
        case errc::smtp_mail_from_rejected: return "smtp_mail_from_rejected";
        case errc::smtp_rejected_recipient: return "smtp_rejected_recipient";
        case errc::smtp_data_rejected: return "smtp_data_rejected";
        case errc::smtp_temporary_failure: return "smtp_temporary_failure";
        case errc::smtp_permanent_failure: return "smtp_permanent_failure";
        case errc::pop3_invalid_state: return "pop3_invalid_state";
        case errc::pop3_negative_response: return "pop3_negative_response";
        case errc::pop3_auth_failed: return "pop3_auth_failed";
        case errc::imap_invalid_state: return "imap_invalid_state";
        case errc::imap_tagged_no: return "imap_tagged_no";
        case errc::imap_tagged_bad: return "imap_tagged_bad";
        case errc::imap_parse_error: return "imap_parse_error";
        case errc::imap_continuation_expected: return "imap_continuation_expected";
        case errc::pool_invalid_state: return "pool_invalid_state";
        case errc::pool_timeout: return "pool_timeout";
        case errc::pool_exhausted: return "pool_exhausted";
        case errc::pool_config_error: return "pool_config_error";
        case errc::codec_invalid_input: return "codec_invalid_input";
        case errc::mime_parse_error: return "mime_parse_error";
    }
    return "unknown";
}

inline std::ostream& operator<<(std::ostream& os, errc code)
{
    return os << to_string(code);
}

/// Rich error type with code, message, and optional details.
/// Conventions:
/// - message: stable summary suitable for logs/comparisons.
/// - detail: "key=value" multi-line, secrets must be redacted by callers.
struct error_info
{
    errc code{errc::ok};
    std::string message;
    std::string detail;
    std::error_code sys{};
    std::source_location where{};
};

[[nodiscard]] inline error_info make_error(
    errc c,
    std::string msg,
    std::string detail = {},
    std::error_code sys = {},
    std::source_location where = std::source_location::current())
{
    return error_info{c, std::move(msg), std::move(detail), sys, where};
}

[[nodiscard]] inline error_info make_error(
    errc c,
    std::string msg,
    detail::error_detail detail,
    std::error_code sys = {},
    std::source_location where = std::source_location::current())
{
    return error_info{c, std::move(msg), std::move(detail).str(), sys, where};
}

/// Result type alias using expected
namespace detail
{
template<class T>
using result = expected<T, error_info>;

using result_void = result<void>;
} // namespace detail

template<class T>
using result = detail::result<T>;

using result_void = detail::result_void;

/// Helper to create successful result
template<typename T>
[[nodiscard]] inline result<std::decay_t<T>> ok(T&& value)
{
    return result<std::decay_t<T>>(std::forward<T>(value));
}

/// Helper to create void success
[[nodiscard]] inline result_void ok()
{
    return result_void{};
}

/// Helper to create error result
template<typename T = void>
[[nodiscard]] inline result<T> fail(error_info err)
{
    return detail::make_unexpected(std::move(err));
}

[[nodiscard]] inline result<void> fail_void(error_info err)
{
    return fail<void>(std::move(err));
}

template<typename T = void>
[[nodiscard]] inline result<T> fail(
    errc c,
    std::string msg,
    std::string detail = {},
    std::error_code sys = {},
    std::source_location where = std::source_location::current())
{
    return detail::make_unexpected(error_info{c, std::move(msg), std::move(detail), sys, where});
}

template<typename T = void>
[[nodiscard]] inline result<T> fail(
    errc c,
    std::string msg,
    detail::error_detail detail,
    std::error_code sys = {},
    std::source_location where = std::source_location::current())
{
    return detail::make_unexpected(error_info{c, std::move(msg), std::move(detail).str(), sys, where});
}

[[nodiscard]] inline result<void> fail_void(
    errc c,
    std::string msg,
    std::string detail = {},
    std::error_code sys = {},
    std::source_location where = std::source_location::current())
{
    return fail<void>(c, std::move(msg), std::move(detail), sys, where);
}

[[nodiscard]] inline result<void> fail_void(
    errc c,
    std::string msg,
    detail::error_detail detail,
    std::error_code sys = {},
    std::source_location where = std::source_location::current())
{
    return fail<void>(c, std::move(msg), std::move(detail), sys, where);
}

// ==================== Monadic Helpers ====================

/// Pipe operator for fluent chaining: result | and_then(f) | transform(g)
template<typename T, typename F>
[[nodiscard]] constexpr auto operator|(detail::expected<T, error_info>&& r, F&& f)
    -> decltype(std::forward<F>(f)(std::move(r)))
{
    return std::forward<F>(f)(std::move(r));
}

template<typename T, typename F>
[[nodiscard]] constexpr auto operator|(const detail::expected<T, error_info>& r, F&& f)
    -> decltype(std::forward<F>(f)(r))
{
    return std::forward<F>(f)(r);
}

/// Functor wrapper for and_then (flatMap)
template<typename F>
[[nodiscard]] constexpr auto and_then(F&& f)
{
    return [f = std::forward<F>(f)]<typename T>(detail::expected<T, error_info>&& r) mutable {
        return std::move(r).and_then(std::move(f));
    };
}

/// Functor wrapper for transform (map)
template<typename F>
[[nodiscard]] constexpr auto transform(F&& f)
{
    return [f = std::forward<F>(f)]<typename T>(detail::expected<T, error_info>&& r) mutable {
        return detail::expected_transform(std::move(r), std::move(f));
    };
}

/// Functor wrapper for or_else (error handling)
template<typename F>
[[nodiscard]] constexpr auto or_else(F&& f)
{
    return [f = std::forward<F>(f)]<typename T>(detail::expected<T, error_info>&& r) mutable {
        return std::move(r).or_else(std::move(f));
    };
}

/// Functor wrapper for transform_error
template<typename F>
[[nodiscard]] constexpr auto transform_error(F&& f)
{
    return [f = std::forward<F>(f)]<typename T>(detail::expected<T, error_info>&& r) mutable {
        return detail::expected_transform_error(std::move(r), std::move(f));
    };
}

/// Inspect value without consuming (for logging/debugging)
template<typename F>
[[nodiscard]] constexpr auto inspect(F&& f)
{
    return [f = std::forward<F>(f)]<typename T>(detail::expected<T, error_info>&& r) mutable
        -> detail::expected<T, error_info>
    {
        if (r) f(*r);
        return std::move(r);
    };
}

/// Inspect error without consuming
template<typename F>
[[nodiscard]] constexpr auto inspect_error(F&& f)
{
    return [f = std::forward<F>(f)]<typename T>(detail::expected<T, error_info>&& r) mutable
        -> detail::expected<T, error_info>
    {
        if (!r) f(r.error());
        return std::move(r);
    };
}

/// Provide default value on error
template<typename T>
[[nodiscard]] constexpr auto value_or(T&& default_value)
{
    return [v = std::forward<T>(default_value)]<typename U>(detail::expected<U, error_info>&& r) mutable -> U {
        return std::move(r).value_or(std::move(v));
    };
}

/// Convert error to different type (useful for error aggregation)
template<typename F>
[[nodiscard]] constexpr auto map_error(F&& f)
{
    return transform_error(std::forward<F>(f));
}

// ==================== Propagation Helpers ====================

/// Propagate a result error and discard the value (use MAILXX_TRY_ASSIGN to keep it)
#define MAILXX_TRY(expr) \
    do { \
        auto&& _result = (expr); \
        if (!_result) [[unlikely]] \
            return ::mailxx::detail::make_unexpected(std::move(_result).error()); \
    } while (0)

/// Assign value from result and propagate errors
#define MAILXX_TRY_ASSIGN(lhs, expr) \
    do { \
        auto&& _result = (expr); \
        if (!_result) [[unlikely]] \
            return ::mailxx::detail::make_unexpected(std::move(_result).error()); \
        (lhs) = std::move(*_result); \
    } while (0)

/// Await a result-returning coroutine and propagate errors
#define MAILXX_TRY_CO_AWAIT(expr) \
    do { \
        auto&& _result = co_await (expr); \
        if (!_result) [[unlikely]] \
            co_return ::mailxx::detail::make_unexpected(std::move(_result).error()); \
    } while (0)

/// Assign value from result in coroutine and propagate errors
#define MAILXX_CO_TRY_ASSIGN(lhs, expr) \
    do { \
        auto&& _result = (expr); \
        if (!_result) [[unlikely]] \
            co_return ::mailxx::detail::make_unexpected(std::move(_result).error()); \
        (lhs) = std::move(*_result); \
    } while (0)

// ==================== Coroutine Helpers ====================

/// Await a result-returning coroutine and propagate errors
/// Usage: auto val = MAILXX_CO_TRY(co_await some_async_op());
#define MAILXX_CO_TRY(expr) \
    ({ \
        auto&& _result = (expr); \
        if (!_result) [[unlikely]] \
            co_return ::mailxx::detail::make_unexpected(std::move(_result).error()); \
        std::move(*_result); \
    })

/// Same but for void results
#define MAILXX_CO_TRY_VOID(expr) \
    do { \
        auto&& _result = (expr); \
        if (!_result) [[unlikely]] \
            co_return ::mailxx::detail::make_unexpected(std::move(_result).error()); \
    } while(0)

/// Collect multiple results into one (fails on first error)
template<typename... Ts>
[[nodiscard]] constexpr auto collect(detail::expected<Ts, error_info>&&... results)
    -> detail::expected<std::tuple<Ts...>, error_info>
{
    // Check for any errors first
    error_info first_error;
    bool has_error = false;

    auto check = [&](auto&& r) {
        if (!has_error && !r) {
            has_error = true;
            first_error = r.error();
        }
    };
    (check(results), ...);

    if (has_error)
        return detail::make_unexpected(std::move(first_error));

    return std::tuple<Ts...>{std::move(*results)...};
}

/// Sequence: execute operations in order, return last result
template<typename T, typename F>
[[nodiscard]] constexpr auto sequence(detail::expected<T, error_info>&& first, F&& next)
    -> decltype(next())
{
    if (!first)
        return decltype(next())(detail::make_unexpected(std::move(first).error()));
    return std::forward<F>(next)();
}

} // namespace mailxx

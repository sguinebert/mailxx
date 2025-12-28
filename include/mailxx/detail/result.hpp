/*

result.hpp
----------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

Error handling types using std::expected (C++23).
No exceptions are thrown in mailxx - all errors are returned via result<T>.

*/

#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <cstdint>
#include <format>

namespace mailxx
{

/// Error categories for mailxx operations
enum class error_code : std::uint16_t
{
    success = 0,
    
    // Network errors (100-199)
    connection_failed = 100,
    connection_closed = 101,
    connection_timeout = 102,
    dns_resolution_failed = 103,
    tls_handshake_failed = 104,
    tls_certificate_error = 105,
    socket_error = 106,
    
    // Protocol errors (200-299)
    invalid_response = 200,
    unexpected_response = 201,
    server_error = 202,
    parse_error = 203,
    invalid_state = 204,
    command_failed = 205,
    authentication_failed = 206,
    capability_not_supported = 207,
    
    // IMAP specific (300-399)
    imap_no_response = 300,
    imap_bad_response = 301,
    imap_mailbox_not_found = 302,
    imap_message_not_found = 303,
    imap_idle_timeout = 304,
    
    // SMTP specific (400-499)
    smtp_rejected = 400,
    smtp_sender_rejected = 401,
    smtp_recipient_rejected = 402,
    smtp_data_rejected = 403,
    smtp_relay_denied = 404,
    
    // POP3 specific (500-599)
    pop3_err_response = 500,
    pop3_message_not_found = 501,
    pop3_locked = 502,
    
    // MIME/Message errors (600-699)
    mime_parse_error = 600,
    mime_encoding_error = 601,
    mime_invalid_header = 602,
    mime_missing_boundary = 603,
    
    // Input validation (700-799)
    invalid_argument = 700,
    invalid_mailbox = 701,
    invalid_address = 702,
    message_too_large = 703,
    
    // Internal errors (900-999)
    internal_error = 900,
    not_implemented = 901,
    cancelled = 902,
};

/// Convert error code to string
[[nodiscard]] constexpr std::string_view error_code_to_string(error_code ec) noexcept
{
    switch (ec)
    {
        case error_code::success: return "Success";
        case error_code::connection_failed: return "Connection failed";
        case error_code::connection_closed: return "Connection closed";
        case error_code::connection_timeout: return "Connection timeout";
        case error_code::dns_resolution_failed: return "DNS resolution failed";
        case error_code::tls_handshake_failed: return "TLS handshake failed";
        case error_code::tls_certificate_error: return "TLS certificate error";
        case error_code::socket_error: return "Socket error";
        case error_code::invalid_response: return "Invalid response";
        case error_code::unexpected_response: return "Unexpected response";
        case error_code::server_error: return "Server error";
        case error_code::parse_error: return "Parse error";
        case error_code::invalid_state: return "Invalid state";
        case error_code::command_failed: return "Command failed";
        case error_code::authentication_failed: return "Authentication failed";
        case error_code::capability_not_supported: return "Capability not supported";
        case error_code::imap_no_response: return "IMAP NO response";
        case error_code::imap_bad_response: return "IMAP BAD response";
        case error_code::imap_mailbox_not_found: return "IMAP mailbox not found";
        case error_code::imap_message_not_found: return "IMAP message not found";
        case error_code::imap_idle_timeout: return "IMAP IDLE timeout";
        case error_code::smtp_rejected: return "SMTP rejected";
        case error_code::smtp_sender_rejected: return "SMTP sender rejected";
        case error_code::smtp_recipient_rejected: return "SMTP recipient rejected";
        case error_code::smtp_data_rejected: return "SMTP data rejected";
        case error_code::smtp_relay_denied: return "SMTP relay denied";
        case error_code::pop3_err_response: return "POP3 -ERR response";
        case error_code::pop3_message_not_found: return "POP3 message not found";
        case error_code::pop3_locked: return "POP3 mailbox locked";
        case error_code::mime_parse_error: return "MIME parse error";
        case error_code::mime_encoding_error: return "MIME encoding error";
        case error_code::mime_invalid_header: return "MIME invalid header";
        case error_code::mime_missing_boundary: return "MIME missing boundary";
        case error_code::invalid_argument: return "Invalid argument";
        case error_code::invalid_mailbox: return "Invalid mailbox";
        case error_code::invalid_address: return "Invalid address";
        case error_code::message_too_large: return "Message too large";
        case error_code::internal_error: return "Internal error";
        case error_code::not_implemented: return "Not implemented";
        case error_code::cancelled: return "Operation cancelled";
    }
    return "Unknown error";
}

/// Rich error type with code, message, and optional server response
class error
{
public:
    error() noexcept : code_(error_code::success) {}
    
    explicit error(error_code code) noexcept 
        : code_(code), message_(error_code_to_string(code)) {}
    
    error(error_code code, std::string message) noexcept
        : code_(code), message_(std::move(message)) {}
    
    error(error_code code, std::string message, std::string server_response) noexcept
        : code_(code), message_(std::move(message)), server_response_(std::move(server_response)) {}
    
    [[nodiscard]] error_code code() const noexcept { return code_; }
    [[nodiscard]] const std::string& message() const noexcept { return message_; }
    [[nodiscard]] const std::string& server_response() const noexcept { return server_response_; }
    
    [[nodiscard]] bool is_success() const noexcept { return code_ == error_code::success; }
    [[nodiscard]] explicit operator bool() const noexcept { return !is_success(); }
    
    /// Format error for display
    [[nodiscard]] std::string to_string() const
    {
        if (server_response_.empty())
            return std::format("[{}] {}", static_cast<int>(code_), message_);
        return std::format("[{}] {}: {}", static_cast<int>(code_), message_, server_response_);
    }
    
    /// Check if this is a specific error
    [[nodiscard]] bool is(error_code ec) const noexcept { return code_ == ec; }
    
    /// Check if this is a network error
    [[nodiscard]] bool is_network_error() const noexcept
    {
        auto c = static_cast<std::uint16_t>(code_);
        return c >= 100 && c < 200;
    }
    
    /// Check if this is a protocol error
    [[nodiscard]] bool is_protocol_error() const noexcept
    {
        auto c = static_cast<std::uint16_t>(code_);
        return c >= 200 && c < 700;
    }
    
private:
    error_code code_;
    std::string message_;
    std::string server_response_;
};

/// Result type alias using std::expected
template<typename T>
using result = std::expected<T, error>;

/// Void result for operations that don't return a value
using result_void = std::expected<void, error>;

/// Helper to create successful result
template<typename T>
[[nodiscard]] constexpr result<std::decay_t<T>> ok(T&& value)
{
    return result<std::decay_t<T>>(std::forward<T>(value));
}

/// Helper to create void success
[[nodiscard]] inline constexpr result_void ok()
{
    return result_void{};
}

/// Helper to create error result
template<typename T = void>
[[nodiscard]] constexpr std::expected<T, error> fail(error err)
{
    return std::unexpected(std::move(err));
}

template<typename T = void>
[[nodiscard]] constexpr std::expected<T, error> fail(error_code code)
{
    return std::unexpected(error(code));
}

template<typename T = void>
[[nodiscard]] constexpr std::expected<T, error> fail(error_code code, std::string message)
{
    return std::unexpected(error(code, std::move(message)));
}

template<typename T = void>
[[nodiscard]] constexpr std::expected<T, error> fail(error_code code, std::string message, std::string server_response)
{
    return std::unexpected(error(code, std::move(message), std::move(server_response)));
}

// ==================== Monadic Helpers ====================

/// Pipe operator for fluent chaining: result | and_then(f) | transform(g)
template<typename T, typename F>
[[nodiscard]] constexpr auto operator|(std::expected<T, error>&& r, F&& f)
    -> decltype(std::forward<F>(f)(std::move(r)))
{
    return std::forward<F>(f)(std::move(r));
}

template<typename T, typename F>
[[nodiscard]] constexpr auto operator|(const std::expected<T, error>& r, F&& f)
    -> decltype(std::forward<F>(f)(r))
{
    return std::forward<F>(f)(r);
}

/// Functor wrapper for and_then (flatMap)
template<typename F>
[[nodiscard]] constexpr auto and_then(F&& f)
{
    return [f = std::forward<F>(f)]<typename T>(std::expected<T, error>&& r) mutable {
        return std::move(r).and_then(std::move(f));
    };
}

/// Functor wrapper for transform (map)
template<typename F>
[[nodiscard]] constexpr auto transform(F&& f)
{
    return [f = std::forward<F>(f)]<typename T>(std::expected<T, error>&& r) mutable {
        return std::move(r).transform(std::move(f));
    };
}

/// Functor wrapper for or_else (error handling)
template<typename F>
[[nodiscard]] constexpr auto or_else(F&& f)
{
    return [f = std::forward<F>(f)]<typename T>(std::expected<T, error>&& r) mutable {
        return std::move(r).or_else(std::move(f));
    };
}

/// Functor wrapper for transform_error
template<typename F>
[[nodiscard]] constexpr auto transform_error(F&& f)
{
    return [f = std::forward<F>(f)]<typename T>(std::expected<T, error>&& r) mutable {
        return std::move(r).transform_error(std::move(f));
    };
}

/// Inspect value without consuming (for logging/debugging)
template<typename F>
[[nodiscard]] constexpr auto inspect(F&& f)
{
    return [f = std::forward<F>(f)]<typename T>(std::expected<T, error>&& r) mutable 
        -> std::expected<T, error> 
    {
        if (r) f(*r);
        return std::move(r);
    };
}

/// Inspect error without consuming
template<typename F>
[[nodiscard]] constexpr auto inspect_error(F&& f)
{
    return [f = std::forward<F>(f)]<typename T>(std::expected<T, error>&& r) mutable 
        -> std::expected<T, error> 
    {
        if (!r) f(r.error());
        return std::move(r);
    };
}

/// Provide default value on error
template<typename T>
[[nodiscard]] constexpr auto value_or(T&& default_value)
{
    return [v = std::forward<T>(default_value)]<typename U>(std::expected<U, error>&& r) mutable -> U {
        return std::move(r).value_or(std::move(v));
    };
}

/// Convert error to different type (useful for error aggregation)
template<typename F>
[[nodiscard]] constexpr auto map_error(F&& f)
{
    return transform_error(std::forward<F>(f));
}

// ==================== Coroutine Helpers ====================

/// Await a result-returning coroutine and propagate errors
/// Usage: auto val = MAILXX_CO_TRY(co_await some_async_op());
#define MAILXX_CO_TRY(expr) \
    ({ \
        auto&& _result = (expr); \
        if (!_result) [[unlikely]] \
            co_return std::unexpected(std::move(_result).error()); \
        std::move(*_result); \
    })

/// Same but for void results
#define MAILXX_CO_TRY_VOID(expr) \
    do { \
        auto&& _result = (expr); \
        if (!_result) [[unlikely]] \
            co_return std::unexpected(std::move(_result).error()); \
    } while(0)

/// Collect multiple results into one (fails on first error)
template<typename... Ts>
[[nodiscard]] constexpr auto collect(std::expected<Ts, error>&&... results)
    -> std::expected<std::tuple<Ts...>, error>
{
    // Check for any errors first
    error first_error;
    bool has_error = false;
    
    auto check = [&](auto&& r) {
        if (!has_error && !r) {
            has_error = true;
            first_error = r.error();
        }
    };
    (check(results), ...);
    
    if (has_error)
        return std::unexpected(std::move(first_error));
    
    return std::tuple<Ts...>{std::move(*results)...};
}

/// Sequence: execute operations in order, return last result
template<typename T, typename F>
[[nodiscard]] constexpr auto sequence(std::expected<T, error>&& first, F&& next)
{
    if (!first)
        return decltype(next())::unexpected(first.error());
    return std::forward<F>(next)();
}

} // namespace mailxx


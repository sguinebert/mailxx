/*

log.hpp
-------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

Lightweight, header-only logging infrastructure for mailxx.
Supports multiple log levels, optional callbacks, and protocol tracing.

*/

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <source_location>
#include <string>
#include <string_view>

namespace mailxx::log
{

/// Log severity levels
enum class level : std::uint8_t
{
    trace = 0,   ///< Protocol-level tracing (very verbose)
    debug = 1,   ///< Debug information
    info = 2,    ///< Informational messages
    warn = 3,    ///< Warnings (non-fatal issues)
    error = 4,   ///< Errors (operation failures)
    fatal = 5,   ///< Fatal errors (unrecoverable)
    off = 6      ///< Logging disabled
};

/// Direction for protocol tracing
enum class direction : std::uint8_t
{
    send,     ///< Data sent to server
    receive   ///< Data received from server
};

/// Log entry structure passed to callbacks
struct entry
{
    level lvl;
    std::chrono::system_clock::time_point timestamp;
    std::string message;
    std::source_location location;
    
    // Optional protocol trace info
    struct trace_info_t
    {
        direction dir;
        std::string protocol;  // "IMAP", "SMTP", "POP3"
        std::string data;      // Raw protocol data
    };
    std::optional<trace_info_t> trace_info;
};

/// Log callback signature
using callback_t = std::function<void(const entry&)>;

/// Convert level to string
[[nodiscard]] constexpr std::string_view level_to_string(level lvl) noexcept
{
    switch (lvl)
    {
        case level::trace: return "TRACE";
        case level::debug: return "DEBUG";
        case level::info:  return "INFO";
        case level::warn:  return "WARN";
        case level::error: return "ERROR";
        case level::fatal: return "FATAL";
        case level::off:   return "OFF";
    }
    return "UNKNOWN";
}

/// Global logger configuration (thread-safe singleton)
class logger
{
public:
    static logger& instance() noexcept
    {
        static logger inst;
        return inst;
    }
    
    /// Set minimum log level
    void set_level(level lvl) noexcept
    {
        min_level_.store(static_cast<std::uint8_t>(lvl), std::memory_order_relaxed);
    }
    
    /// Get current minimum log level
    [[nodiscard]] level get_level() const noexcept
    {
        return static_cast<level>(min_level_.load(std::memory_order_relaxed));
    }
    
    /// Check if level is enabled
    [[nodiscard]] bool is_enabled(level lvl) const noexcept
    {
        return static_cast<std::uint8_t>(lvl) >= min_level_.load(std::memory_order_relaxed);
    }
    
    /// Set custom log callback (replaces default stderr output)
    void set_callback(callback_t cb)
    {
        std::lock_guard lock(mutex_);
        callback_ = std::move(cb);
    }
    
    /// Clear custom callback (restore default stderr output)
    void clear_callback()
    {
        std::lock_guard lock(mutex_);
        callback_ = nullptr;
    }
    
    /// Enable/disable protocol tracing
    void set_trace_enabled(bool enabled) noexcept
    {
        trace_enabled_.store(enabled, std::memory_order_relaxed);
    }
    
    [[nodiscard]] bool is_trace_enabled() const noexcept
    {
        return trace_enabled_.load(std::memory_order_relaxed);
    }
    
    /// Log a message
    void log(level lvl, std::string_view message, 
             std::source_location loc = std::source_location::current())
    {
        if (!is_enabled(lvl))
            return;
        
        entry e{
            .lvl = lvl,
            .timestamp = std::chrono::system_clock::now(),
            .message = std::string(message),
            .location = loc,
            .trace_info = std::nullopt
        };
        
        dispatch(e);
    }
    
    /// Log protocol trace
    void trace_protocol(std::string_view protocol, direction dir, std::string_view data,
                       std::source_location loc = std::source_location::current())
    {
        if (!is_trace_enabled())
            return;
        
        entry e{
            .lvl = level::trace,
            .timestamp = std::chrono::system_clock::now(),
            .message = {},
            .location = loc,
            .trace_info = entry::trace_info_t{
                .dir = dir,
                .protocol = std::string(protocol),
                .data = std::string(data)
            }
        };
        
        dispatch(e);
    }
    
private:
    logger() = default;
    
    void dispatch(const entry& e)
    {
        std::lock_guard lock(mutex_);
        if (callback_)
        {
            callback_(e);
        }
        else
        {
            default_output(e);
        }
    }
    
    void default_output(const entry& e)
    {
        auto time = std::chrono::system_clock::to_time_t(e.timestamp);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            e.timestamp.time_since_epoch()) % 1000;
        
        std::tm tm_buf{};
#ifdef _WIN32
        localtime_s(&tm_buf, &time);
#else
        localtime_r(&time, &tm_buf);
#endif
        
        if (e.trace_info)
        {
            // Protocol trace format
            const char* dir_str = (e.trace_info->dir == direction::send) ? ">>>" : "<<<";
            std::cerr << std::format("[{:02}:{:02}:{:02}.{:03}] {} {} {}\n",
                tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, ms.count(),
                e.trace_info->protocol, dir_str, sanitize_trace(e.trace_info->data));
        }
        else
        {
            // Regular log format
            std::cerr << std::format("[{:02}:{:02}:{:02}.{:03}] [{}] {}\n",
                tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, ms.count(),
                level_to_string(e.lvl), e.message);
        }
    }
    
    /// Sanitize trace data (hide passwords, truncate long data)
    [[nodiscard]] static std::string sanitize_trace(std::string_view data)
    {
        std::string result(data);
        
        // Truncate very long data
        constexpr std::size_t max_len = 500;
        if (result.size() > max_len)
        {
            result.resize(max_len);
            result += "... [truncated]";
        }
        
        // Replace control characters (except CR/LF) with escape sequences
        for (std::size_t i = 0; i < result.size(); ++i)
        {
            char c = result[i];
            if (c < 32 && c != '\r' && c != '\n')
            {
                result[i] = '.';
            }
        }
        
        // Remove trailing CRLF for cleaner output
        while (!result.empty() && (result.back() == '\r' || result.back() == '\n'))
            result.pop_back();
        
        return result;
    }
    
    std::atomic<std::uint8_t> min_level_{static_cast<std::uint8_t>(level::info)};
    std::atomic<bool> trace_enabled_{false};
    std::mutex mutex_;
    callback_t callback_;
};

// Convenience macros for logging with source location
#define MAILXX_LOG(lvl, msg) \
    ::mailxx::log::logger::instance().log(lvl, msg, std::source_location::current())

#define MAILXX_TRACE(msg)  MAILXX_LOG(::mailxx::log::level::trace, msg)
#define MAILXX_DEBUG(msg)  MAILXX_LOG(::mailxx::log::level::debug, msg)
#define MAILXX_INFO(msg)   MAILXX_LOG(::mailxx::log::level::info, msg)
#define MAILXX_WARN(msg)   MAILXX_LOG(::mailxx::log::level::warn, msg)
#define MAILXX_ERROR(msg)  MAILXX_LOG(::mailxx::log::level::error, msg)
#define MAILXX_FATAL(msg)  MAILXX_LOG(::mailxx::log::level::fatal, msg)

/// Protocol trace helper
#define MAILXX_TRACE_SEND(protocol, data) \
    ::mailxx::log::logger::instance().trace_protocol(protocol, ::mailxx::log::direction::send, data)

#define MAILXX_TRACE_RECV(protocol, data) \
    ::mailxx::log::logger::instance().trace_protocol(protocol, ::mailxx::log::direction::receive, data)

// Inline helper functions (alternative to macros)
namespace detail
{
    inline void log_trace(std::string_view msg, std::source_location loc = std::source_location::current())
    { logger::instance().log(level::trace, msg, loc); }
    
    inline void log_debug(std::string_view msg, std::source_location loc = std::source_location::current())
    { logger::instance().log(level::debug, msg, loc); }
    
    inline void log_info(std::string_view msg, std::source_location loc = std::source_location::current())
    { logger::instance().log(level::info, msg, loc); }
    
    inline void log_warn(std::string_view msg, std::source_location loc = std::source_location::current())
    { logger::instance().log(level::warn, msg, loc); }
    
    inline void log_error(std::string_view msg, std::source_location loc = std::source_location::current())
    { logger::instance().log(level::error, msg, loc); }
    
    inline void log_fatal(std::string_view msg, std::source_location loc = std::source_location::current())
    { logger::instance().log(level::fatal, msg, loc); }
}

} // namespace mailxx::log

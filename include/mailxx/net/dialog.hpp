/*

dialog.hpp
----------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once

#include <string>
#include <string_view>
#include <stdexcept>
#include <memory>
#include <optional>
#include <chrono>
#include <atomic>
#include <utility>
#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/log.hpp>
#include <mailxx/detail/redact.hpp>

namespace mailxx
{
namespace net
{

// Import Asio types from the centralized declarations
using namespace mailxx::asio;

/// Default maximum line length for network protocols (RFC 5321: 998 + CRLF, but commonly 8K)
inline constexpr std::size_t DEFAULT_MAX_LINE_LENGTH = 8192;

/// Absolute maximum line length to prevent excessive memory allocation (1 MB)
inline constexpr std::size_t MAX_ALLOWED_LINE_LENGTH = 1024 * 1024;

class dialog_error : public std::runtime_error
{
public:
    dialog_error(const std::string& msg, const std::string& details) : std::runtime_error(msg), details_(details)
    {
    }

    dialog_error(const char* msg, const std::string& details) : std::runtime_error(msg), details_(details)
    {
    }

    std::string details() const { return details_; }

protected:
    std::string details_;
};

/**
Dealing with network in a line oriented fashion.
Wraps a Boost.Asio stream (socket, ssl stream, etc.).
**/
template<typename Stream>
class dialog
{
public:
    using duration = std::chrono::steady_clock::duration;

    dialog(Stream stream,
        std::size_t max_line_length = DEFAULT_MAX_LINE_LENGTH,
        std::optional<duration> timeout = std::nullopt)
        : stream_(std::move(stream)),
          max_line_length_(std::min(max_line_length, MAX_ALLOWED_LINE_LENGTH)),
          timeout_(timeout)
    {
    }

    ~dialog() = default;

    void set_trace_protocol(std::string protocol)
    {
        trace_protocol_ = std::move(protocol);
    }

    void set_trace_redaction(bool enabled) noexcept
    {
        redact_secrets_in_trace_ = enabled;
    }

    /**
    Sending a line to network asynchronously.

    @param line  Line to send (CRLF added if missing).
    @param token Completion token (callback, use_awaitable, etc.).
    **/
    template<typename CompletionToken>
    auto write_line(std::string_view line, CompletionToken&& token)
    {
        std::string payload = normalize_line(line);
        trace_line(mailxx::log::direction::send, payload);
        return async_with_timeout<void(asio::error_code, std::size_t)>(
            [this, payload = std::move(payload)](auto handler) mutable
            {
                asio::async_write(stream_, asio::buffer(payload), std::move(handler));
            }, std::forward<CompletionToken>(token));
    }

    /**
    Writing raw buffers to network asynchronously.

    @param buffers Buffers to write.
    @param token   Completion token.
    **/
    template<typename ConstBufferSequence, typename CompletionToken>
    auto write_raw(const ConstBufferSequence& buffers, CompletionToken&& token)
    {
        return async_with_timeout<void(asio::error_code, std::size_t)>(
            [this, buffers](auto handler) mutable
            {
                asio::async_write(stream_, buffers, std::move(handler));
            }, std::forward<CompletionToken>(token));
    }

    /**
    Receiving a line from network asynchronously.

    @param token Completion token.
    **/
    template<typename CompletionToken>
    auto read_line(CompletionToken&& token)
    {
        return asio::async_compose<CompletionToken, void(asio::error_code, std::string)>(
            [this, started = false](auto& self, asio::error_code ec = {}, std::size_t = 0) mutable
            {
                if (!started)
                {
                    started = true;
                    auto pos = read_buffer_.find('\n');
                    if (pos != std::string::npos)
                    {
                        std::size_t line_length = (pos > 0 && read_buffer_[pos - 1] == '\r') ? pos - 1 : pos;
                        if (line_length > max_line_length_)
                        {
                            self.complete(asio::error::message_size, std::string());
                            return;
                        }
                std::string line = read_buffer_.substr(0, line_length);
                read_buffer_.erase(0, pos + 1);
                trace_line(mailxx::log::direction::receive, line);
                self.complete(ec, std::move(line));
                return;
            }

                    std::size_t max_size = max_line_length_ + 2;
                    async_with_timeout<void(asio::error_code, std::size_t)>(
                        [this, max_size](auto handler) mutable
                        {
                            auto buffer = asio::dynamic_buffer(read_buffer_, max_size);
                            asio::async_read_until(stream_, buffer, '\n', std::move(handler));
                        }, std::move(self));
                    return;
                }

                if (ec)
                {
                    self.complete(ec, std::string());
                    return;
                }

                auto pos = read_buffer_.find('\n');
                if (pos == std::string::npos)
                {
                    self.complete(asio::error::invalid_argument, std::string());
                    return;
                }

                std::size_t line_length = (pos > 0 && read_buffer_[pos - 1] == '\r') ? pos - 1 : pos;
                if (line_length > max_line_length_)
                {
                    self.complete(asio::error::message_size, std::string());
                    return;
                }
                std::string line = read_buffer_.substr(0, line_length);
                read_buffer_.erase(0, pos + 1);
                trace_line(mailxx::log::direction::receive, line);
                self.complete(ec, std::move(line));
            }, token, stream_);
    }

    /**
    Receiving exactly N bytes from network asynchronously.

    @param n     Number of bytes to read.
    @param token Completion token.
    **/
    template<typename CompletionToken>
    auto read_exactly(std::size_t n, CompletionToken&& token)
    {
        return asio::async_compose<CompletionToken, void(asio::error_code, std::string)>(
            [this, n, started = false](auto& self, asio::error_code ec = {}, std::size_t = 0) mutable
            {
                if (!started)
                {
                    started = true;
                    if (n == 0)
                    {
                        self.complete(ec, std::string());
                        return;
                    }
                    if (read_buffer_.size() >= n)
                    {
                        std::string out(read_buffer_.data(), n);
                        read_buffer_.erase(0, n);
                        MAILXX_TRACE_RECV("NET", out);
                        self.complete(ec, std::move(out));
                        return;
                    }
                    std::size_t remaining = n - read_buffer_.size();
                    async_with_timeout<void(asio::error_code, std::size_t)>(
                        [this, remaining](auto handler) mutable
                        {
                            auto buffer = asio::dynamic_buffer(read_buffer_);
                            asio::async_read(stream_, buffer, asio::transfer_exactly(remaining), std::move(handler));
                        }, std::move(self));
                    return;
                }

                if (ec)
                {
                    self.complete(ec, std::string());
                    return;
                }
                if (read_buffer_.size() < n)
                {
                    self.complete(asio::error::operation_aborted, std::string());
                    return;
                }
                std::string out(read_buffer_.data(), n);
                read_buffer_.erase(0, n);
                MAILXX_TRACE_RECV("NET", out);
                self.complete(ec, std::move(out));
            }, token, stream_);
    }

    template<typename Signature, typename Initiation, typename CompletionToken>
    auto async_with_timeout(Initiation initiation, CompletionToken&& token)
    {
        if (timeout_.has_value())
            return async_with_timeout<Signature>(*timeout_, std::move(initiation), std::forward<CompletionToken>(token));

        return asio::async_compose<CompletionToken, Signature>(
            [initiation = std::move(initiation), started = false](auto& self, asio::error_code ec = {}, auto... results) mutable
            {
                if (!started)
                {
                    started = true;
                    initiation(std::move(self));
                    return;
                }
                self.complete(ec, std::move(results)...);
            }, token, stream_);
    }

    template<typename Signature, typename Initiation, typename CompletionToken>
    auto async_with_timeout(duration timeout, Initiation initiation, CompletionToken&& token)
    {
        struct timeout_state
        {
            std::atomic_bool timed_out{false};
        };

        return asio::async_compose<CompletionToken, Signature>(
            [this, initiation = std::move(initiation), timeout,
                state = std::make_shared<timeout_state>(),
                timer = std::shared_ptr<asio::steady_timer>(),
                started = false](auto& self, asio::error_code ec = {}, auto... results) mutable
            {
                if (!started)
                {
                    started = true;
                    timer = std::make_shared<asio::steady_timer>(stream_.get_executor());
                    timer->expires_after(timeout);
                    timer->async_wait([this, state](asio::error_code timer_ec)
                    {
                        if (timer_ec)
                            return;
                        state->timed_out.store(true);
                        asio::error_code ignore_ec;
                        asio::get_lowest_layer(stream_).cancel(ignore_ec);
                    });
                    initiation(std::move(self));
                    return;
                }
                if (timer)
                    timer->cancel();
                if (state->timed_out.load() && ec == asio::error::operation_aborted)
                    ec = asio::error::timed_out;
                self.complete(ec, std::move(results)...);
            }, token, stream_);
    }

    [[nodiscard]] Stream& stream() noexcept { return stream_; }
    [[nodiscard]] const Stream& stream() const noexcept { return stream_; }

    void max_line_length(std::size_t value) noexcept { max_line_length_ = std::min(value, MAX_ALLOWED_LINE_LENGTH); }
    [[nodiscard]] std::size_t max_line_length() const noexcept { return max_line_length_; }

    void timeout(std::optional<duration> value) noexcept { timeout_ = value; }
    [[nodiscard]] std::optional<duration> timeout() const noexcept { return timeout_; }

protected:
    static std::string normalize_line(std::string_view line)
    {
        if (line.size() >= 2 && line.substr(line.size() - 2) == "\r\n")
            return std::string(line);
        if (!line.empty() && line.back() == '\n')
        {
            std::string out(line.substr(0, line.size() - 1));
            out += "\r\n";
            return out;
        }
        if (!line.empty() && line.back() == '\r')
        {
            std::string out(line);
            out += "\n";
            return out;
        }
        std::string out(line);
        out += "\r\n";
        return out;
    }

    Stream stream_;
    std::string read_buffer_;
    std::size_t max_line_length_;
    std::optional<duration> timeout_;

    std::string trace_protocol_{"NET"};
    bool redact_secrets_in_trace_{true};

    void trace_line(mailxx::log::direction dir, std::string_view data) const
    {
        auto& logger = mailxx::log::logger::instance();
        if (!logger.is_trace_enabled())
            return;
        if (dir == mailxx::log::direction::send && redact_secrets_in_trace_)
        {
            logger.trace_protocol(trace_protocol_, dir, mailxx::detail::redact_line(data));
            return;
        }
        logger.trace_protocol(trace_protocol_, dir, data);
    }
};

} // namespace net
} // namespace mailxx

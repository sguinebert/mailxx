/*

dialog.hpp
----------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/


#pragma once

#include <string>
#include <string_view>
#include <array>
#include <concepts>
#include <memory>
#include <optional>
#include <chrono>
#include <atomic>
#include <utility>
#include <new>
#include <type_traits>
#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/result.hpp>
#include <mailxx/detail/log.hpp>
#include <mailxx/detail/redact.hpp>
#include <mailxx/net/error_mapping.hpp>

namespace mailxx
{
namespace net
{

namespace detail
{
template<typename>
struct signature_arity;

template<typename R, typename... Args>
struct signature_arity<R(Args...)> : std::integral_constant<std::size_t, sizeof...(Args)>
{
};

template<typename Buffer>
concept buffer_view = requires(Buffer&& buffer)
{
    { mailxx::asio::buffer(std::forward<Buffer>(buffer)) };
    { mailxx::asio::const_buffer(mailxx::asio::buffer(std::forward<Buffer>(buffer))) };
};

template<typename Owner>
concept buffer_owner = std::movable<std::remove_reference_t<Owner>>;

template<typename Buffer>
concept borrowed_buffer_view =
    buffer_view<Buffer> && std::is_lvalue_reference_v<Buffer&&>;

template<typename Owner>
concept movable_buffer_owner =
    buffer_view<std::remove_reference_t<Owner>&> &&
    buffer_owner<Owner> &&
    (!std::is_lvalue_reference_v<Owner&&>);

template<typename Line>
concept line_view = std::convertible_to<Line, std::string_view>;

template<typename Line>
concept borrowed_line_view =
    line_view<Line> && std::is_lvalue_reference_v<Line&&>;

template<typename Line>
concept static_line_literal =
    std::is_array_v<std::remove_reference_t<Line>> &&
    std::same_as<std::remove_extent_t<std::remove_reference_t<Line>>, const char> &&
    std::is_lvalue_reference_v<Line&&>;

template<typename Line>
concept line_input =
    borrowed_line_view<Line> || static_line_literal<Line>;
} // namespace detail

// Import Asio types from the centralized declarations
using namespace mailxx::asio;

namespace detail
{
template<typename ErrorEnum>
[[nodiscard]] inline asio::error_code make_err(ErrorEnum e) noexcept
{
    return asio::error::make_error_code(e);
}

template<typename ErrorEnum>
[[nodiscard]] inline bool is_err(const asio::error_code& ec, ErrorEnum e) noexcept
{
    return ec == make_err(e);
}
} // namespace detail

/// Default maximum line length for network protocols (RFC 5321: 998 + CRLF, but commonly 8K)
inline constexpr std::size_t DEFAULT_MAX_LINE_LENGTH = 8192;

/// Absolute maximum line length to prevent excessive memory allocation (1 MB)
inline constexpr std::size_t MAX_ALLOWED_LINE_LENGTH = 1024 * 1024;

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

    dialog(const dialog&) = delete;
    dialog& operator=(const dialog&) = delete;
    dialog(dialog&&) noexcept(std::is_nothrow_move_constructible_v<Stream>) = default;
    dialog& operator=(dialog&& other) noexcept(std::is_nothrow_move_constructible_v<Stream>)
    {
        if (this != &other)
        {
            // Rebuild to avoid requiring Stream move assignment.
            this->~dialog();
            new (this) dialog(std::move(other));
        }
        return *this;
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

    void set_peer(std::string_view host, std::string_view service)
    {
        peer_host_.assign(host.begin(), host.end());
        peer_service_.assign(service.begin(), service.end());
    }

    /**
    Sending a borrowed line view to the network asynchronously.

    Borrowed-view path: the caller keeps ownership and must guarantee that the
    view stays alive until completion. The API accepts a logical command line
    and adds the trailing CRLF framing without mutating or copying the line.

    Example:
        std::string line = "EHLO localhost";
        std::string_view view(line);
        co_await dlg.write_line_view_r(view);
    **/
    template<detail::line_input Line, typename CompletionToken>
    auto write_line_view(Line&& line, CompletionToken&& token)
    {
        const std::string_view view(line);
        const auto framing = classify_line_framing(view);
        if (framing == line_framing::invalid)
            return fail_write_operation(detail::make_err(asio::error::invalid_argument),
                std::forward<CompletionToken>(token));

        trace_line(mailxx::log::direction::send, view);
        return write_line_sequence(view, framing == line_framing::append_crlf,
            nullptr, std::forward<CompletionToken>(token));
    }

    /**
    Sending a borrowed line view with an explicit external owner.

    Advanced path: the caller supplies a CRLF-normalized line view together with
    a separate owner object whose lifetime is transferred to the async
    operation.

    Example:
        auto owner = std::make_shared<std::string>("EHLO localhost");
        std::string_view view(*owner);
        co_await dlg.write_line_buffer_r(view, std::move(owner));
    **/
    template<detail::line_input Line, typename Owner, typename CompletionToken>
        requires(detail::buffer_owner<Owner> && !std::is_lvalue_reference_v<Owner&&>)
    auto write_line_buffer(Line&& line, Owner&& owner, CompletionToken&& token)
    {
        const std::string_view view(line);
        const auto framing = classify_line_framing(view);
        if (framing == line_framing::invalid)
            return fail_write_operation(detail::make_err(asio::error::invalid_argument),
                std::forward<CompletionToken>(token));

        trace_line(mailxx::log::direction::send, view);
        return write_line_sequence(view, framing == line_framing::append_crlf,
            std::forward<Owner>(owner), std::forward<CompletionToken>(token));
    }

    template<detail::line_input Line>
    [[nodiscard]] awaitable<mailxx::result<void>> write_line_view_r(Line&& line)
    {
        auto [ec, bytes] = co_await write_line_view(std::forward<Line>(line), use_nothrow_awaitable);
        (void)bytes;
        const bool timeout_triggered = detail::is_err(ec, asio::error::timed_out);
        if (ec)
        {
            const errc code = map_net_error(io_stage::write, ec, timeout_triggered);
            auto detail = make_net_detail(trace_protocol_, peer_host_, peer_service_, io_stage::write, "write_line_view");
            detail.add("sys", format_sys(ec));
            co_return mailxx::fail<void>(code, "net write failed", std::move(detail), ec);
        }
        co_return mailxx::ok();
    }

    template<detail::line_input Line, typename Owner>
        requires(detail::buffer_owner<Owner> && !std::is_lvalue_reference_v<Owner&&>)
    [[nodiscard]] awaitable<mailxx::result<void>> write_line_buffer_r(Line&& line, Owner&& owner)
    {
        auto [ec, bytes] = co_await write_line_buffer(std::forward<Line>(line),
            std::forward<Owner>(owner), use_nothrow_awaitable);
        (void)bytes;
        const bool timeout_triggered = detail::is_err(ec, asio::error::timed_out);
        if (ec)
        {
            const errc code = map_net_error(io_stage::write, ec, timeout_triggered);
            auto detail = make_net_detail(trace_protocol_, peer_host_, peer_service_, io_stage::write, "write_line_buffer");
            detail.add("sys", format_sys(ec));
            co_return mailxx::fail<void>(code, "net write failed", std::move(detail), ec);
        }
        co_return mailxx::ok();
    }

    /**
    Writing an owned buffer to the network asynchronously.

    Moved-owner path: the caller transfers ownership of the container to the
    async operation. The framework keeps that owner alive until completion, so
    no extra byte copy is performed.

    Example:
        std::string payload = build_payload();
        co_await dlg.write_raw_r(std::move(payload));
    **/
    template<detail::movable_buffer_owner Owner, typename CompletionToken>
    auto write_raw(Owner&& owner, CompletionToken&& token)
    {
        return write_owned_buffer(std::forward<Owner>(owner), std::forward<CompletionToken>(token));
    }

    /**
    Writing a raw buffer view to the network asynchronously.

    Borrowed-view path: the caller is responsible for keeping the referenced
    memory alive until the completion handler runs.

    Example:
        std::string payload = build_payload();
        std::string_view chunk(payload.data(), payload.size());
        co_await dlg.write_raw_view_r(chunk);
    **/
    template<detail::borrowed_buffer_view Buffer, typename CompletionToken>
    auto write_raw_view(Buffer&& view, CompletionToken&& token)
    {
        return write_buffer_owned(asio::const_buffer(asio::buffer(view)),
            nullptr, std::forward<CompletionToken>(token));
    }

    /**
    Writing a raw buffer view with an explicit external owner.

    Advanced path: the caller supplies both the view and a separate owner object
    whose lifetime must be transferred to the async operation.

    Example:
        auto owner = std::make_shared<std::string>(build_payload());
        std::string_view chunk(owner->data(), owner->size());
        co_await dlg.write_raw_buffer_r(chunk, std::move(owner));
    **/
    template<detail::borrowed_buffer_view Buffer, typename Owner, typename CompletionToken>
        requires(detail::buffer_owner<Owner> && !std::is_lvalue_reference_v<Owner&&>)
    auto write_raw_buffer(Buffer&& view, Owner&& owner, CompletionToken&& token)
    {
        return write_buffer_owned(asio::const_buffer(asio::buffer(view)),
            std::forward<Owner>(owner), std::forward<CompletionToken>(token));
    }

    template<detail::movable_buffer_owner Owner>
    [[nodiscard]] awaitable<mailxx::result<void>> write_raw_r(Owner&& owner)
    {
        auto [ec, bytes] = co_await write_raw(std::forward<Owner>(owner), use_nothrow_awaitable);
        (void)bytes;
        const bool timeout_triggered = detail::is_err(ec, asio::error::timed_out);
        if (ec)
        {
            const errc code = map_net_error(io_stage::write, ec, timeout_triggered);
            auto detail = make_net_detail(trace_protocol_, peer_host_, peer_service_, io_stage::write, "write_raw");
            detail.add("sys", format_sys(ec));
            co_return mailxx::fail<void>(code, "net write failed", std::move(detail), ec);
        }
        co_return mailxx::ok();
    }

    template<detail::borrowed_buffer_view Buffer>
    [[nodiscard]] awaitable<mailxx::result<void>> write_raw_view_r(Buffer&& view)
    {
        auto [ec, bytes] = co_await write_raw_view(std::forward<Buffer>(view), use_nothrow_awaitable);
        (void)bytes;
        const bool timeout_triggered = detail::is_err(ec, asio::error::timed_out);
        if (ec)
        {
            const errc code = map_net_error(io_stage::write, ec, timeout_triggered);
            auto detail = make_net_detail(trace_protocol_, peer_host_, peer_service_, io_stage::write, "write_raw_view");
            detail.add("sys", format_sys(ec));
            co_return mailxx::fail<void>(code, "net write failed", std::move(detail), ec);
        }
        co_return mailxx::ok();
    }

    template<detail::borrowed_buffer_view Buffer, typename Owner>
        requires(detail::buffer_owner<Owner> && !std::is_lvalue_reference_v<Owner&&>)
    [[nodiscard]] awaitable<mailxx::result<void>> write_raw_buffer_r(Buffer&& view, Owner&& owner)
    {
        auto [ec, bytes] = co_await write_raw_buffer(std::forward<Buffer>(view),
            std::forward<Owner>(owner), use_nothrow_awaitable);
        (void)bytes;
        const bool timeout_triggered = detail::is_err(ec, asio::error::timed_out);
        if (ec)
        {
            const errc code = map_net_error(io_stage::write, ec, timeout_triggered);
            auto detail = make_net_detail(trace_protocol_, peer_host_, peer_service_, io_stage::write, "write_raw_buffer");
            detail.add("sys", format_sys(ec));
            co_return mailxx::fail<void>(code, "net write failed", std::move(detail), ec);
        }
        co_return mailxx::ok();
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
                            self.complete(detail::make_err(asio::error::message_size), std::string());
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
                    self.complete(detail::make_err(asio::error::invalid_argument), std::string());
                    return;
                }

                std::size_t line_length = (pos > 0 && read_buffer_[pos - 1] == '\r') ? pos - 1 : pos;
                if (line_length > max_line_length_)
                {
                    self.complete(detail::make_err(asio::error::message_size), std::string());
                    return;
                }
                std::string line = read_buffer_.substr(0, line_length);
                read_buffer_.erase(0, pos + 1);
                trace_line(mailxx::log::direction::receive, line);
                self.complete(ec, std::move(line));
            }, token, stream_);
    }

    [[nodiscard]] awaitable<mailxx::result<std::string>> read_line_r()
    {
        auto [ec, line] = co_await read_line(use_nothrow_awaitable);
        const bool timeout_triggered = detail::is_err(ec, asio::error::timed_out);
        if (ec)
        {
            const errc code = map_net_error(io_stage::read, ec, timeout_triggered);
            auto detail = make_net_detail(trace_protocol_, peer_host_, peer_service_, io_stage::read, "read_line");
            detail.add("sys", format_sys(ec));
            co_return mailxx::fail<std::string>(code, "net read failed", std::move(detail), ec);
        }
        co_return mailxx::ok(std::move(line));
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
                    self.complete(detail::make_err(asio::error::operation_aborted), std::string());
                    return;
                }
                std::string out(read_buffer_.data(), n);
                read_buffer_.erase(0, n);
                MAILXX_TRACE_RECV("NET", out);
                self.complete(ec, std::move(out));
            }, token, stream_);
    }

    [[nodiscard]] awaitable<mailxx::result<std::string>> read_exactly_r(std::size_t n)
    {
        auto [ec, out] = co_await read_exactly(n, use_nothrow_awaitable);
        const bool timeout_triggered = detail::is_err(ec, asio::error::timed_out);
        if (ec)
        {
            const errc code = map_net_error(io_stage::read, ec, timeout_triggered);
            auto detail = make_net_detail(trace_protocol_, peer_host_, peer_service_, io_stage::read, "read_exactly");
            detail.add("sys", format_sys(ec));
            co_return mailxx::fail<std::string>(code, "net read failed", std::move(detail), ec);
        }
        co_return mailxx::ok(std::move(out));
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
                if constexpr (sizeof...(results) + 1 == detail::signature_arity<Signature>::value)
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
                if (state->timed_out.load() && detail::is_err(ec, asio::error::operation_aborted))
                    ec = detail::make_err(asio::error::timed_out);
                if constexpr (sizeof...(results) + 1 == detail::signature_arity<Signature>::value)
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
    template<typename CompletionToken>
    auto fail_write_operation(asio::error_code ec, CompletionToken&& token)
    {
        return asio::async_compose<CompletionToken, void(asio::error_code, std::size_t)>(
            [ec](auto& self) mutable
            {
                self.complete(ec, 0);
            }, std::forward<CompletionToken>(token), stream_);
    }

    template<detail::buffer_owner Owner, typename CompletionToken>
    auto write_owned_buffer(Owner&& owner, CompletionToken&& token)
    {
        using owner_type = std::decay_t<Owner>;
        return asio::async_compose<CompletionToken, void(asio::error_code, std::size_t)>(
            [this, owner = owner_type(std::forward<Owner>(owner)), offset = std::size_t{0}, started = false](
                auto& self, asio::error_code ec = {}, std::size_t bytes = 0) mutable
            {
                const asio::const_buffer full_buffer(asio::buffer(owner));
                if (!started)
                {
                    started = true;
                }
                else if (ec)
                {
                    self.complete(ec, offset);
                    return;
                }
                else
                {
                    if (bytes == 0 && offset < full_buffer.size())
                    {
                        self.complete(detail::make_err(asio::error::eof), offset);
                        return;
                    }

                    offset += bytes;
                    if (offset >= full_buffer.size())
                    {
                        self.complete(ec, offset);
                        return;
                    }
                }

                const asio::const_buffer remaining = full_buffer + offset;
                async_with_timeout<void(asio::error_code, std::size_t)>(
                    [this, remaining](auto handler) mutable
                    {
                        stream_.async_write_some(remaining, std::move(handler));
                    },
                    std::move(self));
            }, std::forward<CompletionToken>(token), stream_);
    }

    template<std::size_t N, detail::buffer_owner Owner, typename CompletionToken>
    auto write_buffer_sequence_owned(std::array<asio::const_buffer, N> buffers, Owner&& owner, CompletionToken&& token)
    {
        using owner_type = std::decay_t<Owner>;
        return asio::async_compose<CompletionToken, void(asio::error_code, std::size_t)>(
            [this, buffers = std::move(buffers), owner = owner_type(std::forward<Owner>(owner)),
                index = std::size_t{0}, offset = std::size_t{0}, total = std::size_t{0}, started = false](
                auto& self, asio::error_code ec = {}, std::size_t bytes = 0) mutable
            {
                auto advance_to_next_non_empty = [&]() mutable
                {
                    while (index < N)
                    {
                        const asio::const_buffer current = buffers[index];
                        if (offset < current.size())
                            return;
                        ++index;
                        offset = 0;
                    }
                };

                if (!started)
                {
                    started = true;
                    advance_to_next_non_empty();
                    if (index >= N)
                    {
                        self.complete(ec, total);
                        return;
                    }
                }
                else if (ec)
                {
                    self.complete(ec, total);
                    return;
                }
                else
                {
                    const asio::const_buffer current = buffers[index];
                    if (bytes == 0 && offset < current.size())
                    {
                        self.complete(detail::make_err(asio::error::eof), total);
                        return;
                    }

                    total += bytes;
                    offset += bytes;
                    advance_to_next_non_empty();
                    if (index >= N)
                    {
                        self.complete(ec, total);
                        return;
                    }
                }

                const asio::const_buffer current = buffers[index] + offset;
                async_with_timeout<void(asio::error_code, std::size_t)>(
                    [this, current](auto handler) mutable
                    {
                        stream_.async_write_some(current, std::move(handler));
                    },
                    std::move(self));
            }, std::forward<CompletionToken>(token), stream_);
    }

    template<detail::buffer_owner Owner, typename CompletionToken>
    auto write_buffer_owned(asio::const_buffer buffer, Owner&& owner, CompletionToken&& token)
    {
        using owner_type = std::decay_t<Owner>;
        return asio::async_compose<CompletionToken, void(asio::error_code, std::size_t)>(
            [this, remaining = buffer, owner = owner_type(std::forward<Owner>(owner)), total = std::size_t{0}, started = false](
                auto& self, asio::error_code ec = {}, std::size_t bytes = 0) mutable
            {
                if (!started)
                {
                    started = true;
                }
                else if (ec)
                {
                    self.complete(ec, total);
                    return;
                }
                else
                {
                    if (bytes == 0 && remaining.size() != 0)
                    {
                        self.complete(detail::make_err(asio::error::eof), total);
                        return;
                    }

                    total += bytes;
                    remaining = remaining + bytes;
                    if (remaining.size() == 0)
                    {
                        self.complete(ec, total);
                        return;
                    }
                }

                async_with_timeout<void(asio::error_code, std::size_t)>(
                    [this, remaining](auto handler) mutable
                    {
                        stream_.async_write_some(remaining, std::move(handler));
                    },
                    std::move(self));
            }, std::forward<CompletionToken>(token), stream_);
    }

    enum class line_framing
    {
        as_is,
        append_crlf,
        invalid
    };

    [[nodiscard]] static line_framing classify_line_framing(std::string_view line) noexcept
    {
        if (line.size() >= 2 && line.substr(line.size() - 2) == "\r\n")
        {
            const auto body = line.substr(0, line.size() - 2);
            return (body.find('\r') == std::string_view::npos && body.find('\n') == std::string_view::npos)
                ? line_framing::as_is
                : line_framing::invalid;
        }
        if (line.find('\r') != std::string_view::npos || line.find('\n') != std::string_view::npos)
            return line_framing::invalid;
        return line_framing::append_crlf;
    }

    template<detail::buffer_owner Owner, typename CompletionToken>
    auto write_line_sequence(std::string_view line, bool append_crlf, Owner&& owner, CompletionToken&& token)
    {
        std::array<asio::const_buffer, 2> buffers{
            asio::const_buffer(line.data(), line.size()),
            append_crlf ? asio::const_buffer(k_crlf, 2) : asio::const_buffer()
        };
        return write_buffer_sequence_owned(std::move(buffers), std::forward<Owner>(owner),
            std::forward<CompletionToken>(token));
    }

    Stream stream_;
    std::string read_buffer_;
    std::size_t max_line_length_;
    std::optional<duration> timeout_;

    std::string peer_host_;
    std::string peer_service_;
    std::string trace_protocol_{"NET"};
    bool redact_secrets_in_trace_{true};
    inline static constexpr char k_crlf[3] = "\r\n";

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

    [[nodiscard]] static std::string format_sys(const asio::error_code& ec)
    {
        std::string sys = ec.message();
        if (!sys.empty())
        {
            sys += " (";
            sys += std::to_string(ec.value());
            sys += ")";
        }
        else
        {
            sys = std::to_string(ec.value());
        }
        return sys;
    }

    [[nodiscard]] error_info make_net_error(
        const asio::error_code& ec,
        std::source_location where = std::source_location::current()) const
    {
        const bool timeout_triggered = detail::is_err(ec, asio::error::timed_out);
        const errc code = map_net_error(io_stage::read, ec, timeout_triggered);
        auto detail = make_net_detail(trace_protocol_, peer_host_, peer_service_, io_stage::read, "generic");
        detail.add("sys", format_sys(ec));
        return mailxx::make_error(code, std::string(mailxx::to_string(code)), std::move(detail), ec, where);
    }
};

} // namespace net
} // namespace mailxx

/*

smtp/client.hpp
---------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <unordered_set>
#include <utility>
#include <optional>
#include <cctype>
#include <charconv>
#include <system_error>
#include <array>
#include <queue>
#include <thread>
#include <condition_variable>
#include <mutex>

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/log.hpp>
#include <mailxx/detail/oauth2_retry.hpp>
#include <mailxx/detail/output_sink.hpp>
#include <mailxx/detail/result.hpp>

#include <mailxx/net/dialog.hpp>
#include <mailxx/net/error_mapping.hpp>
#include <mailxx/net/tls_mode.hpp>
#include <mailxx/net/upgradable_stream.hpp>
#include <mailxx/mime/message.hpp>
#include <mailxx/mime/mailboxes.hpp>
#include <mailxx/codec/base64.hpp>
#include <mailxx/codec/codec.hpp>
#include <mailxx/detail/append.hpp>
#include <mailxx/detail/async_mutex.hpp>
#include <mailxx/detail/error_detail.hpp>
#include <mailxx/detail/sasl.hpp>
#include <mailxx/detail/sanitize.hpp>
#include <mailxx/detail/redact.hpp>
#include <mailxx/detail/reconnection.hpp>
#include <mailxx/oauth2/token_source.hpp>
#include <mailxx/smtp/types.hpp>
#include <mailxx/smtp/error_mapping.hpp>
#include <mailxx/smtp/error_mapping.hpp>

namespace mailxx::smtp
{

using namespace mailxx::asio;

/// Reconnection policy alias for SMTP
using reconnection_policy = mailxx::detail::reconnection_policy;

class client
{
public:
    using executor_type = any_io_executor;
    using tcp_type = tcp;

    explicit client(executor_type executor, options opts = {})
        : executor_(executor),
          options_(std::move(opts)),
          mutex_(executor_)
    {
    }

    explicit client(io_context& context, options opts = {})
        : client(context.get_executor(), std::move(opts))
    {
    }

    executor_type get_executor() const { return executor_; }

    awaitable<mailxx::result<void>> connect(const std::string& host, unsigned short port)
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await connect_impl(host, std::to_string(port), mailxx::net::tls_mode::none, nullptr, {});
    }

    awaitable<mailxx::result<void>> connect(const std::string& host, const std::string& service)
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await connect_impl(host, service, mailxx::net::tls_mode::none, nullptr, {});
    }

    awaitable<mailxx::result<void>> connect(const std::string& host, unsigned short port, mailxx::net::tls_mode mode,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await connect_impl(host, std::to_string(port), mode, tls_ctx, std::move(sni));
    }

    /**
     * Connect with explicit TLS mode.
     * If options.auto_starttls is enabled, performs greeting -> EHLO -> STARTTLS -> EHLO.
     */
    awaitable<mailxx::result<void>> connect(const std::string& host, const std::string& service, mailxx::net::tls_mode mode,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await connect_impl(host, service, mode, tls_ctx, std::move(sni));
    }

    awaitable<mailxx::result<void>> read_greeting()
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await read_greeting_impl();
    }

    awaitable<mailxx::result<void>> ehlo(std::string domain = {})
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await ehlo_impl(std::move(domain));
    }

    /**
     * Upgrade the connection using STARTTLS.
     * After STARTTLS, EHLO must be issued again to refresh capabilities.
     */
    awaitable<mailxx::result<void>> start_tls(ssl::context& context, std::string sni = {})
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await start_tls_impl(context, std::move(sni));
    }

    awaitable<mailxx::result<void>> authenticate(const std::string& username, const std::string& password, auth_method method)
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await authenticate_impl(username, password, method);
    }

    /**
     * Authenticate using OAuth2 access token.
     * Use this with Gmail, Outlook, and other OAuth2 providers.
     * 
     * @param username The email address
     * @param access_token The OAuth2 access token (not refresh token)
     */
    awaitable<mailxx::result<void>> authenticate_oauth2(const std::string& username, const std::string& access_token)
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await authenticate_impl(username, access_token, auth_method::xoauth2);
    }

    awaitable<mailxx::result<void>> authenticate_oauth2(
        const std::string& username,
        mailxx::oauth2::token_source& source)
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        auto auth = [&](const std::string& token) -> awaitable<mailxx::result<void>>
        {
            co_return co_await authenticate_impl(username, token, auth_method::xoauth2);
        };
        auto should_retry = [](const error_info& err)
        {
            return err.code == errc::smtp_auth_failed;
        };
        co_return co_await mailxx::detail::oauth2_auth_with_retry(source, auth, should_retry);
    }

    awaitable<mailxx::result<reply>> send(const mailxx::message& msg, const envelope& env = envelope{})
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await send_impl(msg, env);
    }

    /**
     * Send message with DSN (Delivery Status Notification) support.
     * Requires server to advertise DSN capability.
     * 
     * @param msg The message to send
     * @param env Extended envelope with DSN options
     * @return Result containing server reply or error
     */
    awaitable<mailxx::result<reply>> send(const mailxx::message& msg, const envelope_dsn& env)
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await send_dsn_impl(msg, env);
    }

    /**
     * Send message without buffering the full DATA payload in memory.
     */
    awaitable<mailxx::result<reply>> send_streaming(const envelope& env, const mailxx::message& msg)
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await send_streaming_impl(env, msg);
    }

    /**
     * Check if server supports DSN (RFC 3461).
     */
    bool supports_dsn() const
    {
        return capabilities_known_ && capabilities_.supports("DSN");
    }

    // ==================== SMTP Extensions ====================

    /**
     * Check if server supports SIZE extension (RFC 1870).
     */
    bool supports_size() const
    {
        return capabilities_known_ && capabilities_.supports("SIZE");
    }

    /**
     * Get server's maximum message size from SIZE extension.
     * @return Size limit (max_size = 0 if unlimited or not supported)
     */
    size_limit get_size_limit() const
    {
        if (!capabilities_known_)
            return {};
        
        const auto* params = capabilities_.parameters("SIZE");
        if (!params || params->empty())
            return {};
        
        const std::string& param = params->front();
        std::size_t value = 0;
        const char* begin = param.data();
        const char* end = begin + param.size();
        auto [ptr, ec] = std::from_chars(begin, end, value);
        if (ec != std::errc{} || ptr != end)
            return {};
        return {value};
    }

    /**
     * Check if server supports 8BITMIME extension (RFC 6152).
     * When supported, 8-bit content can be sent without Base64 encoding.
     */
    bool supports_8bitmime() const
    {
        return capabilities_known_ && capabilities_.supports("8BITMIME");
    }

    /**
     * Check if server supports SMTPUTF8 extension (RFC 6531).
     * When supported, UTF-8 characters can be used in email addresses.
     */
    bool supports_smtputf8() const
    {
        return capabilities_known_ && capabilities_.supports("SMTPUTF8");
    }

    /**
     * Send message with extended envelope options.
     * Automatically uses SIZE, 8BITMIME, and SMTPUTF8 extensions when available.
     * 
     * @param msg The message to send
     * @param env Extended envelope with extension options
     * @return Result containing server reply or error
     */
    awaitable<mailxx::result<reply>> send(const mailxx::message& msg, const envelope_ext& env)
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await send_ext_impl(msg, env);
    }

    /**
     * Send message with progress callback for large attachments.
     * @param msg The message to send
     * @param env Optional envelope (sender/recipients override)
     * @param progress Callback invoked during upload
     */
    awaitable<mailxx::result<reply>> send_with_progress(
        const mailxx::message& msg, 
        const envelope& env,
        progress_callback_t progress)
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        co_return co_await send_with_progress_impl(msg, env, std::move(progress));
    }

    /**
     * Check if server supports PIPELINING (RFC 2920).
     * PIPELINING allows sending multiple commands without waiting for responses.
     * @return true if PIPELINING is supported
     */
    bool supports_pipelining() const
    {
        return capabilities_known_ && capabilities_.supports("PIPELINING");
    }

    /**
     * Send message using PIPELINING if available (RFC 2920).
     * Sends MAIL FROM and all RCPT TO commands in one batch, then reads responses.
     * Falls back to sequential mode if PIPELINING not supported.
     * 
     * @param msg The message to send
     * @param env Optional envelope (sender/recipients override)
     * @return Result containing reply from final DATA command or error
     */
    awaitable<mailxx::result<reply>> send_pipelined(const mailxx::message& msg, const envelope& env = envelope{})
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        if (supports_pipelining())
            co_return co_await send_pipelined_impl(msg, env);
        else
            co_return co_await send_impl(msg, env);  // Fallback to sequential
    }

    awaitable<mailxx::result<reply>> noop()
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        if (state_ == state::disconnected)
            co_return fail<reply>(errc::smtp_invalid_state, "Connection is not established.", state_detail("NOOP"));
        co_return co_await command_impl("NOOP");
    }

    awaitable<mailxx::result<reply>> rset()
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        if (state_ == state::disconnected)
            co_return fail<reply>(errc::smtp_invalid_state, "Connection is not established.", state_detail("RSET"));
        co_return co_await command_impl("RSET");
    }

    awaitable<mailxx::result<reply>> quit()
    {
        mailxx::detail::async_mutex::scoped_lock guard;
        MAILXX_CO_TRY_ASSIGN(guard, co_await mutex_.lock());
        if (state_ == state::disconnected)
            co_return fail<reply>(errc::smtp_invalid_state, "Connection is not established.", state_detail("QUIT"));
        auto rep_res = co_await command_impl("QUIT");
        if (!rep_res)
            co_return rep_res;
        reply rep = std::move(*rep_res);
        dialog_.reset();
        state_ = state::disconnected;
        reset_capabilities();
        remote_host_.clear();
        co_return rep;
    }

    const capabilities& server_capabilities() const { return capabilities_; }

    // ==================== Auto-Reconnection ====================

    /**
     * Set reconnection policy for automatic reconnection on failures.
     * @param policy The reconnection policy to use
     */
    void set_reconnection_policy(reconnection_policy policy)
    {
        reconnection_policy_ = std::move(policy);
    }

    /**
     * Get current reconnection policy.
     */
    const reconnection_policy& reconnection_policy_config() const
    {
        return reconnection_policy_;
    }

    /**
     * Check if auto-reconnection is enabled.
     */
    bool auto_reconnection_enabled() const
    {
        return reconnection_policy_.enabled;
    }

    /**
     * Send message with auto-reconnection on failure.
     * If the connection is lost during send, automatically reconnects and retries.
     * 
     * @param msg The message to send
     * @param env Optional envelope
     * @param credentials Optional credentials for re-authentication (username, password, method)
     * @return Reply from send operation
     */
    awaitable<mailxx::result<reply>> send_with_reconnection(
        const mailxx::message& msg,
        const envelope& env,
        std::optional<std::tuple<std::string, std::string, auth_method>> credentials = std::nullopt)
    {
        if (!reconnection_policy_.enabled)
            co_return co_await send(msg, env);
        
        unsigned int attempt = 0;
        error_info last_error;
        
        while (true)
        {
            auto send_res = co_await send(msg, env);
            if (send_res)
            {
                co_return send_res;
            }
            
            last_error = std::move(send_res).error();
            
            if (!is_connection_error(last_error))
                co_return mailxx::fail<reply>(std::move(last_error));
            
            while (true)
            {
                ++attempt;
                
                if (reconnection_policy_.max_attempts > 0 && 
                    attempt > reconnection_policy_.max_attempts)
                {
                    if (reconnection_policy_.on_reconnect_failed)
                        reconnection_policy_.on_reconnect_failed(last_error);
                    co_return mailxx::fail<reply>(std::move(last_error));
                }
                
                auto delay = reconnection_policy_.calculate_delay(attempt);
                
                if (reconnection_policy_.on_reconnect_attempt)
                {
                    if (!reconnection_policy_.on_reconnect_attempt(attempt, delay))
                        co_return mailxx::fail<reply>(std::move(last_error));
                }
                
                // Wait before reconnecting
                steady_timer timer(executor_);
                timer.expires_after(delay);
                co_await timer.async_wait(use_awaitable);
                
                // Reset state
                dialog_.reset();
                state_ = state::disconnected;
                reset_capabilities();
                
                // Reconnect
                auto connect_res = co_await connect_impl(saved_host_, saved_service_);
                if (!connect_res)
                {
                    last_error = std::move(connect_res).error();
                    if (!is_connection_error(last_error))
                        co_return mailxx::fail<reply>(std::move(last_error));
                    continue;
                }
                auto greeting_res = co_await read_greeting_impl();
                if (!greeting_res)
                {
                    last_error = std::move(greeting_res).error();
                    if (!is_connection_error(last_error))
                        co_return mailxx::fail<reply>(std::move(last_error));
                    continue;
                }
                auto ehlo_res = co_await ehlo_impl({});
                if (!ehlo_res)
                {
                    last_error = std::move(ehlo_res).error();
                    if (!is_connection_error(last_error))
                        co_return mailxx::fail<reply>(std::move(last_error));
                    continue;
                }
                
                // Re-authenticate if credentials provided
                if (credentials.has_value())
                {
                    auto [user, pass, method] = credentials.value();
                    auto auth_res = co_await authenticate_impl(user, pass, method);
                    if (!auth_res)
                    {
                        last_error = std::move(auth_res).error();
                        if (!is_connection_error(last_error))
                            co_return mailxx::fail<reply>(std::move(last_error));
                        continue;
                    }
                }
                
                if (reconnection_policy_.on_reconnect_success)
                    reconnection_policy_.on_reconnect_success();
                break;
            }
        }
    }

private:
    /// Check if an error indicates a connection failure
    [[nodiscard]] static bool is_connection_error(const error_info& err) noexcept
    {
        switch (err.code)
        {
            case errc::net_resolve_failed:
            case errc::net_connect_failed:
            case errc::net_connection_refused:
            case errc::net_connection_reset:
            case errc::net_io_failed:
            case errc::net_timeout:
            case errc::net_eof:
            case errc::net_cancelled:
                return true;
            default:
                return false;
        }
    }

    static void append_smtp_data_terminator(std::string& data)
    {
        if (ends_with_crlf(data))
            data += ".\r\n";
        else
            data += "\r\n.\r\n";
    }

    static bool ends_with_crlf(std::string_view data) noexcept
    {
        return data.size() >= 2 && data[data.size() - 2] == '\r' && data[data.size() - 1] == '\n';
    }

    static std::size_t smtp_data_terminator_size(std::string_view data) noexcept
    {
        return ends_with_crlf(data) ? 3u : 5u;
    }

    struct mail_data_info
    {
        std::string data;
        std::size_t size = 0;
        bool has_8bit = false;
        bool needs_utf8 = false;
    };

    class streaming_queue
    {
    public:
        explicit streaming_queue(std::size_t max_buffer = 1 << 16) : max_buffer_(max_buffer) {}

        void push(std::string chunk)
        {
            std::unique_lock lk(mutex_);
            space_cv_.wait(lk, [&] { return buffered_ + chunk.size() <= max_buffer_ || done_; });
            if (done_)
                return;
            buffered_ += chunk.size();
            queue_.push(std::move(chunk));
            data_cv_.notify_one();
        }

        bool pop(std::string& out)
        {
            std::unique_lock lk(mutex_);
            data_cv_.wait(lk, [&] { return !queue_.empty() || done_ || error_; });
            if (error_)
                return false;
            if (queue_.empty())
                return false;
            out = std::move(queue_.front());
            queue_.pop();
            buffered_ -= out.size();
            space_cv_.notify_one();
            return true;
        }

        void set_done()
        {
            std::lock_guard lk(mutex_);
            done_ = true;
            data_cv_.notify_all();
            space_cv_.notify_all();
        }

        void set_error(std::string msg)
        {
            std::lock_guard lk(mutex_);
            error_ = true;
            error_msg_ = std::move(msg);
            done_ = true;
            data_cv_.notify_all();
            space_cv_.notify_all();
        }

        bool has_error() const
        {
            std::lock_guard lk(mutex_);
            return error_;
        }

        std::string error_msg() const
        {
            std::lock_guard lk(mutex_);
            return error_msg_;
        }

    private:
        std::size_t max_buffer_;
        mutable std::mutex mutex_;
        std::condition_variable data_cv_;
        std::condition_variable space_cv_;
        std::queue<std::string> queue_;
        std::size_t buffered_{0};
        bool done_{false};
        bool error_{false};
        std::string error_msg_;
    };

    class smtp_dot_stuffing_sink : public mailxx::detail::output_sink
    {
    public:
        smtp_dot_stuffing_sink(std::size_t flush_threshold = 8192, streaming_queue* queue = nullptr)
            : flush_threshold_(flush_threshold), queue_(queue)
        {
        }

        void write(std::string_view chunk) override
        {
            for (unsigned char c : chunk)
            {
                if (c & 0x80)
                    has_8bit_ = true;
                if (bol_ && c == '.')
                    add_char('.');
                add_char(static_cast<char>(c));
            }
        }

        void finalize() { flush_buffer(); }

        bool has_8bit() const noexcept { return has_8bit_; }
        std::size_t size() const noexcept { return total_size_; }
        bool ends_with_crlf() const noexcept { return last_crlf_; }

    private:
        void add_char(char c)
        {
            last_two_[0] = last_two_[1];
            last_two_[1] = c;
            last_crlf_ = (last_two_[0] == '\r' && last_two_[1] == '\n');

            buffer_.push_back(c);
            ++total_size_;
            if (buffer_.size() >= flush_threshold_)
                flush_buffer();

            if (c == '\n')
            {
                bol_ = true;
                prev_cr_ = false;
            }
            else if (c == '\r')
            {
                prev_cr_ = true;
                bol_ = false;
            }
            else
            {
                bol_ = prev_cr_;
                prev_cr_ = false;
            }
        }

        void flush_buffer()
        {
            if (buffer_.empty())
                return;
            if (queue_)
                queue_->push(std::move(buffer_));
            buffer_.clear();
            buffer_.reserve(flush_threshold_);
        }

        std::size_t flush_threshold_;
        streaming_queue* queue_;
        std::string buffer_;
        bool bol_{true};
        bool prev_cr_{false};
        bool last_crlf_{false};
        bool has_8bit_{false};
        std::size_t total_size_{0};
        std::array<char, 2> last_two_{{0, 0}};
    };

    static mailxx::result<mail_data_info> prepare_mail_data(const mailxx::message& msg, const std::string& mail_from,
        const std::vector<std::string>& recipients)
    {
        mail_data_info info;
        message_format_options_t opts;
        opts.dot_escape = true;
        opts.add_bcc_header = false;
        auto fmt_res = msg.format(info.data, opts);
        if (!fmt_res)
            return mailxx::fail<mail_data_info>(std::move(fmt_res).error());
        info.size = info.data.size() + smtp_data_terminator_size(info.data);
        info.has_8bit = contains_8bit(info.data);
        info.needs_utf8 = contains_utf8(mail_from);
        if (!info.needs_utf8)
        {
            for (const auto& rcpt : recipients)
            {
                if (contains_utf8(rcpt))
                {
                    info.needs_utf8 = true;
                    break;
                }
            }
        }
        return mailxx::ok(std::move(info));
    }

    void append_mail_extensions(std::string& cmd, const mail_data_info& info) const
    {
        mailxx::smtp::detail::mail_extension_flags flags;
        flags.use_size = options_.use_size_extension;
        flags.use_smtputf8 = options_.use_smtputf8;
        flags.use_8bitmime = options_.use_8bitmime;
        flags.supports_size = capabilities_known_ && capabilities_.supports("SIZE");
        flags.supports_smtputf8 = capabilities_known_ && capabilities_.supports("SMTPUTF8");
        flags.supports_8bitmime = capabilities_known_ && capabilities_.supports("8BITMIME");
        mailxx::smtp::detail::append_mail_extensions(cmd, info.size, info.has_8bit, info.needs_utf8, flags);
    }

    enum class state
    {
        disconnected,
        connected,
        greeted,
        ehlo_done,
        tls,
        authenticated
    };

    using dialog_type = mailxx::net::dialog<mailxx::net::upgradable_stream>;

    static bool allows_helo_fallback(int status) noexcept
    {
        return status == 500 || status == 502 || status == 504;
    }

    bool has_greeting() const noexcept
    {
        return state_ != state::disconnected && state_ != state::connected;
    }

    bool has_helo_or_ehlo() const noexcept
    {
        return state_ == state::ehlo_done || state_ == state::authenticated || helo_only_;
    }

    void reset_capabilities() noexcept
    {
        capabilities_.entries.clear();
        capabilities_known_ = false;
        helo_only_ = false;
        server_name_.clear();
    }

    [[nodiscard]] static const char* state_to_string(state value) noexcept
    {
        switch (value)
        {
            case state::disconnected: return "disconnected";
            case state::connected: return "connected";
            case state::greeted: return "greeted";
            case state::ehlo_done: return "ehlo_done";
            case state::tls: return "tls";
            case state::authenticated: return "authenticated";
        }
        return "unknown";
    }

    [[nodiscard]] std::string peer_label(std::string_view host = {}, std::string_view service = {}) const
    {
        std::string_view peer_host = host.empty() ? std::string_view(saved_host_) : host;
        std::string_view peer_service = service.empty() ? std::string_view(saved_service_) : service;
        if (peer_host.empty() && peer_service.empty())
            return {};

        std::string out;
        out.reserve(peer_host.size() + peer_service.size() + 1);
        if (!peer_host.empty())
            out.append(peer_host.data(), peer_host.size());
        if (!peer_service.empty())
        {
            if (!out.empty())
                out.push_back(':');
            out.append(peer_service.data(), peer_service.size());
        }
        return out;
    }

    void append_peer_detail(mailxx::detail::error_detail& detail, std::string_view host = {}, std::string_view service = {}) const
    {
        std::string peer = peer_label(host, service);
        if (peer.empty())
            return;
        detail.add("peer", peer);
    }

    [[nodiscard]] std::string_view smtp_host() const
    {
        if (!remote_host_.empty())
            return remote_host_;
        return saved_host_;
    }

    [[nodiscard]] std::string_view smtp_service() const
    {
        return saved_service_;
    }

    [[nodiscard]] std::string smtp_detail(
        command_kind kind,
        std::string_view command,
        const reply& rep,
        std::string_view previous = {}) const
    {
        std::string redacted;
        if (!command.empty())
            redacted = mailxx::detail::redact_line(command);
        if (options_.redact_secrets_in_trace)
        {
            reply sanitized = rep;
            for (auto& line : sanitized.lines)
                line = mailxx::detail::redact_line(line);
            return mailxx::smtp::make_smtp_detail(smtp_host(), smtp_service(), kind, redacted, sanitized, previous).str();
        }
        return mailxx::smtp::make_smtp_detail(smtp_host(), smtp_service(), kind, redacted, rep, previous).str();
    }

    [[nodiscard]] static constexpr std::string_view smtp_reply_message(command_kind kind) noexcept
    {
        switch (kind)
        {
            case command_kind::auth: return "smtp auth failed";
            case command_kind::rcpt_to: return "smtp rcpt rejected";
            case command_kind::mail_from: return "smtp mail from rejected";
            case command_kind::data_cmd:
            case command_kind::data_body: return "smtp data rejected";
            case command_kind::ehlo: return "smtp ehlo failed";
            case command_kind::helo: return "smtp helo failed";
            default: return "smtp command failed";
        }
    }

    template<typename T>
    [[nodiscard]] mailxx::result<T> smtp_fail(
        command_kind kind,
        const reply& rep,
        std::string_view command,
        std::string_view previous = {}) const
    {
        return mailxx::fail<T>(
            map_smtp_reply(kind, rep.status),
            std::string(smtp_reply_message(kind)),
            smtp_detail(kind, command, rep, previous));
    }

    [[nodiscard]] std::string state_detail(std::string_view operation) const
    {
        mailxx::detail::error_detail detail;
        detail.add("proto", "SMTP");
        detail.add("operation", operation);
        detail.add("state", state_to_string(state_));
        append_peer_detail(detail);
        return detail.str();
    }

    [[nodiscard]] std::string command_detail(std::string_view command) const
    {
        mailxx::detail::error_detail detail;
        detail.add("proto", "SMTP");
        detail.add("command", mailxx::detail::redact_line(command));
        append_peer_detail(detail);
        return detail.str();
    }

    [[nodiscard]] std::string parse_error_detail(std::string_view command, std::string_view line) const
    {
        mailxx::detail::error_detail detail;
        detail.add("proto", "smtp");
        detail.add("command.line", mailxx::detail::redact_line(command));
        if (!line.empty())
            detail.add("line", line);
        append_peer_detail(detail);
        return detail.str();
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
        mailxx::net::io_stage stage,
        std::string_view operation,
        std::string_view host = {},
        std::string_view service = {}) const
    {
        const bool timeout_triggered = (ec == asio::error::timed_out);
        const errc code = mailxx::net::map_net_error(stage, ec, timeout_triggered);
        auto detail = mailxx::net::make_net_detail("SMTP", host, service, stage, operation);
        detail.add("sys", format_sys(ec));
        return mailxx::make_error(code, std::string(mailxx::to_string(code)), detail.str(), ec);
    }

    [[nodiscard]] mailxx::result<void> validate_no_crlf_or_nul(
        std::string_view value,
        const char* field,
        std::string_view host = {},
        std::string_view service = {}) const
    {
        if (!mailxx::detail::contains_crlf_or_nul(value))
            return mailxx::ok();
        std::string msg = "Invalid ";
        msg += field ? field : "value";
        msg += ": CR/LF or NUL not allowed.";
        mailxx::detail::error_detail detail;
        append_peer_detail(detail, host, service);
        return mailxx::fail<void>(errc::codec_invalid_input, std::move(msg), detail.str());
    }

    [[nodiscard]] mailxx::result<std::string> resolve_sni(std::string_view host, std::string sni) const
    {
        if (sni.empty())
            sni.assign(host.begin(), host.end());
        auto check = validate_no_crlf_or_nul(sni, "sni", host);
        if (!check)
            return mailxx::fail<std::string>(std::move(check).error());
        return sni;
    }

    dialog_type& dialog()
    {
        return *dialog_;
    }

    void configure_trace()
    {
        if (!dialog_.has_value())
            return;
        dialog_->set_trace_protocol("SMTP");
        dialog_->set_trace_redaction(options_.redact_secrets_in_trace);
    }

    void trace_payload(std::string_view label, std::size_t bytes) const
    {
        auto& logger = mailxx::log::logger::instance();
        if (!logger.is_trace_enabled())
            return;
        std::string line;
        line.reserve(label.size() + 32);
        mailxx::detail::append_sv(line, label);
        mailxx::detail::append_sv(line, " payload bytes=");
        mailxx::detail::append_uint(line, static_cast<std::uint64_t>(bytes));
        if (options_.redact_secrets_in_trace)
            line = mailxx::detail::redact_line(line);
        logger.trace_protocol("SMTP", mailxx::log::direction::send, line);
    }

    awaitable<mailxx::result<void>> connect_impl(const std::string& host, const std::string& service,
        mailxx::net::tls_mode mode = mailxx::net::tls_mode::none,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        if (state_ != state::disconnected)
            co_return fail_void(errc::smtp_invalid_state, "Connection is already established.", state_detail("CONNECT"));

        auto host_check = validate_no_crlf_or_nul(host, "host", host, service);
        if (!host_check)
            co_return host_check;
        auto service_check = validate_no_crlf_or_nul(service, "service", host, service);
        if (!service_check)
            co_return service_check;

        remote_host_ = host;

        // Save for auto-reconnection
        saved_host_ = host;
        saved_service_ = service;

        tcp_type::resolver resolver(executor_);
        auto [resolve_ec, endpoints] = co_await resolver.async_resolve(host, service, use_nothrow_awaitable);
        if (resolve_ec)
            co_return mailxx::fail<void>(make_net_error(resolve_ec, mailxx::net::io_stage::resolve, "resolve", host, service));

        mailxx::net::upgradable_stream stream(executor_);
        auto [connect_ec, endpoint] = co_await async_connect(stream.lowest_layer(), endpoints, use_nothrow_awaitable);
        (void)endpoint;
        if (connect_ec)
            co_return mailxx::fail<void>(make_net_error(connect_ec, mailxx::net::io_stage::connect, "connect", host, service));

        if (mode == mailxx::net::tls_mode::implicit)
        {
            if (tls_ctx == nullptr)
                co_return fail_void(errc::smtp_invalid_state, "TLS context is required.", state_detail("CONNECT"));
            auto resolved_sni = resolve_sni(host, std::move(sni));
            if (!resolved_sni)
                co_return mailxx::fail<void>(std::move(resolved_sni).error());
            auto tls_res = co_await stream.start_tls(*tls_ctx, std::move(*resolved_sni), options_.tls);
            if (!tls_res)
            {
                auto err = tls_res.error();
                if (err.detail.empty())
                {
                    mailxx::detail::error_detail detail;
                    append_peer_detail(detail, host, service);
                    err.detail = detail.str();
                }
                co_return mailxx::fail<void>(std::move(err));
            }
        }

        dialog_.emplace(std::move(stream));
        dialog_->set_peer(host, service);
        configure_trace();
        state_ = state::connected;
        reset_capabilities();

        if (mode == mailxx::net::tls_mode::starttls && options_.auto_starttls)
        {
            if (tls_ctx == nullptr)
                co_return fail_void(errc::smtp_invalid_state, "TLS context is required.", state_detail("STARTTLS"));
            MAILXX_TRY_CO_AWAIT(read_greeting_impl());
            MAILXX_TRY_CO_AWAIT(ehlo_impl({}));
            MAILXX_TRY_CO_AWAIT(start_tls_impl(*tls_ctx, std::move(sni)));
            MAILXX_TRY_CO_AWAIT(ehlo_impl({}));
        }
        co_return mailxx::ok();
    }

    awaitable<mailxx::result<void>> read_greeting_impl()
    {
        if (state_ != state::connected)
            co_return fail_void(errc::smtp_invalid_state, "Greeting requires an established connection.",
                state_detail("GREETING"));
        auto rep_res = co_await read_reply_impl("GREETING");
        if (!rep_res)
            co_return mailxx::fail<void>(std::move(rep_res).error());
        reply rep = std::move(*rep_res);
        if (rep.status != 220)
            co_return smtp_fail<void>(command_kind::greeting, rep, "GREETING");
        state_ = state::greeted;
        co_return mailxx::ok();
    }

    awaitable<mailxx::result<void>> ehlo_impl(std::string domain)
    {
        if (state_ != state::greeted && state_ != state::tls)
            co_return fail_void(errc::smtp_invalid_state, "EHLO requires a greeting.", state_detail("EHLO"));

        if (!domain.empty())
        {
            auto check = validate_no_crlf_or_nul(domain, "domain");
            if (!check)
                co_return check;
        }
        const std::string helo_name = domain.empty() ? default_hostname() : std::move(domain);
        {
            auto check = validate_no_crlf_or_nul(helo_name, "helo_name");
            if (!check)
                co_return check;
        }
        const std::string ehlo_cmd = "EHLO " + helo_name;
        auto rep_res = co_await command_impl(ehlo_cmd);
        if (!rep_res)
            co_return mailxx::fail<void>(std::move(rep_res).error());
        reply rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
        {
            if (!allows_helo_fallback(rep.status))
                co_return smtp_fail<void>(command_kind::ehlo, rep, ehlo_cmd);

            const std::string helo_cmd = "HELO " + helo_name;
            auto helo_res = co_await command_impl(helo_cmd);
            if (!helo_res)
                co_return mailxx::fail<void>(std::move(helo_res).error());
            reply helo_rep = std::move(*helo_res);
            if (!helo_rep.is_positive_completion())
                co_return smtp_fail<void>(command_kind::helo, helo_rep, helo_cmd, "ehlo_failed");
            capabilities_.entries.clear();
            capabilities_known_ = false;
            helo_only_ = true;
            server_name_.clear();
            state_ = state::ehlo_done;
            co_return mailxx::ok();
        }

        capabilities_.entries.clear();
        capabilities_known_ = false;
        helo_only_ = false;
        server_name_.clear();
        if (!rep.lines.empty())
        {
            const std::string& first = rep.lines.front();
            const auto space_pos = first.find(' ');
            server_name_ = space_pos == std::string::npos ? first : first.substr(0, space_pos);
        }
        parse_capabilities(rep);
        capabilities_known_ = true;
        helo_only_ = false;
        state_ = state::ehlo_done;
        co_return mailxx::ok();
    }

    awaitable<mailxx::result<void>> start_tls_impl(ssl::context& context, std::string sni)
    {
        if (!has_greeting())
            co_return fail_void(errc::smtp_invalid_state, "STARTTLS requires a greeting.", state_detail("STARTTLS"));
        if (state_ == state::tls || state_ == state::authenticated)
            co_return fail_void(errc::smtp_invalid_state, "STARTTLS is already active.", state_detail("STARTTLS"));
        if (capabilities_known_ && !capabilities_.supports("STARTTLS"))
            co_return fail_void(errc::smtp_bad_reply, "STARTTLS not supported.", command_detail("STARTTLS"));

        auto rep_res = co_await command_impl("STARTTLS");
        if (!rep_res)
            co_return mailxx::fail<void>(std::move(rep_res).error());
        reply rep = std::move(*rep_res);
        if (rep.status != 220)
            co_return smtp_fail<void>(command_kind::starttls, rep, "STARTTLS");

        dialog_type& dlg = dialog();
        const std::size_t max_len = dlg.max_line_length();
        const auto timeout = dlg.timeout();

        mailxx::net::upgradable_stream stream = std::move(dlg.stream());
        auto resolved_sni = resolve_sni(remote_host_, std::move(sni));
        if (!resolved_sni)
            co_return mailxx::fail<void>(std::move(resolved_sni).error());
        auto tls_res = co_await stream.start_tls(context, std::move(*resolved_sni), options_.tls);
        if (!tls_res)
        {
            auto err = tls_res.error();
            if (err.detail.empty())
            {
                mailxx::detail::error_detail detail;
                append_peer_detail(detail);
                err.detail = std::move(detail).str();
            }
            co_return mailxx::fail<void>(std::move(err));
        }

        dialog_.emplace(std::move(stream), max_len, timeout);
        dialog_->set_peer(saved_host_, saved_service_);
        configure_trace();
        state_ = state::tls;
        reset_capabilities();
        co_return mailxx::ok();
    }

    awaitable<mailxx::result<void>> authenticate_impl(const std::string& username, const std::string& password, auth_method method)
    {
        {
            auto check = validate_no_crlf_or_nul(username, "username");
            if (!check)
                co_return check;
        }
        {
            auto check = validate_no_crlf_or_nul(password, "password");
            if (!check)
                co_return check;
        }
        if (!has_greeting())
            co_return fail_void(errc::smtp_invalid_state, "Authentication requires a greeting.", state_detail("AUTH"));
        if (!has_helo_or_ehlo())
            co_return fail_void(errc::smtp_invalid_state, "Authentication requires EHLO/HELO.", state_detail("AUTH"));
        if (state_ == state::authenticated)
            co_return fail_void(errc::smtp_invalid_state, "Already authenticated.", state_detail("AUTH"));
        if (!capabilities_known_)
            co_return fail_void(errc::smtp_invalid_state,
                "Server capabilities unknown; call EHLO before AUTH.", state_detail("AUTH"));
        auto tls_policy = enforce_auth_tls_policy();
        if (!tls_policy)
            co_return tls_policy;

        const auto* auth_params = capabilities_.parameters("AUTH");
        if (auth_params == nullptr)
            co_return fail_void(errc::smtp_auth_failed, "AUTH not supported.", command_detail("AUTH"));

        auto resolved_res = resolve_auth_method(method, *auth_params, password);
        if (!resolved_res)
            co_return mailxx::fail<void>(std::move(resolved_res).error());
        const auth_method resolved = *resolved_res;
        switch (resolved)
        {
            case auth_method::auto_detect:
                co_return fail_void(errc::smtp_auth_failed, "AUTH auto-detect resolution failed.", command_detail("AUTH"));
            case auth_method::plain:
                MAILXX_TRY_CO_AWAIT(authenticate_plain_impl(username, password));
                break;
            case auth_method::login:
                MAILXX_TRY_CO_AWAIT(authenticate_login_impl(username, password));
                break;
            case auth_method::xoauth2:
                MAILXX_TRY_CO_AWAIT(authenticate_xoauth2_impl(username, password));
                break;
        }
        state_ = state::authenticated;
        co_return mailxx::ok();
    }

    awaitable<mailxx::result<reply>> send_impl(const mailxx::message& msg, const envelope& env)
    {
        if (!has_greeting())
            co_return fail<reply>(errc::smtp_invalid_state, "Send requires a greeting.", state_detail("SEND"));
        if (!has_helo_or_ehlo())
            co_return fail<reply>(errc::smtp_invalid_state, "Send requires EHLO/HELO.", state_detail("SEND"));

        std::string mail_from = env.mail_from;
        if (mail_from.empty())
        {
            const auto sender = msg.sender();
            if (!sender.address.empty())
                mail_from = sender.address;
            else
            {
                const auto from = msg.from();
                if (!from.addresses.empty())
                    mail_from = from.addresses.front().address;
            }
        }
        if (mail_from.empty())
            co_return fail<reply>(errc::smtp_invalid_state, "Mail sender is missing.", command_detail("MAIL FROM"));
        {
            auto check = validate_no_crlf_or_nul(mail_from, "mail_from");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
        }

        std::vector<std::string> recipients = env.rcpt_to;
        if (recipients.empty())
            recipients = collect_recipients(msg);
        recipients = dedup(recipients);
        if (recipients.empty())
            co_return fail<reply>(errc::smtp_invalid_state, "No recipients.", command_detail("RCPT TO"));

        auto info_res = prepare_mail_data(msg, mail_from, recipients);
        if (!info_res)
            co_return mailxx::fail<reply>(std::move(info_res).error());
        mail_data_info info = std::move(*info_res);

        std::string cmd;
        mailxx::detail::append_sv(cmd, "MAIL FROM: ");
        mailxx::detail::append_angle_addr(cmd, mail_from);
        append_mail_extensions(cmd, info);
        auto rep_res = co_await command_impl(cmd);
        if (!rep_res)
            co_return rep_res;
        reply rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<reply>(command_kind::mail_from, rep, cmd);

        for (const auto& rcpt : recipients)
        {
            auto check = validate_no_crlf_or_nul(rcpt, "rcpt_to");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
            cmd.clear();
            mailxx::detail::append_sv(cmd, "RCPT TO: ");
            mailxx::detail::append_angle_addr(cmd, rcpt);
            rep_res = co_await command_impl(cmd);
            if (!rep_res)
                co_return rep_res;
            rep = std::move(*rep_res);
            if (!rep.is_positive_completion())
                co_return smtp_fail<reply>(command_kind::rcpt_to, rep, cmd);
        }

        rep_res = co_await command_impl("DATA");
        if (!rep_res)
            co_return rep_res;
        rep = std::move(*rep_res);
        if (!rep.is_positive_intermediate())
            co_return smtp_fail<reply>(command_kind::data_cmd, rep, "DATA");

        append_smtp_data_terminator(info.data);
        trace_payload("DATA", info.data.size());
        MAILXX_TRY_CO_AWAIT(dialog().write_raw_r(buffer(info.data)));

        rep_res = co_await read_reply_impl("DATA");
        if (!rep_res)
            co_return rep_res;
        rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<reply>(command_kind::data_body, rep, "DATA");

        co_return rep;
    }

    awaitable<mailxx::result<reply>> send_streaming_impl(const envelope& env, const mailxx::message& msg)
    {
        if (!has_greeting())
            co_return fail<reply>(errc::smtp_invalid_state, "Send requires a greeting.", state_detail("SEND"));
        if (!has_helo_or_ehlo())
            co_return fail<reply>(errc::smtp_invalid_state, "Send requires EHLO/HELO.", state_detail("SEND"));

        std::string mail_from = env.mail_from;
        if (mail_from.empty())
        {
            const auto sender = msg.sender();
            if (!sender.address.empty())
                mail_from = sender.address;
            else
            {
                const auto from = msg.from();
                if (!from.addresses.empty())
                    mail_from = from.addresses.front().address;
            }
        }
        if (mail_from.empty())
            co_return fail<reply>(errc::smtp_invalid_state, "Mail sender is missing.", command_detail("MAIL FROM"));
        {
            auto check = validate_no_crlf_or_nul(mail_from, "mail_from");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
        }

        std::vector<std::string> recipients = env.rcpt_to;
        if (recipients.empty())
            recipients = collect_recipients(msg);
        recipients = dedup(recipients);
        if (recipients.empty())
            co_return fail<reply>(errc::smtp_invalid_state, "No recipients.", command_detail("RCPT TO"));

        // First pass: count size and detect 8-bit/CRLF ending with dot-stuffing applied.
        smtp_dot_stuffing_sink counting_sink;
        message_format_options_t fmt_opts;
        fmt_opts.dot_escape = false; // Dot-stuffing is handled here.
        fmt_opts.add_bcc_header = false;
        auto fmt_res = msg.format_to(counting_sink, fmt_opts);
        if (!fmt_res)
            co_return mailxx::fail<reply>(std::move(fmt_res).error());
        counting_sink.finalize();
        const bool ends_with_crlf = counting_sink.ends_with_crlf();
        mail_data_info info;
        info.size = counting_sink.size() + (ends_with_crlf ? 3u : 5u);
        info.has_8bit = counting_sink.has_8bit();
        info.needs_utf8 = contains_utf8(mail_from);
        if (!info.needs_utf8)
        {
            for (const auto& rcpt : recipients)
            {
                if (contains_utf8(rcpt))
                {
                    info.needs_utf8 = true;
                    break;
                }
            }
        }

        std::string cmd;
        mailxx::detail::append_sv(cmd, "MAIL FROM: ");
        mailxx::detail::append_angle_addr(cmd, mail_from);
        append_mail_extensions(cmd, info);
        auto rep_res = co_await command_impl(cmd);
        if (!rep_res)
            co_return rep_res;
        reply rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<reply>(command_kind::mail_from, rep, cmd);

        for (const auto& rcpt : recipients)
        {
            auto check = validate_no_crlf_or_nul(rcpt, "rcpt_to");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
            cmd.clear();
            mailxx::detail::append_sv(cmd, "RCPT TO: ");
            mailxx::detail::append_angle_addr(cmd, rcpt);
            rep_res = co_await command_impl(cmd);
            if (!rep_res)
                co_return rep_res;
            rep = std::move(*rep_res);
            if (!rep.is_positive_completion())
                co_return smtp_fail<reply>(command_kind::rcpt_to, rep, cmd);
        }

        rep_res = co_await command_impl("DATA");
        if (!rep_res)
            co_return rep_res;
        rep = std::move(*rep_res);
        if (!rep.is_positive_intermediate())
            co_return smtp_fail<reply>(command_kind::data_cmd, rep, "DATA");

        // Second pass: stream the message body through a blocking queue.
        streaming_queue queue;
        smtp_dot_stuffing_sink streaming_sink(8192, &queue);
        std::thread producer([&, fmt_opts] {
            auto res = msg.format_to(streaming_sink, fmt_opts);
            if (!res)
            {
                queue.set_error(res.error().message);
                return;
            }
            streaming_sink.finalize();
            queue.set_done();
        });

        std::string chunk;
        while (queue.pop(chunk))
        {
            trace_payload("DATA", chunk.size());
            auto write_res = co_await dialog().write_raw_r(buffer(chunk));
            if (!write_res)
            {
                queue.set_done();
                producer.join();
                co_return mailxx::fail<reply>(std::move(write_res).error());
            }
        }
        queue.set_done();
        if (producer.joinable())
            producer.join();
        if (queue.has_error())
            co_return fail<reply>(errc::smtp_invalid_state, "mime format error", queue.error_msg());

        std::string terminator = ends_with_crlf ? ".\r\n" : "\r\n.\r\n";
        auto write_res = co_await dialog().write_raw_r(buffer(terminator));
        if (!write_res)
            co_return mailxx::fail<reply>(std::move(write_res).error());

        rep_res = co_await read_reply_impl("DATA");
        if (!rep_res)
            co_return rep_res;
        rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<reply>(command_kind::data_body, rep, "DATA");

        co_return rep;
    }

    /**
     * Send with DSN (RFC 3461) parameters.
     */
    awaitable<mailxx::result<reply>> send_dsn_impl(const mailxx::message& msg, const envelope_dsn& env)
    {
        if (!has_greeting())
            co_return fail<reply>(errc::smtp_invalid_state, "Send requires a greeting.", state_detail("SEND"));
        if (!has_helo_or_ehlo())
            co_return fail<reply>(errc::smtp_invalid_state, "Send requires EHLO/HELO.", state_detail("SEND"));

        // Check DSN support if DSN options are active
        const bool dsn_active = env.dsn.ret != dsn_ret::none 
                             || env.dsn.notify != dsn_notify::none
                             || !env.dsn.envid.empty();
        
        if (dsn_active && !supports_dsn())
            co_return fail<reply>(errc::smtp_bad_reply,
                "DSN requested but not supported by server.", command_detail("MAIL FROM"));

        std::string mail_from = env.mail_from;
        if (mail_from.empty())
        {
            const auto sender = msg.sender();
            if (!sender.address.empty())
                mail_from = sender.address;
            else
            {
                const auto from = msg.from();
                if (!from.addresses.empty())
                    mail_from = from.addresses.front().address;
            }
        }
        if (mail_from.empty())
            co_return fail<reply>(errc::smtp_invalid_state, "Mail sender is missing.", command_detail("MAIL FROM"));
        {
            auto check = validate_no_crlf_or_nul(mail_from, "mail_from");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
        }

        std::vector<std::string> recipients = env.rcpt_to;
        if (recipients.empty())
            recipients = collect_recipients(msg);
        recipients = dedup(recipients);
        if (recipients.empty())
            co_return fail<reply>(errc::smtp_invalid_state, "No recipients.", command_detail("RCPT TO"));

        auto info_res = prepare_mail_data(msg, mail_from, recipients);
        if (!info_res)
            co_return mailxx::fail<reply>(std::move(info_res).error());
        mail_data_info info = std::move(*info_res);

        // Build MAIL FROM with DSN parameters
        std::string cmd;
        mailxx::detail::append_sv(cmd, "MAIL FROM: ");
        mailxx::detail::append_angle_addr(cmd, mail_from);
        append_mail_extensions(cmd, info);
        
        if (dsn_active)
        {
            // RET parameter
            if (env.dsn.ret == dsn_ret::full)
                cmd += " RET=FULL";
            else if (env.dsn.ret == dsn_ret::hdrs)
                cmd += " RET=HDRS";
            
            // ENVID parameter
            if (!env.dsn.envid.empty())
            {
                auto check = validate_no_crlf_or_nul(env.dsn.envid, "dsn.envid");
                if (!check)
                    co_return mailxx::fail<reply>(std::move(check).error());
                cmd += " ENVID=";
                cmd += env.dsn.envid;
            }
        }

        auto rep_res = co_await command_impl(cmd);
        if (!rep_res)
            co_return rep_res;
        reply rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<reply>(command_kind::mail_from, rep, cmd);

        // Build NOTIFY string once
        std::string notify_str;
        if (dsn_active && env.dsn.notify != dsn_notify::none)
        {
            if ((env.dsn.notify & dsn_notify::never) != dsn_notify::none)
            {
                notify_str = " NOTIFY=NEVER";
            }
            else
            {
                std::vector<std::string_view> parts;
                if ((env.dsn.notify & dsn_notify::success) != dsn_notify::none)
                    parts.push_back("SUCCESS");
                if ((env.dsn.notify & dsn_notify::failure) != dsn_notify::none)
                    parts.push_back("FAILURE");
                if ((env.dsn.notify & dsn_notify::delay) != dsn_notify::none)
                    parts.push_back("DELAY");
                
                if (!parts.empty())
                {
                    notify_str = " NOTIFY=";
                    for (size_t i = 0; i < parts.size(); ++i)
                    {
                        if (i > 0) notify_str += ',';
                        notify_str += parts[i];
                    }
                }
            }
        }

        // ORCPT base (same for all recipients unless per-recipient is needed)
        std::string orcpt_suffix;
        if (dsn_active && !env.dsn.orcpt.empty())
        {
            auto check = validate_no_crlf_or_nul(env.dsn.orcpt, "dsn.orcpt");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
            orcpt_suffix = " ORCPT=rfc822;";
            orcpt_suffix += env.dsn.orcpt;
        }

        for (const auto& rcpt : recipients)
        {
            auto check = validate_no_crlf_or_nul(rcpt, "rcpt_to");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
            cmd.clear();
            mailxx::detail::append_sv(cmd, "RCPT TO: ");
            mailxx::detail::append_angle_addr(cmd, rcpt);
            
            if (dsn_active)
            {
                cmd += notify_str;
                // Use recipient as ORCPT if not explicitly set
                if (orcpt_suffix.empty() && env.dsn.notify != dsn_notify::none)
                {
                    cmd += " ORCPT=rfc822;";
                    cmd += rcpt;
                }
                else
                {
                    cmd += orcpt_suffix;
                }
            }
            
            rep_res = co_await command_impl(cmd);
            if (!rep_res)
                co_return rep_res;
            rep = std::move(*rep_res);
            if (!rep.is_positive_completion())
                co_return smtp_fail<reply>(command_kind::rcpt_to, rep, cmd);
        }

        rep_res = co_await command_impl("DATA");
        if (!rep_res)
            co_return rep_res;
        rep = std::move(*rep_res);
        if (!rep.is_positive_intermediate())
            co_return smtp_fail<reply>(command_kind::data_cmd, rep, "DATA");

        append_smtp_data_terminator(info.data);
        trace_payload("DATA", info.data.size());
        MAILXX_TRY_CO_AWAIT(dialog().write_raw_r(buffer(info.data)));

        rep_res = co_await read_reply_impl("DATA");
        if (!rep_res)
            co_return rep_res;
        rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<reply>(command_kind::data_body, rep, "DATA");

        co_return rep;
    }

    /**
     * Send with extended envelope (SIZE, 8BITMIME, SMTPUTF8, DSN).
     */
    awaitable<mailxx::result<reply>> send_ext_impl(const mailxx::message& msg, const envelope_ext& env)
    {
        if (!has_greeting())
            co_return fail<reply>(errc::smtp_invalid_state, "Send requires a greeting.", state_detail("SEND"));
        if (!has_helo_or_ehlo())
            co_return fail<reply>(errc::smtp_invalid_state, "Send requires EHLO/HELO.", state_detail("SEND"));

        // Resolve sender
        std::string mail_from = env.mail_from;
        if (mail_from.empty())
        {
            const auto sender = msg.sender();
            if (!sender.address.empty())
                mail_from = sender.address;
            else
            {
                const auto from = msg.from();
                if (!from.addresses.empty())
                    mail_from = from.addresses.front().address;
            }
        }
        if (mail_from.empty())
            co_return fail<reply>(errc::smtp_invalid_state, "Mail sender is missing.", command_detail("MAIL FROM"));
        {
            auto check = validate_no_crlf_or_nul(mail_from, "mail_from");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
        }

        // Resolve recipients
        std::vector<std::string> recipients = env.rcpt_to;
        if (recipients.empty())
            recipients = collect_recipients(msg);
        recipients = dedup(recipients);
        if (recipients.empty())
            co_return fail<reply>(errc::smtp_invalid_state, "No recipients.", command_detail("RCPT TO"));

        // Format message to get size and detect content type
        std::string data;
        message_format_options_t opts;
        opts.dot_escape = true;
        opts.add_bcc_header = false;
        auto fmt_res = msg.format(data, opts);
        if (!fmt_res)
            co_return mailxx::fail<reply>(std::move(fmt_res).error());
        
        const std::size_t msg_size = data.size() + 5;  // +5 for \r\n.\r\n

        // Check SIZE limit
        if (supports_size())
        {
                const auto limit = get_size_limit();
                if (limit.exceeds(msg_size))
                {
                    mailxx::detail::error_detail detail;
                    detail.add_int("size", static_cast<std::uint64_t>(msg_size));
                    detail.add_int("limit", static_cast<std::uint64_t>(limit.max_size));
                    append_peer_detail(detail);
                    co_return fail<reply>(errc::smtp_invalid_state, "Message exceeds server size limit.", detail.str());
                }
            }

        // Detect if message contains 8-bit content
        const bool has_8bit = contains_8bit(data);
        
        // Detect if envelope needs UTF-8
        const bool needs_utf8 = env.smtputf8 || contains_utf8(mail_from) || 
            std::any_of(recipients.begin(), recipients.end(), 
                [this](const std::string& r) { return contains_utf8(r); });

        // Validate extension requirements
        if (has_8bit && env.body == body_type::bit8 && !supports_8bitmime())
            co_return fail<reply>(errc::smtp_bad_reply,
                "8BITMIME required but not supported by server.", command_detail("MAIL FROM"));
        
        if (needs_utf8 && !supports_smtputf8())
            co_return fail<reply>(errc::smtp_bad_reply,
                "SMTPUTF8 required but not supported by server.", command_detail("MAIL FROM"));

        // Build MAIL FROM command with extensions
        std::string cmd;
        mailxx::detail::append_sv(cmd, "MAIL FROM: ");
        mailxx::detail::append_angle_addr(cmd, mail_from);

        // SIZE parameter (RFC 1870)
        if (supports_size())
        {
            const std::size_t declared_size = env.size > 0 ? env.size : msg_size;
            cmd += " SIZE=";
            cmd += std::to_string(declared_size);
        }

        // BODY parameter (RFC 6152 - 8BITMIME)
        if (supports_8bitmime())
        {
            body_type effective_body = env.body;
            if (effective_body == body_type::auto_detect)
                effective_body = has_8bit ? body_type::bit8 : body_type::bit7;
            
            if (effective_body == body_type::bit8)
                cmd += " BODY=8BITMIME";
            else
                cmd += " BODY=7BIT";
        }

        // SMTPUTF8 parameter (RFC 6531)
        if (needs_utf8 && supports_smtputf8())
        {
            cmd += " SMTPUTF8";
        }

        // DSN parameters (RFC 3461)
        if (env.dsn.enabled())
        {
            if (!supports_dsn())
                co_return fail<reply>(errc::smtp_bad_reply,
                    "DSN requested but not supported by server.", command_detail("MAIL FROM"));
            
            if (env.dsn.ret != dsn_ret::none)
            {
                cmd += " RET=";
                cmd += env.dsn.ret_string();
            }
            
            if (!env.dsn.envid.empty())
            {
                auto check = validate_no_crlf_or_nul(env.dsn.envid, "dsn.envid");
                if (!check)
                    co_return mailxx::fail<reply>(std::move(check).error());
                cmd += " ENVID=";
                cmd += env.dsn.envid;
            }
        }

        auto rep_res = co_await command_impl(cmd);
        if (!rep_res)
            co_return rep_res;
        reply rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<reply>(command_kind::mail_from, rep, cmd);

        // Build DSN NOTIFY/ORCPT strings
        std::string notify_str;
        std::string orcpt_suffix;
        
        if (env.dsn.enabled() && env.dsn.notify != dsn_notify::none)
        {
            notify_str = " NOTIFY=" + env.dsn.notify_string();
        }
        
        if (env.dsn.enabled() && !env.dsn.orcpt.empty())
        {
            auto check = validate_no_crlf_or_nul(env.dsn.orcpt, "dsn.orcpt");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
            orcpt_suffix = " ORCPT=rfc822;";
            orcpt_suffix += env.dsn.orcpt;
        }

        // RCPT TO commands
        for (const auto& rcpt : recipients)
        {
            auto check = validate_no_crlf_or_nul(rcpt, "rcpt_to");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
            cmd.clear();
            mailxx::detail::append_sv(cmd, "RCPT TO: ");
            mailxx::detail::append_angle_addr(cmd, rcpt);
            
            // Add DSN parameters
            if (env.dsn.enabled())
            {
                cmd += notify_str;
                if (orcpt_suffix.empty() && env.dsn.notify != dsn_notify::none)
                {
                    cmd += " ORCPT=rfc822;";
                    cmd += rcpt;
                }
                else if (!orcpt_suffix.empty())
                {
                    cmd += orcpt_suffix;
                }
            }
            
            rep_res = co_await command_impl(cmd);
            if (!rep_res)
                co_return rep_res;
            rep = std::move(*rep_res);
            if (!rep.is_positive_completion())
                co_return smtp_fail<reply>(command_kind::rcpt_to, rep, cmd);
        }

        rep_res = co_await command_impl("DATA");
        if (!rep_res)
            co_return rep_res;
        rep = std::move(*rep_res);
        if (!rep.is_positive_intermediate())
            co_return smtp_fail<reply>(command_kind::data_cmd, rep, "DATA");

        data += "\r\n.\r\n";
        trace_payload("DATA", data.size());
        MAILXX_TRY_CO_AWAIT(dialog().write_raw_r(buffer(data)));

        rep_res = co_await read_reply_impl("DATA");
        if (!rep_res)
            co_return rep_res;
        rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<reply>(command_kind::data_body, rep, "DATA");

        co_return rep;
    }

    awaitable<mailxx::result<reply>> send_with_progress_impl(
        const mailxx::message& msg, 
        const envelope& env,
        progress_callback_t progress)
    {
        if (!has_greeting())
            co_return fail<reply>(errc::smtp_invalid_state, "Send requires a greeting.", state_detail("SEND"));
        if (!has_helo_or_ehlo())
            co_return fail<reply>(errc::smtp_invalid_state, "Send requires EHLO/HELO.", state_detail("SEND"));

        std::string mail_from = env.mail_from;
        if (mail_from.empty())
        {
            const auto sender = msg.sender();
            if (!sender.address.empty())
                mail_from = sender.address;
            else
            {
                const auto from = msg.from();
                if (!from.addresses.empty())
                    mail_from = from.addresses.front().address;
            }
        }
        if (mail_from.empty())
            co_return fail<reply>(errc::smtp_invalid_state, "Mail sender is missing.", command_detail("MAIL FROM"));
        {
            auto check = validate_no_crlf_or_nul(mail_from, "mail_from");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
        }

        std::vector<std::string> recipients = env.rcpt_to;
        if (recipients.empty())
            recipients = collect_recipients(msg);
        recipients = dedup(recipients);
        if (recipients.empty())
            co_return fail<reply>(errc::smtp_invalid_state, "No recipients.", command_detail("RCPT TO"));

        auto info_res = prepare_mail_data(msg, mail_from, recipients);
        if (!info_res)
            co_return mailxx::fail<reply>(std::move(info_res).error());
        mail_data_info info = std::move(*info_res);

        std::string cmd;
        mailxx::detail::append_sv(cmd, "MAIL FROM: ");
        mailxx::detail::append_angle_addr(cmd, mail_from);
        append_mail_extensions(cmd, info);
        auto rep_res = co_await command_impl(cmd);
        if (!rep_res)
            co_return rep_res;
        reply rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<reply>(command_kind::mail_from, rep, cmd);

        for (const auto& rcpt : recipients)
        {
            auto check = validate_no_crlf_or_nul(rcpt, "rcpt_to");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
            cmd.clear();
            mailxx::detail::append_sv(cmd, "RCPT TO: ");
            mailxx::detail::append_angle_addr(cmd, rcpt);
            rep_res = co_await command_impl(cmd);
            if (!rep_res)
                co_return rep_res;
            rep = std::move(*rep_res);
            if (!rep.is_positive_completion())
                co_return smtp_fail<reply>(command_kind::rcpt_to, rep, cmd);
        }

        rep_res = co_await command_impl("DATA");
        if (!rep_res)
            co_return rep_res;
        rep = std::move(*rep_res);
        if (!rep.is_positive_intermediate())
            co_return smtp_fail<reply>(command_kind::data_cmd, rep, "DATA");

        append_smtp_data_terminator(info.data);
        trace_payload("DATA", info.data.size());

        // Send data with progress tracking
        const size_t chunk_size = 8192;
        uint64_t bytes_sent = 0;
        const uint64_t total = info.data.size();

        for (size_t offset = 0; offset < info.data.size(); offset += chunk_size)
        {
            size_t len = std::min(chunk_size, info.data.size() - offset);
            MAILXX_TRY_CO_AWAIT(dialog().write_raw_r(buffer(info.data.data() + offset, len)));
            
            bytes_sent += len;
            
            if (progress)
            {
                progress_info_t info;
                info.bytes_transferred = bytes_sent;
                info.total_bytes = total;
                info.is_upload = true;
                progress(info);
            }
        }

        rep_res = co_await read_reply_impl("DATA");
        if (!rep_res)
            co_return rep_res;
        rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<reply>(command_kind::data_body, rep, "DATA");

        co_return rep;
    }

    /**
     * PIPELINING implementation (RFC 2920).
     * Sends MAIL FROM and all RCPT TO in one batch, then reads all responses.
     */
    awaitable<mailxx::result<reply>> send_pipelined_impl(const mailxx::message& msg, const envelope& env)
    {
        if (!has_greeting())
            co_return fail<reply>(errc::smtp_invalid_state, "Send requires a greeting.", state_detail("SEND"));
        if (!has_helo_or_ehlo())
            co_return fail<reply>(errc::smtp_invalid_state, "Send requires EHLO/HELO.", state_detail("SEND"));

        std::string mail_from = env.mail_from;
        if (mail_from.empty())
        {
            const auto sender = msg.sender();
            if (!sender.address.empty())
                mail_from = sender.address;
            else
            {
                const auto from = msg.from();
                if (!from.addresses.empty())
                    mail_from = from.addresses.front().address;
            }
        }
        if (mail_from.empty())
            co_return fail<reply>(errc::smtp_invalid_state, "Mail sender is missing.", command_detail("MAIL FROM"));
        {
            auto check = validate_no_crlf_or_nul(mail_from, "mail_from");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
        }

        std::vector<std::string> recipients = env.rcpt_to;
        if (recipients.empty())
            recipients = collect_recipients(msg);
        recipients = dedup(recipients);
        if (recipients.empty())
            co_return fail<reply>(errc::smtp_invalid_state, "No recipients.", command_detail("RCPT TO"));

        auto info_res = prepare_mail_data(msg, mail_from, recipients);
        if (!info_res)
            co_return mailxx::fail<reply>(std::move(info_res).error());
        mail_data_info info = std::move(*info_res);

        // ========== PIPELINING: Send all commands first ==========
        
        // Send MAIL FROM
        std::string cmd;
        mailxx::detail::append_sv(cmd, "MAIL FROM: ");
        mailxx::detail::append_angle_addr(cmd, mail_from);
        append_mail_extensions(cmd, info);
        MAILXX_TRY_CO_AWAIT(dialog().write_line_r(cmd));
        std::string mail_command = cmd;

        // Send all RCPT TO commands without waiting for responses
        std::vector<std::string> rcpt_commands;
        rcpt_commands.reserve(recipients.size());
        for (const auto& rcpt : recipients)
        {
            auto check = validate_no_crlf_or_nul(rcpt, "rcpt_to");
            if (!check)
                co_return mailxx::fail<reply>(std::move(check).error());
            cmd.clear();
            mailxx::detail::append_sv(cmd, "RCPT TO: ");
            mailxx::detail::append_angle_addr(cmd, rcpt);
            rcpt_commands.push_back(cmd);
            MAILXX_TRY_CO_AWAIT(dialog().write_line_r(cmd));
        }

        // ========== PIPELINING: Now read all responses ==========
        
        // Read MAIL FROM response
        auto rep_res = co_await read_reply_impl(mail_command);
        if (!rep_res)
            co_return rep_res;
        reply rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<reply>(command_kind::mail_from, rep, mail_command);

        // Read all RCPT TO responses
        std::vector<std::string> accepted_recipients;
        std::vector<std::pair<std::string, reply>> rejected_recipients;
        
        for (std::size_t i = 0; i < rcpt_commands.size(); ++i)
        {
            rep_res = co_await read_reply_impl(rcpt_commands[i]);
            if (!rep_res)
                co_return rep_res;
            rep = std::move(*rep_res);
            if (rep.is_positive_completion())
            {
                accepted_recipients.push_back(recipients[i]);
            }
            else
            {
                rejected_recipients.emplace_back(rcpt_commands[i], rep);
            }
        }

        // If all recipients rejected, fail
        if (accepted_recipients.empty())
        {
            if (!rejected_recipients.empty())
            {
                const auto& rejected = rejected_recipients.front();
                co_return smtp_fail<reply>(command_kind::rcpt_to, rejected.second, rejected.first);
            }
            co_return fail<reply>(errc::smtp_rejected_recipient,
                std::string(smtp_reply_message(command_kind::rcpt_to)),
                command_detail("RCPT TO"));
        }

        // Send DATA command (must wait for this response before sending data)
        rep_res = co_await command_impl("DATA");
        if (!rep_res)
            co_return rep_res;
        rep = std::move(*rep_res);
        if (!rep.is_positive_intermediate())
            co_return smtp_fail<reply>(command_kind::data_cmd, rep, "DATA");

        // Format and send message body
        append_smtp_data_terminator(info.data);
        trace_payload("DATA", info.data.size());
        MAILXX_TRY_CO_AWAIT(dialog().write_raw_r(buffer(info.data)));

        rep_res = co_await read_reply_impl("DATA");
        if (!rep_res)
            co_return rep_res;
        rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<reply>(command_kind::data_body, rep, "DATA");

        co_return rep;
    }

    awaitable<mailxx::result<reply>> command_impl(std::string_view line)
    {
        std::string command(line);
        MAILXX_TRY_CO_AWAIT(dialog().write_line_r(command));
        co_return co_await read_reply_impl(command);
    }

    awaitable<mailxx::result<reply>> read_reply_impl(std::string_view command)
    {
        reply rep;

        while (true)
        {
            auto line_res = co_await dialog().read_line_r();
            if (!line_res)
                co_return mailxx::fail<reply>(std::move(line_res).error());
            std::string line = std::move(*line_res);
            if (line.size() < 3)
                co_return fail<reply>(errc::smtp_bad_reply,
                    "Parsing server failure.", parse_error_detail(command, line));

            if (!std::isdigit(static_cast<unsigned char>(line[0])) ||
                !std::isdigit(static_cast<unsigned char>(line[1])) ||
                !std::isdigit(static_cast<unsigned char>(line[2])))
                co_return fail<reply>(errc::smtp_bad_reply,
                    "Parsing server failure.", parse_error_detail(command, line));

            const int code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');

            bool last = true;
            if (line.size() >= 4)
            {
                if (line[3] == '-')
                    last = false;
                else if (line[3] != ' ')
                    co_return fail<reply>(errc::smtp_bad_reply,
                        "Parsing server failure.", parse_error_detail(command, line));
            }

            std::string text;
            if (line.size() > 4)
                text = line.substr(4);

            if (rep.status == 0)
                rep.status = code;
            else if (rep.status != code)
                co_return fail<reply>(errc::smtp_bad_reply,
                    "Parsing server failure.", parse_error_detail(command, line));

            rep.lines.push_back(std::move(text));

            if (last)
                break;
        }

        co_return rep;
    }

    awaitable<mailxx::result<void>> authenticate_plain_impl(const std::string& username, const std::string& password)
    {
        std::string auth;
        auth.reserve(username.size() + password.size() + 2);
        auth.push_back('\0');
        auth += username;
        auth.push_back('\0');
        auth += password;

        const auto policy = static_cast<std::string::size_type>(mailxx::codec::line_len_policy_t::NONE);
        mailxx::base64 b64(policy, policy);
        auto encoded_res = b64.encode(std::string_view(auth));
        if (!encoded_res)
            co_return fail_void(errc::smtp_auth_failed,
                "AUTH PLAIN encoding failure.", format_codec_error(encoded_res.error()));
        std::string encoded = std::move(*encoded_res);

        auto rep_res = co_await command_impl("AUTH PLAIN " + encoded);
        if (!rep_res)
            co_return mailxx::fail<void>(std::move(rep_res).error());
        reply rep = std::move(*rep_res);
        if (rep.status == 334)
        {
            rep_res = co_await command_impl(encoded);
            if (!rep_res)
                co_return mailxx::fail<void>(std::move(rep_res).error());
            rep = std::move(*rep_res);
        }

        if (!rep.is_positive_completion())
            co_return smtp_fail<void>(command_kind::auth, rep, "AUTH PLAIN");
        co_return mailxx::ok();
    }

    awaitable<mailxx::result<void>> authenticate_login_impl(const std::string& username, const std::string& password)
    {
        auto rep_res = co_await command_impl("AUTH LOGIN");
        if (!rep_res)
            co_return mailxx::fail<void>(std::move(rep_res).error());
        reply rep = std::move(*rep_res);
        if (rep.status != 334)
            co_return smtp_fail<void>(command_kind::auth, rep, "AUTH LOGIN");

        const auto policy = static_cast<std::string::size_type>(mailxx::codec::line_len_policy_t::NONE);
        mailxx::base64 b64(policy, policy);
        auto encoded_user_res = b64.encode(std::string_view(username));
        if (!encoded_user_res)
            co_return fail_void(errc::smtp_auth_failed,
                "AUTH LOGIN username encoding failure.", format_codec_error(encoded_user_res.error()));
        auto encoded_pass_res = b64.encode(std::string_view(password));
        if (!encoded_pass_res)
            co_return fail_void(errc::smtp_auth_failed,
                "AUTH LOGIN password encoding failure.", format_codec_error(encoded_pass_res.error()));
        std::string encoded_user = std::move(*encoded_user_res);
        std::string encoded_pass = std::move(*encoded_pass_res);

        rep_res = co_await command_impl(encoded_user);
        if (!rep_res)
            co_return mailxx::fail<void>(std::move(rep_res).error());
        rep = std::move(*rep_res);
        if (rep.status != 334)
            co_return smtp_fail<void>(command_kind::auth, rep, "AUTH LOGIN");

        rep_res = co_await command_impl(encoded_pass);
        if (!rep_res)
            co_return mailxx::fail<void>(std::move(rep_res).error());
        rep = std::move(*rep_res);
        if (!rep.is_positive_completion())
            co_return smtp_fail<void>(command_kind::auth, rep, "AUTH LOGIN");
        co_return mailxx::ok();
    }

    awaitable<mailxx::result<void>> authenticate_xoauth2_impl(const std::string& username, const std::string& access_token)
    {
        {
            auto check = validate_no_crlf_or_nul(username, "username");
            if (!check)
                co_return check;
        }
        {
            auto check = validate_no_crlf_or_nul(access_token, "access_token");
            if (!check)
                co_return check;
        }
        auto encoded_res = sasl::encode_xoauth2(username, access_token);
        if (!encoded_res)
            co_return fail_void(errc::smtp_auth_failed,
                "AUTH XOAUTH2 encoding failure.", format_codec_error(encoded_res.error()));
        std::string encoded = std::move(*encoded_res);

        auto rep_res = co_await command_impl("AUTH XOAUTH2 " + encoded);
        if (!rep_res)
            co_return mailxx::fail<void>(std::move(rep_res).error());
        reply rep = std::move(*rep_res);

        // Handle continuation response (server wants more data or is sending error details)
        if (rep.status == 334)
        {
            // Send empty response to get the actual error
            rep_res = co_await command_impl("");
            if (!rep_res)
                co_return mailxx::fail<void>(std::move(rep_res).error());
            rep = std::move(*rep_res);
        }

        if (!rep.is_positive_completion())
            co_return smtp_fail<void>(command_kind::auth, rep, "AUTH XOAUTH2");
        co_return mailxx::ok();
    }

    static std::string format_codec_error(const error_info& err)
    {
        if (err.detail.empty())
            return err.message;
        std::string detail = err.message;
        detail += ": ";
        detail += err.detail;
        return detail;
    }

    static std::string default_hostname()
    {
        mailxx::asio::error_code ec;
        std::string name = ip::host_name(ec);
        if (ec || name.empty())
            return "localhost";
        return name;
    }

    void parse_capabilities(const reply& rep)
    {
        capabilities_.entries.clear();
        if (rep.lines.empty())
            return;

        std::size_t start = 0;
        if (rep.lines.size() > 1)
        {
            const std::string& first = rep.lines.front();
            if (first.find(' ') == std::string::npos)
                start = 1;
        }

        for (std::size_t i = start; i < rep.lines.size(); ++i)
        {
            const std::string& line = rep.lines[i];
            if (line.empty())
                continue;

            const auto space_pos = line.find(' ');
            const std::string key = to_upper_ascii(space_pos == std::string::npos ?
                std::string_view(line) : std::string_view(line.data(), space_pos));

            std::vector<std::string> params;
            if (space_pos != std::string::npos && space_pos + 1 < line.size())
            {
                std::string_view rest(line.data() + space_pos + 1, line.size() - space_pos - 1);
                std::string current;
                for (char ch : rest)
                {
                    if (ch == ' ')
                    {
                        if (!current.empty())
                        {
                            params.push_back(current);
                            current.clear();
                        }
                        continue;
                    }
                    current.push_back(ch);
                }
                if (!current.empty())
                    params.push_back(current);
            }

            auto& slot = capabilities_.entries[key];
            slot.insert(slot.end(), params.begin(), params.end());
        }
    }

    static std::vector<std::string> collect_recipients(const mailxx::message& msg)
    {
        std::vector<std::string> recipients;
        append_mailboxes(recipients, msg.recipients());
        append_mailboxes(recipients, msg.cc_recipients());
        append_mailboxes(recipients, msg.bcc_recipients());
        return recipients;
    }

    static void append_mailboxes(std::vector<std::string>& out, const mailxx::mailboxes& boxes)
    {
        for (const auto& addr : boxes.addresses)
        {
            if (!addr.address.empty())
                out.push_back(addr.address);
        }
        for (const auto& group : boxes.groups)
        {
            for (const auto& member : group.members)
            {
                if (!member.address.empty())
                    out.push_back(member.address);
            }
        }
    }

    static std::vector<std::string> dedup(const std::vector<std::string>& addresses)
    {
        std::vector<std::string> out;
        std::unordered_set<std::string> seen;

        for (const auto& addr : addresses)
        {
            if (addr.empty())
                continue;
            std::string key = to_lower_ascii(addr);
            if (seen.insert(key).second)
                out.push_back(addr);
        }

        return out;
    }

    static std::string to_lower_ascii(std::string_view input)
    {
        std::string out;
        out.reserve(input.size());
        for (char ch : input)
        {
            if (ch >= 'A' && ch <= 'Z')
                out.push_back(static_cast<char>(ch + ('a' - 'A')));
            else
                out.push_back(ch);
        }
        return out;
    }

    static std::string to_upper_ascii(std::string_view input)
    {
        std::string out;
        out.reserve(input.size());
        for (char ch : input)
        {
            if (ch >= 'a' && ch <= 'z')
                out.push_back(static_cast<char>(ch - ('a' - 'A')));
            else
                out.push_back(ch);
        }
        return out;
    }

    /**
     * Check if string contains any 8-bit (non-ASCII) characters.
     */
    static bool contains_8bit(std::string_view data) noexcept
    {
        for (unsigned char ch : data)
        {
            if (ch > 127)
                return true;
        }
        return false;
    }

    /**
     * Check if string contains UTF-8 multi-byte sequences.
     * Used to detect if SMTPUTF8 extension is needed.
     */
    static bool contains_utf8(std::string_view data) noexcept
    {
        for (std::size_t i = 0; i < data.size(); ++i)
        {
            unsigned char ch = static_cast<unsigned char>(data[i]);
            if (ch > 127)
            {
                // Check for valid UTF-8 lead byte
                if ((ch & 0xE0) == 0xC0 ||  // 2-byte
                    (ch & 0xF0) == 0xE0 ||  // 3-byte
                    (ch & 0xF8) == 0xF0)    // 4-byte
                {
                    return true;
                }
            }
        }
        return false;
    }

    static bool auth_mechanism_supported(const std::vector<std::string>& params, std::string_view mechanism)
    {
        const std::string key = to_upper_ascii(mechanism);
        for (const auto& param : params)
        {
            if (to_upper_ascii(param) == key)
                return true;
        }
        return false;
    }

    mailxx::result<auth_method> resolve_auth_method(
        auth_method method,
        const std::vector<std::string>& params,
        std::string_view secret)
    {
        const bool has_xoauth2 = auth_mechanism_supported(params, "XOAUTH2");
        const bool has_plain = auth_mechanism_supported(params, "PLAIN");
        const bool has_login = auth_mechanism_supported(params, "LOGIN");
        auto auth_detail = [&]()
        {
            std::string detail = command_detail("AUTH");
            if (!params.empty())
            {
                if (!detail.empty())
                    detail += "\n";
                detail += "mechanisms: ";
                for (std::size_t i = 0; i < params.size(); ++i)
                {
                    if (i > 0)
                        detail.push_back(' ');
                    detail += params[i];
                }
            }
            return detail;
        };

        if (method == auth_method::auto_detect)
        {
            if (!secret.empty() && has_xoauth2)
                return mailxx::ok(auth_method::xoauth2);
            if (has_plain)
                return mailxx::ok(auth_method::plain);
            if (has_login)
                return mailxx::ok(auth_method::login);
            return mailxx::fail<auth_method>(errc::smtp_auth_failed,
                "No supported AUTH mechanisms advertised.", auth_detail());
        }

        if (method == auth_method::plain && !has_plain)
            return mailxx::fail<auth_method>(errc::smtp_auth_failed,
                "AUTH PLAIN not advertised by the server.", auth_detail());
        if (method == auth_method::login && !has_login)
            return mailxx::fail<auth_method>(errc::smtp_auth_failed,
                "AUTH LOGIN not advertised by the server.", auth_detail());
        if (method == auth_method::xoauth2 && !has_xoauth2)
            return mailxx::fail<auth_method>(errc::smtp_auth_failed,
                "AUTH XOAUTH2 not advertised by the server.", auth_detail());
        return mailxx::ok(method);
    }

    mailxx::result<void> enforce_auth_tls_policy()
    {
        if (dialog().stream().is_tls() || !options_.require_tls_for_auth)
            return mailxx::ok();
        if (options_.allow_cleartext_auth)
        {
            MAILXX_WARN("AUTH without TLS allowed by configuration.");
            return mailxx::ok();
        }
        mailxx::detail::error_detail detail;
        detail.add("policy", "require_tls_for_auth");
        append_peer_detail(detail);
        return mailxx::fail<void>(errc::smtp_invalid_state,
            "TLS required for authentication; call start_tls() or use tls_mode::implicit",
            detail.str());
    }

    executor_type executor_;
    options options_;
    mailxx::detail::async_mutex mutex_;
    std::optional<dialog_type> dialog_;
    std::string remote_host_;
    std::string server_name_;
    std::string saved_host_;      ///< For auto-reconnection
    std::string saved_service_;   ///< For auto-reconnection
    capabilities capabilities_;
    state state_{state::disconnected};
    bool helo_only_{false};
    bool capabilities_known_{false};
    reconnection_policy reconnection_policy_;  ///< Auto-reconnection configuration
};

} // namespace mailxx::smtp

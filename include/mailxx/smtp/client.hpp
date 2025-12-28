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

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/auth_policy.hpp>
#include <mailxx/detail/log.hpp>

#include <mailxx/net/dialog.hpp>
#include <mailxx/net/tls_mode.hpp>
#include <mailxx/net/upgradable_stream.hpp>
#include <mailxx/mime/message.hpp>
#include <mailxx/mime/mailboxes.hpp>
#include <mailxx/codec/base64.hpp>
#include <mailxx/codec/codec.hpp>
#include <mailxx/detail/append.hpp>
#include <mailxx/detail/async_mutex.hpp>
#include <mailxx/detail/sasl.hpp>
#include <mailxx/detail/sanitize.hpp>
#include <mailxx/detail/redact.hpp>
#include <mailxx/detail/reconnection.hpp>
#include <mailxx/smtp/types.hpp>
#include <mailxx/smtp/error.hpp>

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

    awaitable<void> connect(const std::string& host, unsigned short port)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await connect_impl(host, std::to_string(port), mailxx::net::tls_mode::none, nullptr, {});
    }

    awaitable<void> connect(const std::string& host, const std::string& service)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await connect_impl(host, service, mailxx::net::tls_mode::none, nullptr, {});
    }

    awaitable<void> connect(const std::string& host, unsigned short port, mailxx::net::tls_mode mode,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await connect_impl(host, std::to_string(port), mode, tls_ctx, std::move(sni));
    }

    /**
     * Connect with explicit TLS mode.
     * If options.auto_starttls is enabled, performs greeting -> EHLO -> STARTTLS -> EHLO.
     */
    awaitable<void> connect(const std::string& host, const std::string& service, mailxx::net::tls_mode mode,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await connect_impl(host, service, mode, tls_ctx, std::move(sni));
    }

    awaitable<void> connect(std::string host, std::string service, mailxx::net::tls_mode mode,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await connect_impl(host, service, mode, tls_ctx, std::move(sni));
    }

    awaitable<reply> read_greeting()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await read_greeting_impl();
    }

    awaitable<reply> ehlo(std::string domain = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await ehlo_impl(std::move(domain));
    }

    /**
     * Upgrade the connection using STARTTLS.
     * After STARTTLS, EHLO must be issued again to refresh capabilities.
     */
    awaitable<void> start_tls(ssl::context& context, std::string sni = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await start_tls_impl(context, std::move(sni));
    }

    awaitable<void> authenticate(const std::string& username, const std::string& password, auth_method method)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await authenticate_impl(username, password, method);
    }

    /**
     * Authenticate using OAuth2 access token.
     * Use this with Gmail, Outlook, and other OAuth2 providers.
     * 
     * @param username The email address
     * @param access_token The OAuth2 access token (not refresh token)
     */
    awaitable<void> authenticate_oauth2(const std::string& username, const std::string& access_token)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await authenticate_impl(username, access_token, auth_method::xoauth2);
    }

    awaitable<reply> send(const mailxx::message& msg, const envelope& env = envelope{})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await send_impl(msg, env);
    }

    /**
     * Send message with DSN (Delivery Status Notification) support.
     * Requires server to advertise DSN capability.
     * 
     * @param msg The message to send
     * @param env Extended envelope with DSN options
     * @return Server reply
     * @throws error if DSN requested but not supported by server
     */
    awaitable<reply> send(const mailxx::message& msg, const envelope_dsn& env)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await send_dsn_impl(msg, env);
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
        
        try
        {
            return {std::stoull(params->front())};
        }
        catch (...)
        {
            return {};
        }
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
     * @return Server reply
     */
    awaitable<reply> send(const mailxx::message& msg, const envelope_ext& env)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await send_ext_impl(msg, env);
    }

    /**
     * Send message with progress callback for large attachments.
     * @param msg The message to send
     * @param env Optional envelope (sender/recipients override)
     * @param progress Callback invoked during upload
     */
    awaitable<reply> send_with_progress(
        const mailxx::message& msg, 
        const envelope& env,
        progress_callback_t progress)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
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
     * @return Reply from final DATA command
     */
    awaitable<reply> send_pipelined(const mailxx::message& msg, const envelope& env = envelope{})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        if (supports_pipelining())
            co_return co_await send_pipelined_impl(msg, env);
        else
            co_return co_await send_impl(msg, env);  // Fallback to sequential
    }

    awaitable<reply> noop()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        if (state_ == state::disconnected)
            throw error("Connection is not established.", "");
        co_return co_await command_impl("NOOP");
    }

    awaitable<reply> rset()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        if (state_ == state::disconnected)
            throw error("Connection is not established.", "");
        co_return co_await command_impl("RSET");
    }

    awaitable<reply> quit()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        if (state_ == state::disconnected)
            throw error("Connection is not established.", "");
        reply rep = co_await command_impl("QUIT");
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
    awaitable<reply> send_with_reconnection(
        const mailxx::message& msg,
        const envelope& env,
        std::optional<std::tuple<std::string, std::string, auth_method>> credentials = std::nullopt)
    {
        if (!reconnection_policy_.enabled)
            co_return co_await send(msg, env);
        
        unsigned int attempt = 0;
        std::exception_ptr last_error;
        
        while (true)
        {
            try
            {
                co_return co_await send(msg, env);
            }
            catch (const std::exception& e)
            {
                last_error = std::current_exception();
                
                if (!is_connection_error(e))
                    std::rethrow_exception(last_error);
                
                ++attempt;
                
                if (reconnection_policy_.max_attempts > 0 && 
                    attempt > reconnection_policy_.max_attempts)
                {
                    if (reconnection_policy_.on_reconnect_failed)
                        reconnection_policy_.on_reconnect_failed(e);
                    std::rethrow_exception(last_error);
                }
                
                auto delay = reconnection_policy_.calculate_delay(attempt);
                
                if (reconnection_policy_.on_reconnect_attempt)
                {
                    if (!reconnection_policy_.on_reconnect_attempt(attempt, delay))
                        std::rethrow_exception(last_error);
                }
                
                // Wait before reconnecting
                steady_timer timer(executor_);
                timer.expires_after(delay);
                co_await timer.async_wait(use_awaitable);
                
                // Try to reconnect
                try
                {
                    // Reset state
                    dialog_.reset();
                    state_ = state::disconnected;
                    reset_capabilities();
                    
                    // Reconnect
                    co_await connect_impl(saved_host_, saved_service_);
                    co_await read_greeting_impl();
                    co_await ehlo_impl({});
                    
                    // Re-authenticate if credentials provided
                    if (credentials.has_value())
                    {
                        auto [user, pass, method] = credentials.value();
                        co_await authenticate_impl(user, pass, method);
                    }
                    
                    if (reconnection_policy_.on_reconnect_success)
                        reconnection_policy_.on_reconnect_success();
                }
                catch (const std::exception& conn_error)
                {
                    // Connection failed, try again
                    continue;
                }
            }
        }
    }

private:
    /// Check if an exception indicates a connection error
    [[nodiscard]] static bool is_connection_error(const std::exception& e)
    {
        const std::string msg = e.what();
        static const char* keywords[] = {
            "connection", "disconnected", "broken pipe", "reset by peer",
            "timed out", "timeout", "eof", "end of file", "closed", "network"
        };
        for (const char* keyword : keywords)
        {
            if (msg.find(keyword) != std::string::npos)
                return true;
        }
        return false;
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

    static mail_data_info prepare_mail_data(const mailxx::message& msg, const std::string& mail_from,
        const std::vector<std::string>& recipients)
    {
        mail_data_info info;
        message_format_options_t opts;
        opts.dot_escape = true;
        opts.add_bcc_header = false;
        msg.format(info.data, opts);
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
        return info;
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

    std::string resolve_sni(std::string_view host, std::string sni) const
    {
        if (sni.empty())
            sni.assign(host.begin(), host.end());
        mailxx::detail::ensure_no_crlf_or_nul(sni, "sni");
        return sni;
    }

    dialog_type& dialog()
    {
        if (!dialog_.has_value())
            throw error("Connection is not established.", "");
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

    awaitable<void> connect_impl(const std::string& host, const std::string& service,
        mailxx::net::tls_mode mode = mailxx::net::tls_mode::none,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        if (state_ != state::disconnected)
            throw error("Connection is already established.", "");
        mailxx::detail::ensure_no_crlf_or_nul(host, "host");
        remote_host_ = host;
        
        // Save for auto-reconnection
        saved_host_ = host;
        saved_service_ = service;

        tcp_type::resolver resolver(executor_);
        auto endpoints = co_await resolver.async_resolve(host, service, use_awaitable);

        mailxx::net::upgradable_stream stream(executor_);
        co_await async_connect(stream.lowest_layer(), endpoints, use_awaitable);

        if (mode == mailxx::net::tls_mode::implicit)
        {
            if (tls_ctx == nullptr)
                throw error("TLS context is required.", "Implicit TLS needs a context.");
            std::string resolved_sni = resolve_sni(host, std::move(sni));
            co_await stream.start_tls(*tls_ctx, std::move(resolved_sni), options_.tls);
        }

        dialog_.emplace(std::move(stream));
        configure_trace();
        state_ = state::connected;
        reset_capabilities();

        if (mode == mailxx::net::tls_mode::starttls && options_.auto_starttls)
        {
            if (tls_ctx == nullptr)
                throw error("TLS context is required.", "STARTTLS needs a context.");
            co_await read_greeting_impl();
            co_await ehlo_impl({});
            co_await start_tls_impl(*tls_ctx, std::move(sni));
            co_await ehlo_impl({});
        }
    }

    awaitable<reply> read_greeting_impl()
    {
        if (state_ != state::connected)
            throw error("Greeting requires an established connection.", "");
        reply rep = co_await read_reply_impl();
        if (rep.status != 220)
            throw error("Connection rejection.", rep.message());
        state_ = state::greeted;
        co_return rep;
    }

    awaitable<reply> ehlo_impl(std::string domain)
    {
        if (state_ != state::greeted && state_ != state::tls)
            throw error("EHLO requires a greeting.", "");

        if (!domain.empty())
            mailxx::detail::ensure_no_crlf_or_nul(domain, "domain");
        const std::string helo_name = domain.empty() ? default_hostname() : std::move(domain);
        mailxx::detail::ensure_no_crlf_or_nul(helo_name, "helo_name");
        reply rep = co_await command_impl("EHLO " + helo_name);
        if (!rep.is_positive_completion())
        {
            if (!allows_helo_fallback(rep.status))
                throw error("EHLO rejection.", rep.message());

            reply helo_rep = co_await command_impl("HELO " + helo_name);
            if (!helo_rep.is_positive_completion())
                throw error("HELO rejection.", helo_rep.message());
            capabilities_.entries.clear();
            capabilities_known_ = false;
            helo_only_ = true;
            server_name_.clear();
            state_ = state::ehlo_done;
            co_return helo_rep;
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
        co_return rep;
    }

    awaitable<void> start_tls_impl(ssl::context& context, std::string sni)
    {
        if (!has_greeting())
            throw error("STARTTLS requires a greeting.", "");
        if (state_ == state::tls || state_ == state::authenticated)
            throw error("STARTTLS is already active.", "");
        if (capabilities_known_ && !capabilities_.supports("STARTTLS"))
            throw error("STARTTLS not supported.", "Server did not advertise STARTTLS.");

        reply rep = co_await command_impl("STARTTLS");
        if (rep.status != 220)
            throw error("STARTTLS failure.", rep.message());

        dialog_type& dlg = dialog();
        const std::size_t max_len = dlg.max_line_length();
        const auto timeout = dlg.timeout();

        mailxx::net::upgradable_stream stream = std::move(dlg.stream());
        std::string resolved_sni = resolve_sni(remote_host_, std::move(sni));
        co_await stream.start_tls(context, std::move(resolved_sni), options_.tls);

        dialog_.emplace(std::move(stream), max_len, timeout);
        configure_trace();
        state_ = state::tls;
        reset_capabilities();
    }

    awaitable<void> authenticate_impl(const std::string& username, const std::string& password, auth_method method)
    {
        mailxx::detail::ensure_no_crlf_or_nul(username, "username");
        mailxx::detail::ensure_no_crlf_or_nul(password, "password");
        if (!has_greeting())
            throw error("Authentication requires a greeting.", "");
        if (!has_helo_or_ehlo())
            throw error("Authentication requires EHLO/HELO.", "");
        if (state_ == state::authenticated)
            throw error("Already authenticated.", "");
        if (!capabilities_known_)
            throw error("Server capabilities unknown; call EHLO before AUTH.", "");
        enforce_auth_tls_policy();

        const auto* auth_params = capabilities_.parameters("AUTH");
        if (auth_params == nullptr)
            throw error("AUTH not supported.", "Server did not advertise AUTH.");

        const auth_method resolved = resolve_auth_method(method, *auth_params, password);
        switch (resolved)
        {
            case auth_method::auto_detect:
                throw error("AUTH auto-detect resolution failed.", "");
            case auth_method::plain:
                co_await authenticate_plain_impl(username, password);
                break;
            case auth_method::login:
                co_await authenticate_login_impl(username, password);
                break;
            case auth_method::xoauth2:
                co_await authenticate_xoauth2_impl(username, password);
                break;
        }
        state_ = state::authenticated;
    }

    awaitable<reply> send_impl(const mailxx::message& msg, const envelope& env)
    {
        if (!has_greeting())
            throw error("Send requires a greeting.", "");
        if (!has_helo_or_ehlo())
            throw error("Send requires EHLO/HELO.", "");

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
            throw error("Mail sender is missing.", "");
        mailxx::detail::ensure_no_crlf_or_nul(mail_from, "mail_from");

        std::vector<std::string> recipients = env.rcpt_to;
        if (recipients.empty())
            recipients = collect_recipients(msg);
        recipients = dedup(recipients);
        if (recipients.empty())
            throw error("No recipients.", "");

        mail_data_info info = prepare_mail_data(msg, mail_from, recipients);

        std::string cmd;
        mailxx::detail::append_sv(cmd, "MAIL FROM: ");
        mailxx::detail::append_angle_addr(cmd, mail_from);
        append_mail_extensions(cmd, info);
        reply rep = co_await command_impl(cmd);
        if (!rep.is_positive_completion())
            throw error("Mail sender rejection.", rep.message());

        for (const auto& rcpt : recipients)
        {
            mailxx::detail::ensure_no_crlf_or_nul(rcpt, "rcpt_to");
            cmd.clear();
            mailxx::detail::append_sv(cmd, "RCPT TO: ");
            mailxx::detail::append_angle_addr(cmd, rcpt);
            rep = co_await command_impl(cmd);
            if (!rep.is_positive_completion())
                throw error("Mail recipient rejection.", rep.message());
        }

        rep = co_await command_impl("DATA");
        if (!rep.is_positive_intermediate())
            throw error("Mail message rejection.", rep.message());

        append_smtp_data_terminator(info.data);
        trace_payload("DATA", info.data.size());
        co_await dialog().write_raw(buffer(info.data), use_awaitable);

        rep = co_await read_reply_impl();
        if (!rep.is_positive_completion())
            throw error("Mail message rejection.", rep.message());

        co_return rep;
    }

    /**
     * Send with DSN (RFC 3461) parameters.
     */
    awaitable<reply> send_dsn_impl(const mailxx::message& msg, const envelope_dsn& env)
    {
        if (!has_greeting())
            throw error("Send requires a greeting.", "");
        if (!has_helo_or_ehlo())
            throw error("Send requires EHLO/HELO.", "");

        // Check DSN support if DSN options are active
        const bool dsn_active = env.dsn.ret != dsn_ret::none 
                             || env.dsn.notify != dsn_notify::none
                             || !env.dsn.envid.empty();
        
        if (dsn_active && !supports_dsn())
            throw error("DSN requested but not supported by server.", "");

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
            throw error("Mail sender is missing.", "");
        mailxx::detail::ensure_no_crlf_or_nul(mail_from, "mail_from");

        std::vector<std::string> recipients = env.rcpt_to;
        if (recipients.empty())
            recipients = collect_recipients(msg);
        recipients = dedup(recipients);
        if (recipients.empty())
            throw error("No recipients.", "");

        mail_data_info info = prepare_mail_data(msg, mail_from, recipients);

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
                mailxx::detail::ensure_no_crlf_or_nul(env.dsn.envid, "dsn.envid");
                cmd += " ENVID=";
                cmd += env.dsn.envid;
            }
        }

        reply rep = co_await command_impl(cmd);
        if (!rep.is_positive_completion())
            throw error("Mail sender rejection.", rep.message());

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
            mailxx::detail::ensure_no_crlf_or_nul(env.dsn.orcpt, "dsn.orcpt");
            orcpt_suffix = " ORCPT=rfc822;";
            orcpt_suffix += env.dsn.orcpt;
        }

        for (const auto& rcpt : recipients)
        {
            mailxx::detail::ensure_no_crlf_or_nul(rcpt, "rcpt_to");
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
            
            rep = co_await command_impl(cmd);
            if (!rep.is_positive_completion())
                throw error("Mail recipient rejection.", rep.message());
        }

        rep = co_await command_impl("DATA");
        if (!rep.is_positive_intermediate())
            throw error("Mail message rejection.", rep.message());

        append_smtp_data_terminator(info.data);
        trace_payload("DATA", info.data.size());
        co_await dialog().write_raw(buffer(info.data), use_awaitable);

        rep = co_await read_reply_impl();
        if (!rep.is_positive_completion())
            throw error("Mail message rejection.", rep.message());

        co_return rep;
    }

    /**
     * Send with extended envelope (SIZE, 8BITMIME, SMTPUTF8, DSN).
     */
    awaitable<reply> send_ext_impl(const mailxx::message& msg, const envelope_ext& env)
    {
        if (!has_greeting())
            throw error("Send requires a greeting.", "");
        if (!has_helo_or_ehlo())
            throw error("Send requires EHLO/HELO.", "");

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
            throw error("Mail sender is missing.", "");
        mailxx::detail::ensure_no_crlf_or_nul(mail_from, "mail_from");

        // Resolve recipients
        std::vector<std::string> recipients = env.rcpt_to;
        if (recipients.empty())
            recipients = collect_recipients(msg);
        recipients = dedup(recipients);
        if (recipients.empty())
            throw error("No recipients.", "");

        // Format message to get size and detect content type
        std::string data;
        message_format_options_t opts;
        opts.dot_escape = true;
        opts.add_bcc_header = false;
        msg.format(data, opts);
        
        const std::size_t msg_size = data.size() + 5;  // +5 for \r\n.\r\n

        // Check SIZE limit
        if (supports_size())
        {
            const auto limit = get_size_limit();
            if (limit.exceeds(msg_size))
            {
                throw error("Message exceeds server size limit.", 
                    "Size: " + std::to_string(msg_size) + ", Limit: " + std::to_string(limit.max_size));
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
            throw error("8BITMIME required but not supported by server.", "");
        
        if (needs_utf8 && !supports_smtputf8())
            throw error("SMTPUTF8 required but not supported by server.", "");

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
                throw error("DSN requested but not supported by server.", "");
            
            if (env.dsn.ret != dsn_ret::none)
            {
                cmd += " RET=";
                cmd += env.dsn.ret_string();
            }
            
            if (!env.dsn.envid.empty())
            {
                mailxx::detail::ensure_no_crlf_or_nul(env.dsn.envid, "dsn.envid");
                cmd += " ENVID=";
                cmd += env.dsn.envid;
            }
        }

        reply rep = co_await command_impl(cmd);
        if (!rep.is_positive_completion())
            throw error("Mail sender rejection.", rep.message());

        // Build DSN NOTIFY/ORCPT strings
        std::string notify_str;
        std::string orcpt_suffix;
        
        if (env.dsn.enabled() && env.dsn.notify != dsn_notify::none)
        {
            notify_str = " NOTIFY=" + env.dsn.notify_string();
        }
        
        if (env.dsn.enabled() && !env.dsn.orcpt.empty())
        {
            mailxx::detail::ensure_no_crlf_or_nul(env.dsn.orcpt, "dsn.orcpt");
            orcpt_suffix = " ORCPT=rfc822;";
            orcpt_suffix += env.dsn.orcpt;
        }

        // RCPT TO commands
        for (const auto& rcpt : recipients)
        {
            mailxx::detail::ensure_no_crlf_or_nul(rcpt, "rcpt_to");
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
            
            rep = co_await command_impl(cmd);
            if (!rep.is_positive_completion())
                throw error("Mail recipient rejection.", rep.message());
        }

        rep = co_await command_impl("DATA");
        if (!rep.is_positive_intermediate())
            throw error("Mail message rejection.", rep.message());

        data += "\r\n.\r\n";
        trace_payload("DATA", data.size());
        co_await dialog().write_raw(buffer(data), use_awaitable);

        rep = co_await read_reply_impl();
        if (!rep.is_positive_completion())
            throw error("Mail message rejection.", rep.message());

        co_return rep;
    }

    awaitable<reply> send_with_progress_impl(
        const mailxx::message& msg, 
        const envelope& env,
        progress_callback_t progress)
    {
        if (!has_greeting())
            throw error("Send requires a greeting.", "");
        if (!has_helo_or_ehlo())
            throw error("Send requires EHLO/HELO.", "");

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
            throw error("Mail sender is missing.", "");
        mailxx::detail::ensure_no_crlf_or_nul(mail_from, "mail_from");

        std::vector<std::string> recipients = env.rcpt_to;
        if (recipients.empty())
            recipients = collect_recipients(msg);
        recipients = dedup(recipients);
        if (recipients.empty())
            throw error("No recipients.", "");

        mail_data_info info = prepare_mail_data(msg, mail_from, recipients);

        std::string cmd;
        mailxx::detail::append_sv(cmd, "MAIL FROM: ");
        mailxx::detail::append_angle_addr(cmd, mail_from);
        append_mail_extensions(cmd, info);
        reply rep = co_await command_impl(cmd);
        if (!rep.is_positive_completion())
            throw error("Mail sender rejection.", rep.message());

        for (const auto& rcpt : recipients)
        {
            mailxx::detail::ensure_no_crlf_or_nul(rcpt, "rcpt_to");
            cmd.clear();
            mailxx::detail::append_sv(cmd, "RCPT TO: ");
            mailxx::detail::append_angle_addr(cmd, rcpt);
            rep = co_await command_impl(cmd);
            if (!rep.is_positive_completion())
                throw error("Mail recipient rejection.", rep.message());
        }

        rep = co_await command_impl("DATA");
        if (!rep.is_positive_intermediate())
            throw error("Mail message rejection.", rep.message());

        append_smtp_data_terminator(info.data);
        trace_payload("DATA", info.data.size());

        // Send data with progress tracking
        const size_t chunk_size = 8192;
        uint64_t bytes_sent = 0;
        const uint64_t total = info.data.size();

        for (size_t offset = 0; offset < info.data.size(); offset += chunk_size)
        {
            size_t len = std::min(chunk_size, info.data.size() - offset);
            co_await dialog().write_raw(buffer(info.data.data() + offset, len), use_awaitable);
            
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

        rep = co_await read_reply_impl();
        if (!rep.is_positive_completion())
            throw error("Mail message rejection.", rep.message());

        co_return rep;
    }

    /**
     * PIPELINING implementation (RFC 2920).
     * Sends MAIL FROM and all RCPT TO in one batch, then reads all responses.
     */
    awaitable<reply> send_pipelined_impl(const mailxx::message& msg, const envelope& env)
    {
        if (!has_greeting())
            throw error("Send requires a greeting.", "");
        if (!has_helo_or_ehlo())
            throw error("Send requires EHLO/HELO.", "");

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
            throw error("Mail sender is missing.", "");
        mailxx::detail::ensure_no_crlf_or_nul(mail_from, "mail_from");

        std::vector<std::string> recipients = env.rcpt_to;
        if (recipients.empty())
            recipients = collect_recipients(msg);
        recipients = dedup(recipients);
        if (recipients.empty())
            throw error("No recipients.", "");

        mail_data_info info = prepare_mail_data(msg, mail_from, recipients);

        // ========== PIPELINING: Send all commands first ==========
        
        // Send MAIL FROM
        std::string cmd;
        mailxx::detail::append_sv(cmd, "MAIL FROM: ");
        mailxx::detail::append_angle_addr(cmd, mail_from);
        append_mail_extensions(cmd, info);
        co_await dialog().write_line(cmd, use_awaitable);

        // Send all RCPT TO commands without waiting for responses
        for (const auto& rcpt : recipients)
        {
            mailxx::detail::ensure_no_crlf_or_nul(rcpt, "rcpt_to");
            cmd.clear();
            mailxx::detail::append_sv(cmd, "RCPT TO: ");
            mailxx::detail::append_angle_addr(cmd, rcpt);
            co_await dialog().write_line(cmd, use_awaitable);
        }

        // ========== PIPELINING: Now read all responses ==========
        
        // Read MAIL FROM response
        reply rep = co_await read_reply_impl();
        if (!rep.is_positive_completion())
            throw error("Mail sender rejection.", rep.message());

        // Read all RCPT TO responses
        std::vector<std::string> accepted_recipients;
        std::vector<std::pair<std::string, reply>> rejected_recipients;
        
        for (const auto& rcpt : recipients)
        {
            rep = co_await read_reply_impl();
            if (rep.is_positive_completion())
            {
                accepted_recipients.push_back(rcpt);
            }
            else
            {
                rejected_recipients.emplace_back(rcpt, rep);
            }
        }

        // If all recipients rejected, fail
        if (accepted_recipients.empty())
            throw error("All recipients rejected.", rejected_recipients.front().second.message());

        // Send DATA command (must wait for this response before sending data)
        rep = co_await command_impl("DATA");
        if (!rep.is_positive_intermediate())
            throw error("Mail message rejection.", rep.message());

        // Format and send message body
        append_smtp_data_terminator(info.data);
        trace_payload("DATA", info.data.size());
        co_await dialog().write_raw(buffer(info.data), use_awaitable);

        rep = co_await read_reply_impl();
        if (!rep.is_positive_completion())
            throw error("Mail message rejection.", rep.message());

        co_return rep;
    }

    awaitable<reply> command_impl(std::string_view line)
    {
        co_await dialog().write_line(line, use_awaitable);
        co_return co_await read_reply_impl();
    }

    awaitable<reply> read_reply_impl()
    {
        reply rep;

        while (true)
        {
            std::string line = co_await dialog().read_line(use_awaitable);
            if (line.size() < 3)
                throw error("Parsing server failure.", line);

            if (!std::isdigit(static_cast<unsigned char>(line[0])) ||
                !std::isdigit(static_cast<unsigned char>(line[1])) ||
                !std::isdigit(static_cast<unsigned char>(line[2])))
                throw error("Parsing server failure.", line);

            const int code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');

            bool last = true;
            if (line.size() >= 4)
            {
                if (line[3] == '-')
                    last = false;
                else if (line[3] != ' ')
                    throw error("Parsing server failure.", line);
            }

            std::string text;
            if (line.size() > 4)
                text = line.substr(4);

            if (rep.status == 0)
                rep.status = code;
            else if (rep.status != code)
                throw error("Parsing server failure.", line);

            rep.lines.push_back(std::move(text));

            if (last)
                break;
        }

        co_return rep;
    }

    awaitable<void> authenticate_plain_impl(const std::string& username, const std::string& password)
    {
        std::string auth;
        auth.reserve(username.size() + password.size() + 2);
        auth.push_back('\0');
        auth += username;
        auth.push_back('\0');
        auth += password;

        const auto policy = static_cast<std::string::size_type>(mailxx::codec::line_len_policy_t::NONE);
        mailxx::base64 b64(policy, policy);
        const auto encoded_lines = b64.encode(auth);
        const std::string encoded = join_lines(encoded_lines);

        reply rep = co_await command_impl("AUTH PLAIN " + encoded);
        if (rep.status == 334)
            rep = co_await command_impl(encoded);

        if (!rep.is_positive_completion())
            throw error("Authentication rejection.", rep.message());
    }

    awaitable<void> authenticate_login_impl(const std::string& username, const std::string& password)
    {
        reply rep = co_await command_impl("AUTH LOGIN");
        if (rep.status != 334)
            throw error("Authentication rejection.", rep.message());

        const auto policy = static_cast<std::string::size_type>(mailxx::codec::line_len_policy_t::NONE);
        mailxx::base64 b64(policy, policy);
        std::string encoded_user = join_lines(b64.encode(username));
        std::string encoded_pass = join_lines(b64.encode(password));

        rep = co_await command_impl(encoded_user);
        if (rep.status != 334)
            throw error("Username rejection.", rep.message());

        rep = co_await command_impl(encoded_pass);
        if (!rep.is_positive_completion())
            throw error("Password rejection.", rep.message());
    }

    awaitable<void> authenticate_xoauth2_impl(const std::string& username, const std::string& access_token)
    {
        mailxx::detail::ensure_no_crlf_or_nul(username, "username");
        mailxx::detail::ensure_no_crlf_or_nul(access_token, "access_token");
        const std::string encoded = sasl::encode_xoauth2(username, access_token);

        reply rep = co_await command_impl("AUTH XOAUTH2 " + encoded);

        // Handle continuation response (server wants more data or is sending error details)
        if (rep.status == 334)
        {
            // Send empty response to get the actual error
            rep = co_await command_impl("");
        }

        if (!rep.is_positive_completion())
            throw error("XOAUTH2 authentication failure.", rep.message());
    }

    static std::string join_lines(const std::vector<std::string>& lines)
    {
        std::string out;
        for (const auto& line : lines)
            out += line;
        return out;
    }

    static std::string default_hostname()
    {
        try
        {
            return ip::host_name();
        }
        catch (...)
        {
            return "localhost";
        }
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

    auth_method resolve_auth_method(auth_method method, const std::vector<std::string>& params, std::string_view secret)
    {
        const bool has_xoauth2 = auth_mechanism_supported(params, "XOAUTH2");
        const bool has_plain = auth_mechanism_supported(params, "PLAIN");
        const bool has_login = auth_mechanism_supported(params, "LOGIN");

        if (method == auth_method::auto_detect)
        {
            if (!secret.empty() && has_xoauth2)
                return auth_method::xoauth2;
            if (has_plain)
                return auth_method::plain;
            if (has_login)
                return auth_method::login;
            throw error("No supported AUTH mechanisms advertised.", "");
        }

        if (method == auth_method::plain && !has_plain)
            throw error("AUTH PLAIN not advertised by the server.", "");
        if (method == auth_method::login && !has_login)
            throw error("AUTH LOGIN not advertised by the server.", "");
        if (method == auth_method::xoauth2 && !has_xoauth2)
            throw error("AUTH XOAUTH2 not advertised by the server.", "");
        return method;
    }

    void enforce_auth_tls_policy()
    {
        mailxx::detail::ensure_auth_allowed<error>(dialog().stream().is_tls(), options_);
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

/*

pop3.hpp
--------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4251)
#endif

#include <string>
#include <string_view>
#include <cstdint>
#include <charconv>
#include <vector>
#include <utility>
#include <istream>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <optional>
#include <system_error>
#include <openssl/md5.h>
#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/net/upgradable_stream.hpp>
#include <mailxx/net/dialog.hpp>
#include <mailxx/net/tls_mode.hpp>
#include <mailxx/mime/message.hpp>
#include <mailxx/detail/append.hpp>
#include <mailxx/detail/auth_policy.hpp>
#include <mailxx/detail/async_mutex.hpp>
#include <mailxx/detail/log.hpp>
#include <mailxx/detail/sasl.hpp>
#include <mailxx/detail/sanitize.hpp>
#include <mailxx/detail/reconnection.hpp>
#include <mailxx/pop3/error.hpp>
#include <mailxx/pop3/types.hpp>

namespace mailxx::pop3
{

using namespace mailxx::asio;

/// Reconnection policy alias for POP3
using reconnection_policy = mailxx::detail::reconnection_policy;

/**
Base class for POP3 client containing common logic and constants.
**/
class pop3_base
{
public:
    enum class auth_method_t {LOGIN, PLAIN, XOAUTH2, APOP};

    using message_list_t = message_list;
    using uidl_list_t = uidl_list;
    using mailbox_stat_t = mailbox_stat;

protected:
    static const char TOKEN_SEPARATOR_CHAR = ' ';
    inline static const std::string OK_RESPONSE = "+OK";
    inline static const std::string ERR_RESPONSE = "-ERR";
    inline static const std::string END_OF_DATA = ".";

    static std::tuple<std::string, std::string> parse_status(const std::string& line)
    {
        std::string::size_type pos = line.find(TOKEN_SEPARATOR_CHAR);
        std::string status = line.substr(0, pos);
        std::string rest = (pos != std::string::npos) ? line.substr(pos + 1) : "";
        if (status != OK_RESPONSE && status != ERR_RESPONSE)
            throw error("Unknown response status.", line);
        return std::make_tuple(status, rest);
    }
    
    static bool is_ok(const std::string& status) { return status == OK_RESPONSE; }
};


/**
Stable POP3 client implementation.
**/
class client : public pop3_base
{
private:
    struct session_snapshot
    {
        enum class auth_mechanism { none, user_pass, sasl_plain, xoauth2, apop };

        std::string host;
        std::string service;
        mailxx::net::tls_mode tls_mode{mailxx::net::tls_mode::none};
        ssl::context* tls_ctx{nullptr}; // non-owning
        std::string sni;
        auth_mechanism auth{auth_mechanism::none};
        std::string username;
        std::optional<std::string> secret; // sensible

        [[nodiscard]] bool has_connection() const noexcept
        {
            return !host.empty() && !service.empty();
        }

        [[nodiscard]] bool has_auth() const noexcept
        {
            return auth != auth_mechanism::none && !username.empty();
        }
    };

public:
    using dialog_type = mailxx::net::dialog<mailxx::net::upgradable_stream>;
    using capabilities_t = capabilities;

    /// POP3 session state (RFC 1939)
    enum class state_t { 
        DISCONNECTED,   ///< Not connected to server
        CONNECTED,      ///< Connected, waiting for greeting
        GREETING,       ///< Received greeting, in authorization state
        TRANSACTION,    ///< Authenticated, ready for commands
        UPDATE          ///< QUIT sent, connection closing
    };

    explicit client(any_io_executor executor, options opts = {})
        : options_(std::move(opts)),
          dlg_(mailxx::net::upgradable_stream(executor), options_.max_line_length, options_.timeout),
          mutex_(dlg_.stream().get_executor()),
          state_(state_t::DISCONNECTED)
    {
        configure_trace();
    }

    explicit client(io_context& io_context, options opts = {})
        : client(io_context.get_executor(), std::move(opts))
    {
    }

    ~client() = default;

    [[nodiscard]] state_t state() const noexcept { return state_; }

#if defined(MAILXX_TESTING)
    struct debug_snapshot_view
    {
        std::string host;
        std::string service;
        mailxx::net::tls_mode tls_mode = mailxx::net::tls_mode::none;
        bool has_tls_ctx = false;
        std::string sni;
        bool has_auth = false;
        std::string username;
        std::optional<std::string> secret;
    };

    void debug_remember_connection(std::string_view host, std::string_view service,
        mailxx::net::tls_mode mode = mailxx::net::tls_mode::none,
        ssl::context* tls_ctx = nullptr, std::string_view sni = {})
    {
        remember_connection(host, service);
        remember_tls(mode, tls_ctx, sni);
    }

    void debug_remember_user_pass(std::string_view username, std::string_view password)
    {
        remember_auth(session_snapshot::auth_mechanism::user_pass, username, password);
    }

    void debug_remember_plain(std::string_view username, std::string_view password)
    {
        remember_auth(session_snapshot::auth_mechanism::sasl_plain, username, password);
    }

    void debug_remember_xoauth2(std::string_view username, std::string_view access_token)
    {
        remember_auth(session_snapshot::auth_mechanism::xoauth2, username, access_token);
    }

    debug_snapshot_view debug_snapshot() const
    {
        debug_snapshot_view view;
        view.host = session_snapshot_.host;
        view.service = session_snapshot_.service;
        view.tls_mode = session_snapshot_.tls_mode;
        view.has_tls_ctx = session_snapshot_.tls_ctx != nullptr;
        view.sni = session_snapshot_.sni;
        view.has_auth = session_snapshot_.has_auth();
        view.username = session_snapshot_.username;
        view.secret = session_snapshot_.secret;
        return view;
    }
#endif

    awaitable<void> connect(const std::string& host, uint16_t port)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await connect_impl(host, std::to_string(port), mailxx::net::tls_mode::none, nullptr, {});
    }

    awaitable<void> connect(const std::string& host, uint16_t port, mailxx::net::tls_mode mode,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await connect_impl(host, std::to_string(port), mode, tls_ctx, std::move(sni));
    }

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

    awaitable<std::string> read_greeting()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await read_greeting_impl();
    }

    awaitable<capabilities_t> capa()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await capa_impl();
    }

    awaitable<void> start_tls(ssl::context& context, std::string sni = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await start_tls_impl(context, std::move(sni));
    }

    awaitable<void> login(const std::string& username, const std::string& password)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await login_impl(username, password);
    }

    /**
     * Authenticate using SASL PLAIN mechanism.
     */
    awaitable<void> auth_plain(const std::string& username, const std::string& password)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await auth_plain_impl(username, password);
    }

    /**
     * Authenticate using XOAUTH2 mechanism for OAuth2.
     * Use this with Gmail, Outlook, and other OAuth2 providers.
     * 
     * @param username The email address
     * @param access_token The OAuth2 access token (not refresh token)
     */
    awaitable<void> auth_xoauth2(const std::string& username, const std::string& access_token)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await auth_xoauth2_impl(username, access_token);
    }

    /**
     * Authenticate using APOP challenge-response.
     */
    awaitable<void> apop(const std::string& username, const std::string& password)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await apop_impl(username, password);
    }

    /**
     * Authenticate using the specified method.
     */
    awaitable<void> authenticate(const std::string& username, const std::string& credential, auth_method_t method)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await authenticate_impl(username, credential, method);
    }

    /**
     * Authenticate using OAuth2 access token.
     * Convenience method for OAuth2 authentication.
     */
    awaitable<void> authenticate_oauth2(const std::string& username, const std::string& access_token)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await auth_xoauth2_impl(username, access_token);
    }

    awaitable<mailbox_stat_t> stat()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await stat_impl();
    }

    awaitable<message_list_t> list()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await list_impl();
    }

    awaitable<message_list_t> list(unsigned message_no)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await list_impl(message_no);
    }

    awaitable<uidl_list_t> uidl(unsigned message_no = 0)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await uidl_impl(message_no);
    }

    awaitable<std::string> retr(unsigned long message_no)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await retr_impl(message_no);
    }

    /**
     * RETR with progress callback for large messages.
     * @param message_no Message number
     * @param expected_size Expected size from LIST (for progress calculation)
     * @param progress Callback invoked during download
     */
    awaitable<std::string> retr_with_progress(
        unsigned long message_no,
        unsigned long expected_size,
        progress_callback_t progress)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await retr_with_progress_impl(message_no, expected_size, std::move(progress));
    }

    awaitable<std::string> top(unsigned message_no, unsigned lines)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await top_impl(message_no, lines);
    }

    awaitable<mailxx::message> retr_message(unsigned message_no)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await retr_message_impl(message_no);
    }

    awaitable<void> dele(unsigned long message_no)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await dele_impl(message_no);
    }

    awaitable<void> rset()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await rset_impl();
    }

    awaitable<void> noop()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await noop_impl();
    }

    awaitable<void> quit()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await quit_impl();
    }

    dialog_type& dialog() { return dlg_; }
    const dialog_type& dialog() const { return dlg_; }

    void configure_trace()
    {
        dlg_.set_trace_protocol("POP3");
        dlg_.set_trace_redaction(options_.redact_secrets_in_trace);
    }

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
     * Retrieve message with auto-reconnection on failure.
     * @param message_no Message number
     * @param credentials Kept for compatibility; reconnection uses stored session data.
     * @return Message content
     */
    awaitable<std::string> retr_with_reconnection(
        unsigned long message_no,
        const std::pair<std::string, std::string>& /*credentials*/)
    {
        if (!reconnection_policy_.enabled)
            co_return co_await retr(message_no);
        
        unsigned int attempt = 0;
        std::exception_ptr last_error;
        
        while (true)
        {
            try
            {
                co_return co_await retr(message_no);
            }
            catch (const std::exception& e)
            {
                last_error = std::current_exception();
                
                if (!is_connection_error(e))
                    std::rethrow_exception(last_error);

                const session_snapshot snapshot = session_snapshot_;
                ensure_reconnect_ready(snapshot);
                
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
                steady_timer timer(dlg_.stream().get_executor());
                timer.expires_after(delay);
                co_await timer.async_wait(use_awaitable);
                
                // Try to reconnect
                try
                {
                    co_await reconnect_with_snapshot(snapshot);
                    
                    if (reconnection_policy_.on_reconnect_success)
                        reconnection_policy_.on_reconnect_success();
                }
                catch (const std::exception& reconnect_error)
                {
                    if (!is_connection_error(reconnect_error))
                        throw;
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

    static void ensure_reconnect_ready(const session_snapshot& snapshot)
    {
        if (!snapshot.has_connection())
            throw error("Reconnection failure: no session stored.", "");
        if (!snapshot.has_auth())
            throw error("Reconnection failure: no auth stored.", "");
        if (!snapshot.secret.has_value())
            throw error("Reconnection failure: no creds stored.", "");
        if (snapshot.tls_mode != mailxx::net::tls_mode::none && snapshot.tls_ctx == nullptr)
            throw error("Reconnection failure: no TLS context stored.", "");
    }

    void remember_connection(std::string_view host, std::string_view service)
    {
        session_snapshot_.host.assign(host.begin(), host.end());
        session_snapshot_.service.assign(service.begin(), service.end());
    }

    void remember_tls(mailxx::net::tls_mode mode, ssl::context* tls_ctx, std::string_view sni)
    {
        session_snapshot_.tls_mode = mode;
        session_snapshot_.tls_ctx = tls_ctx;
        session_snapshot_.sni.assign(sni.begin(), sni.end());
    }

    void remember_auth(session_snapshot::auth_mechanism mechanism, std::string_view username, std::string_view secret)
    {
        session_snapshot_.auth = mechanism;
        session_snapshot_.username.assign(username.begin(), username.end());
        if (options_.store_credentials_for_reconnect)
            session_snapshot_.secret = std::string(secret); // sensible
        else
            session_snapshot_.secret.reset();
    }

    static std::string extract_apop_challenge(std::string_view greeting_line)
    {
        const auto start = greeting_line.find('<');
        if (start == std::string_view::npos)
            throw error("APOP challenge missing.", std::string(greeting_line));
        const auto end = greeting_line.find('>', start + 1);
        if (end == std::string_view::npos || end <= start)
            throw error("APOP challenge missing.", std::string(greeting_line));
        return std::string(greeting_line.substr(start, end - start + 1));
    }

    static std::string md5_hex(std::string_view input)
    {
        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);

        static constexpr char hex[] = "0123456789abcdef";
        std::string out;
        out.reserve(MD5_DIGEST_LENGTH * 2);
        for (unsigned char byte : digest)
        {
            out.push_back(hex[byte >> 4]);
            out.push_back(hex[byte & 0x0F]);
        }
        return out;
    }

    awaitable<void> reconnect_with_snapshot(const session_snapshot& snapshot)
    {
        state_ = state_t::DISCONNECTED;

        co_await connect_impl(snapshot.host, snapshot.service, snapshot.tls_mode, snapshot.tls_ctx, snapshot.sni);

        if (state_ == state_t::CONNECTED)
            co_await read_greeting_impl();

        if (snapshot.tls_mode == mailxx::net::tls_mode::starttls && !options_.auto_starttls)
        {
            if (snapshot.tls_ctx == nullptr)
                throw error("TLS context is required.", "STLS needs a context.");
            (void)co_await capa_impl();
            co_await start_tls_impl(*snapshot.tls_ctx, snapshot.sni);
        }

        co_await reauthenticate(snapshot);
    }

    awaitable<void> reauthenticate(const session_snapshot& snapshot)
    {
        const std::string& secret = snapshot.secret.value();
        switch (snapshot.auth)
        {
            case session_snapshot::auth_mechanism::user_pass:
                co_await login_impl(snapshot.username, secret);
                break;
            case session_snapshot::auth_mechanism::sasl_plain:
                co_await auth_plain_impl(snapshot.username, secret);
                break;
            case session_snapshot::auth_mechanism::xoauth2:
                co_await auth_xoauth2_impl(snapshot.username, secret);
                break;
            case session_snapshot::auth_mechanism::apop:
                co_await apop_impl(snapshot.username, secret);
                break;
            case session_snapshot::auth_mechanism::none:
                throw error("Reconnection failure: no auth stored.", "");
        }
    }

    std::string resolve_sni(std::string_view host, std::string sni) const
    {
        if (sni.empty())
            sni.assign(host.begin(), host.end());
        mailxx::detail::ensure_no_crlf_or_nul(sni, "sni");
        return sni;
    }

    awaitable<void> upgrade_to_tls(ssl::context& context, std::string sni)
    {
        dialog_type& dlg = dlg_;
        const std::size_t max_len = dlg.max_line_length();
        const auto timeout = dlg.timeout();

        mailxx::net::upgradable_stream stream = std::move(dlg.stream());
        co_await stream.start_tls(context, std::move(sni), options_.tls);
        dlg_ = dialog_type(std::move(stream), max_len, timeout);
        configure_trace();
    }

    awaitable<void> connect_impl(const std::string& host, const std::string& service,
        mailxx::net::tls_mode mode = mailxx::net::tls_mode::none,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        ensure_state(state_t::DISCONNECTED, "CONNECT");
        mailxx::detail::ensure_no_crlf_or_nul(host, "host");
        host_ = host;
        remember_connection(host, service);
        remember_tls(mode, tls_ctx, sni);
        
        // Save for auto-reconnection
        saved_host_ = host;
        saved_service_ = service;
        saved_port_ = 0;
        if (!service.empty())
        {
            std::uint32_t value = 0;
            const char* begin = service.data();
            const char* end = begin + service.size();
            auto [ptr, ec] = std::from_chars(begin, end, value);
            if (ec == std::errc{} && ptr == end && value <= 65535u)
                saved_port_ = static_cast<uint16_t>(value);
        }
        
        capabilities_.reset();
        const auto executor = dlg_.stream().get_executor();
        tcp::resolver resolver(executor);
        auto endpoints = co_await resolver.async_resolve(host, service, use_awaitable);

        mailxx::net::upgradable_stream stream(executor);
        co_await async_connect(stream.lowest_layer(), endpoints, use_awaitable);
        
        if (mode == mailxx::net::tls_mode::implicit)
        {
            if (tls_ctx == nullptr)
                throw error("TLS context is required.", "Implicit TLS needs a context.");
            std::string resolved_sni = resolve_sni(host, std::move(sni));
            remember_tls(mailxx::net::tls_mode::implicit, tls_ctx, resolved_sni);
            co_await stream.start_tls(*tls_ctx, std::move(resolved_sni), options_.tls);
        }

        dlg_ = dialog_type(std::move(stream), options_.max_line_length, options_.timeout);
        configure_trace();
        state_ = state_t::CONNECTED;

        if (mode == mailxx::net::tls_mode::starttls && options_.auto_starttls)
        {
            if (tls_ctx == nullptr)
                throw error("TLS context is required.", "STLS needs a context.");
            co_await read_greeting_impl();
            (void)co_await capa_impl();
            co_await start_tls_impl(*tls_ctx, std::move(sni));
            (void)co_await capa_impl();
        }
    }

    awaitable<std::string> read_greeting_impl()
    {
        ensure_state(state_t::CONNECTED, "READ_GREETING");
        std::string line = co_await dlg_.read_line(use_awaitable);
        last_greeting_line_ = line;
        auto [status, msg] = parse_status(line);
        if (!is_ok(status))
            throw error("Connection to server failure.", msg);
        state_ = state_t::GREETING;
        co_return msg;
    }

    awaitable<capabilities_t> capa_impl()
    {
        ensure_state_at_least(state_t::GREETING, "CAPA");
        co_await send_command("CAPA");
        (void)co_await read_ok_response("Capabilities failure.");

        capabilities_t caps;
        while (true)
        {
            std::string line = co_await dlg_.read_line(use_awaitable);
            if (line == END_OF_DATA)
                break;
            if (!line.empty() && line[0] == '.')
                line.erase(0, 1);
            caps.raw_lines.push_back(line);
            parse_capability_line(caps, line);
        }
        capabilities_ = caps;
        co_return caps;
    }

    awaitable<void> start_tls_impl(ssl::context& context, std::string sni)
    {
        ensure_state(state_t::GREETING, "STLS");
        // Require CAPA to be called first to avoid optimistic STLS.
        if (!capabilities_.has_value())
            throw error("STLS capability unknown; call CAPA first.", "");
        if (!capabilities_->stls)
            throw error("STLS not supported.", "");

        co_await send_command("STLS");
        std::string line = co_await dlg_.read_line(use_awaitable);
        auto [status, msg] = parse_status(line);
        if (!is_ok(status))
            throw error("STARTTLS failure.", msg);

        std::string resolved_sni = resolve_sni(host_, std::move(sni));
        remember_tls(mailxx::net::tls_mode::starttls, &context, resolved_sni);
        co_await upgrade_to_tls(context, std::move(resolved_sni));
    }

    awaitable<void> login_impl(const std::string& username, const std::string& password)
    {
        ensure_state(state_t::GREETING, "LOGIN");
        enforce_auth_tls_policy();
        mailxx::detail::ensure_no_crlf_or_nul(username, "username");
        mailxx::detail::ensure_no_crlf_or_nul(password, "password");
        co_await send_command("USER " + username);
        (void)co_await read_ok_response("Username rejection.");

        co_await send_command("PASS " + password);
        (void)co_await read_ok_response("Password rejection.");
        state_ = state_t::TRANSACTION;
        remember_auth(session_snapshot::auth_mechanism::user_pass, username, password);
    }

    awaitable<void> auth_plain_impl(const std::string& username, const std::string& password)
    {
        ensure_state(state_t::GREETING, "AUTH PLAIN");
        enforce_auth_tls_policy();
        mailxx::detail::ensure_no_crlf_or_nul(username, "username");
        mailxx::detail::ensure_no_crlf_or_nul(password, "password");
        const std::string encoded = sasl::encode_plain(username, password);
        
        co_await send_command("AUTH PLAIN");
        std::string line = co_await dlg_.read_line(use_awaitable);
        
        if (!line.empty() && line[0] == '+')
        {
            co_await send_command(encoded);
            (void)co_await read_ok_response("PLAIN authentication failure.");
        }
        else
        {
            auto [status, msg] = parse_status(line);
            if (!is_ok(status))
                throw error("PLAIN authentication failure.", msg);
        }
        state_ = state_t::TRANSACTION;
        remember_auth(session_snapshot::auth_mechanism::sasl_plain, username, password);
    }

    awaitable<void> auth_xoauth2_impl(const std::string& username, const std::string& access_token)
    {
        ensure_state(state_t::GREETING, "AUTH XOAUTH2");
        enforce_auth_tls_policy();
        mailxx::detail::ensure_no_crlf_or_nul(username, "username");
        mailxx::detail::ensure_no_crlf_or_nul(access_token, "access_token");
        const std::string encoded = sasl::encode_xoauth2(username, access_token);
        
        co_await send_command("AUTH XOAUTH2 " + encoded);
        std::string line = co_await dlg_.read_line(use_awaitable);
        
        if (!line.empty() && line[0] == '+')
        {
            co_await send_command("");
            (void)co_await read_ok_response("XOAUTH2 authentication failure.");
        }
        else
        {
            auto [status, msg] = parse_status(line);
            if (!is_ok(status))
                throw error("XOAUTH2 authentication failure.", msg);
        }
        state_ = state_t::TRANSACTION;
        remember_auth(session_snapshot::auth_mechanism::xoauth2, username, access_token);
    }

    awaitable<void> apop_impl(const std::string& username, const std::string& password)
    {
        ensure_state(state_t::GREETING, "APOP");
        mailxx::detail::ensure_no_crlf_or_nul(username, "username");
        mailxx::detail::ensure_no_crlf_or_nul(password, "password");

        if (last_greeting_line_.empty())
            throw error("APOP challenge missing.", "");

        const std::string challenge = extract_apop_challenge(last_greeting_line_);
        const std::string digest = md5_hex(challenge + password);

        std::string cmd;
        mailxx::detail::append_sv(cmd, "APOP ");
        mailxx::detail::append_sv(cmd, username);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, digest);
        co_await send_command(cmd);
        (void)co_await read_ok_response("APOP authentication failure.");
        state_ = state_t::TRANSACTION;
        remember_auth(session_snapshot::auth_mechanism::apop, username, password);
    }

    awaitable<void> authenticate_impl(const std::string& username, const std::string& credential, auth_method_t method)
    {
        switch (method)
        {
            case auth_method_t::LOGIN:
                co_await login_impl(username, credential);
                break;
            case auth_method_t::PLAIN:
                co_await auth_plain_impl(username, credential);
                break;
            case auth_method_t::XOAUTH2:
                co_await auth_xoauth2_impl(username, credential);
                break;
            case auth_method_t::APOP:
                co_await apop_impl(username, credential);
                break;
        }
    }

    void enforce_auth_tls_policy()
    {
        mailxx::detail::ensure_auth_allowed<error>(dlg_.stream().is_tls(), options_);
    }

    awaitable<mailbox_stat_t> stat_impl()
    {
        ensure_state(state_t::TRANSACTION, "STAT");
        co_await send_command("STAT");
        std::string msg = co_await read_ok_response("Reading statistics failure.");
        mailbox_stat_t stat;
        std::istringstream iss(msg);
        if (!(iss >> stat.messages_no >> stat.mailbox_size))
            throw error("Parser failure.", msg);
        co_return stat;
    }

    awaitable<message_list_t> list_impl()
    {
        ensure_state(state_t::TRANSACTION, "LIST");
        co_await send_command("LIST");
        (void)co_await read_ok_response("Listing all messages failure.");

        message_list_t msg_list;
        while (true)
        {
            std::string line = co_await dlg_.read_line(use_awaitable);
            if (line == END_OF_DATA)
                break;
            if (!line.empty() && line[0] == '.')
                line.erase(0, 1);
            std::istringstream iss(line);
            unsigned num = 0;
            unsigned long size = 0;
            if (iss >> num >> size)
                msg_list[num] = size;
        }
        co_return msg_list;
    }

    awaitable<message_list_t> list_impl(unsigned message_no)
    {
        ensure_state(state_t::TRANSACTION, "LIST");
        std::string cmd;
        mailxx::detail::append_sv(cmd, "LIST ");
        mailxx::detail::append_uint(cmd, message_no);
        co_await send_command(cmd);
        std::string msg = co_await read_ok_response("Listing message failure.");

        message_list_t msg_list;
        std::istringstream iss(msg);
        unsigned num = 0;
        unsigned long size = 0;
        if (iss >> num >> size)
            msg_list[num] = size;
        co_return msg_list;
    }

    awaitable<uidl_list_t> uidl_impl(unsigned message_no)
    {
        ensure_state(state_t::TRANSACTION, "UIDL");
        std::string cmd;
        if (message_no == 0)
        {
            cmd = "UIDL";
        }
        else
        {
            mailxx::detail::append_sv(cmd, "UIDL ");
            mailxx::detail::append_uint(cmd, message_no);
        }
        co_await send_command(cmd);
        std::string msg = co_await read_ok_response("Unique ID listing failure.");

        uidl_list_t uidl_list;
        if (message_no != 0)
        {
            std::istringstream iss(msg);
            unsigned num = 0;
            std::string uidl;
            if (iss >> num >> uidl)
                uidl_list[num] = std::move(uidl);
            co_return uidl_list;
        }

        while (true)
        {
            std::string line = co_await dlg_.read_line(use_awaitable);
            if (line == END_OF_DATA)
                break;
            if (!line.empty() && line[0] == '.')
                line.erase(0, 1);
            std::istringstream iss(line);
            unsigned num = 0;
            std::string uidl;
            if (iss >> num >> uidl)
                uidl_list[num] = std::move(uidl);
        }
        co_return uidl_list;
    }

    awaitable<std::string> retr_impl(unsigned long message_no)
    {
        ensure_state(state_t::TRANSACTION, "RETR");
        std::string cmd;
        mailxx::detail::append_sv(cmd, "RETR ");
        mailxx::detail::append_uint(cmd, message_no);
        co_await send_command(cmd);
        (void)co_await read_ok_response("Fetching message failure.");

        std::string msg_str;
        while (true)
        {
            std::string line = co_await dlg_.read_line(use_awaitable);
            if (line == END_OF_DATA)
                break;
            if (!line.empty() && line[0] == '.')
                line.erase(0, 1);
            msg_str += line + "\r\n";
        }
        co_return msg_str;
    }

    awaitable<std::string> retr_with_progress_impl(
        unsigned long message_no,
        unsigned long expected_size,
        progress_callback_t progress)
    {
        ensure_state(state_t::TRANSACTION, "RETR");
        std::string cmd;
        mailxx::detail::append_sv(cmd, "RETR ");
        mailxx::detail::append_uint(cmd, message_no);
        co_await send_command(cmd);
        (void)co_await read_ok_response("Fetching message failure.");

        std::string msg_str;
        msg_str.reserve(expected_size > 0 ? expected_size : 8192);
        unsigned long bytes_received = 0;
        unsigned long last_callback_bytes = 0;
        constexpr unsigned long callback_interval = 8192; // 8KB

        // Initial progress callback
        if (progress)
        {
            progress_info_t info{0, expected_size, false};
            progress(info);
        }

        while (true)
        {
            std::string line = co_await dlg_.read_line(use_awaitable);
            if (line == END_OF_DATA)
                break;
            if (!line.empty() && line[0] == '.')
                line.erase(0, 1);
            
            msg_str += line + "\r\n";
            bytes_received += line.size() + 2; // +2 for CRLF

            // Call progress callback at intervals
            if (progress && (bytes_received - last_callback_bytes) >= callback_interval)
            {
                progress_info_t info{bytes_received, expected_size, false};
                progress(info);
                last_callback_bytes = bytes_received;
            }
        }

        // Final progress callback
        if (progress)
        {
            progress_info_t info{bytes_received, bytes_received, false};
            progress(info);
        }

        co_return msg_str;
    }

    awaitable<std::string> top_impl(unsigned message_no, unsigned lines)
    {
        ensure_state(state_t::TRANSACTION, "TOP");
        std::string cmd;
        mailxx::detail::append_sv(cmd, "TOP ");
        mailxx::detail::append_uint(cmd, message_no);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_uint(cmd, lines);
        co_await send_command(cmd);
        (void)co_await read_ok_response("Fetching top lines failure.");

        std::string msg_str;
        while (true)
        {
            std::string line = co_await dlg_.read_line(use_awaitable);
            if (line == END_OF_DATA)
                break;
            if (!line.empty() && line[0] == '.')
                line.erase(0, 1);
            msg_str += line + "\r\n";
        }
        co_return msg_str;
    }

    awaitable<mailxx::message> retr_message_impl(unsigned message_no)
    {
        // Note: retr_impl already checks TRANSACTION state
        std::string msg_str = co_await retr_impl(message_no);
        mailxx::message msg;
        msg.parse(msg_str);
        co_return msg;
    }

    awaitable<void> dele_impl(unsigned long message_no)
    {
        ensure_state(state_t::TRANSACTION, "DELE");
        std::string cmd;
        mailxx::detail::append_sv(cmd, "DELE ");
        mailxx::detail::append_uint(cmd, message_no);
        co_await send_command(cmd);
        (void)co_await read_ok_response("Removing message failure.");
    }

    awaitable<void> rset_impl()
    {
        ensure_state(state_t::TRANSACTION, "RSET");
        co_await send_command("RSET");
        (void)co_await read_ok_response("Reset failure.");
    }

    awaitable<void> noop_impl()
    {
        ensure_state(state_t::TRANSACTION, "NOOP");
        co_await send_command("NOOP");
        (void)co_await read_ok_response("Noop failure.");
    }

    awaitable<void> quit_impl()
    {
        ensure_state_at_least(state_t::GREETING, "QUIT");
        co_await send_command("QUIT");
        (void)co_await read_ok_response("Quit failure.");
        state_ = state_t::UPDATE;
    }

    static void parse_capability_line(capabilities_t& caps, std::string_view line)
    {
        auto space = line.find(' ');
        std::string_view key = (space == std::string_view::npos) ? line : line.substr(0, space);

        if (key == "STLS")
        {
            caps.stls = true;
            return;
        }
        if (key == "UIDL")
        {
            caps.uidl = true;
            return;
        }
        if (key == "TOP")
        {
            caps.top = true;
            return;
        }
        if (key != "SASL" || space == std::string_view::npos)
            return;

        std::string_view rest = line.substr(space + 1);
        while (!rest.empty())
        {
            auto next = rest.find(' ');
            std::string_view token = (next == std::string_view::npos) ? rest : rest.substr(0, next);
            if (!token.empty())
                caps.sasl_mechanisms.emplace_back(token);
            if (next == std::string_view::npos)
                break;
            rest.remove_prefix(next + 1);
            while (!rest.empty() && rest.front() == ' ')
                rest.remove_prefix(1);
        }
    }

    awaitable<void> send_command(const std::string& command)
    {
        co_await dlg_.write_line(command, use_awaitable);
    }

    awaitable<std::string> read_ok_response(const std::string& error_message)
    {
        std::string line = co_await dlg_.read_line(use_awaitable);
        auto [status, msg] = parse_status(line);
        if (!is_ok(status))
            throw error(error_message, msg);
        co_return msg;
    }

    static const char* state_to_string(state_t state) noexcept
    {
        switch (state)
        {
            case state_t::DISCONNECTED:
                return "DISCONNECTED";
            case state_t::CONNECTED:
                return "CONNECTED";
            case state_t::GREETING:
                return "GREETING";
            case state_t::TRANSACTION:
                return "TRANSACTION";
            case state_t::UPDATE:
                return "UPDATE";
        }
        return "UNKNOWN";
    }

    static std::string state_details_exact(state_t expected, state_t actual)
    {
        std::string details = "expected ";
        details += state_to_string(expected);
        details += ", got ";
        details += state_to_string(actual);
        return details;
    }

    static std::string state_details_at_least(state_t expected, state_t actual)
    {
        std::string details = "expected at least ";
        details += state_to_string(expected);
        details += ", got ";
        details += state_to_string(actual);
        return details;
    }

    void ensure_state(state_t required, const char* operation) const
    {
        if (state_ != required)
            throw error(std::string(operation) + ": invalid state", state_details_exact(required, state_));
    }

    void ensure_state_at_least(state_t minimum, const char* operation) const
    {
        if (static_cast<int>(state_) < static_cast<int>(minimum))
            throw error(std::string(operation) + ": invalid state", state_details_at_least(minimum, state_));
    }

    options options_;
    dialog_type dlg_;
    mailxx::detail::async_mutex mutex_;
    std::string host_;
    session_snapshot session_snapshot_;
    std::string last_greeting_line_;
    std::string saved_host_;      ///< For auto-reconnection
    std::string saved_service_;   ///< For auto-reconnection
    uint16_t saved_port_{0};      ///< For auto-reconnection
    std::optional<capabilities_t> capabilities_;
    state_t state_{state_t::DISCONNECTED};
    reconnection_policy reconnection_policy_;  ///< Auto-reconnection configuration
};

using auth_method_t = pop3_base::auth_method_t;

} // namespace mailxx::pop3


#ifdef _MSC_VER
#pragma warning(pop)
#endif

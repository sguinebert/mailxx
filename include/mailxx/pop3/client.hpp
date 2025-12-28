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
#include <mailxx/net/tls_error.hpp>
#include <mailxx/mime/message.hpp>
#include <mailxx/detail/append.hpp>
#include <mailxx/detail/asio_error.hpp>
#include <mailxx/detail/async_mutex.hpp>
#include <mailxx/detail/log.hpp>
#include <mailxx/detail/oauth2_retry.hpp>
#include <mailxx/detail/sasl.hpp>
#include <mailxx/detail/sanitize.hpp>
#include <mailxx/detail/reconnection.hpp>
#include <mailxx/oauth2/token_source.hpp>
#include <mailxx/pop3/error.hpp>
#include <mailxx/pop3/error_mapping.hpp>
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

    [[nodiscard]] static result<std::tuple<std::string, std::string>> parse_status(
        const std::string& line, std::string_view command)
    {
        std::string::size_type pos = line.find(TOKEN_SEPARATOR_CHAR);
        std::string status = line.substr(0, pos);
        std::string rest = (pos != std::string::npos) ? line.substr(pos + 1) : "";
        if (status != OK_RESPONSE && status != ERR_RESPONSE)
            return fail<std::tuple<std::string, std::string>>(
                map_pop3_error(error_kind::response, status),
                "Unknown response status.",
                make_pop3_detail(command, line));
        return ok(std::make_tuple(status, rest));
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

    awaitable<result_void> connect(const std::string& host, uint16_t port)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await connect_impl(host, std::to_string(port), mailxx::net::tls_mode::none, nullptr, {});
    }

    awaitable<result_void> connect(const std::string& host, uint16_t port, mailxx::net::tls_mode mode,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await connect_impl(host, std::to_string(port), mode, tls_ctx, std::move(sni));
    }

    awaitable<result_void> connect(const std::string& host, const std::string& service, mailxx::net::tls_mode mode,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await connect_impl(host, service, mode, tls_ctx, std::move(sni));
    }

    awaitable<result_void> connect(std::string host, std::string service, mailxx::net::tls_mode mode,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await connect_impl(host, service, mode, tls_ctx, std::move(sni));
    }

    awaitable<result<std::string>> read_greeting()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await read_greeting_impl();
    }

    awaitable<result<capabilities_t>> capa()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await capa_impl();
    }

    awaitable<result_void> start_tls(ssl::context& context, std::string sni = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await start_tls_impl(context, std::move(sni));
    }

    awaitable<result_void> login(const std::string& username, const std::string& password)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await login_impl(username, password);
    }

    /**
     * Authenticate using SASL PLAIN mechanism.
     */
    awaitable<result_void> auth_plain(const std::string& username, const std::string& password)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await auth_plain_impl(username, password);
    }

    /**
     * Authenticate using XOAUTH2 mechanism for OAuth2.
     * Use this with Gmail, Outlook, and other OAuth2 providers.
     * 
     * @param username The email address
     * @param access_token The OAuth2 access token (not refresh token)
     */
    awaitable<result_void> auth_xoauth2(const std::string& username, const std::string& access_token)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await auth_xoauth2_impl(username, access_token);
    }

    /**
     * Authenticate using APOP challenge-response.
     */
    awaitable<result_void> apop(const std::string& username, const std::string& password)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await apop_impl(username, password);
    }

    /**
     * Authenticate using the specified method.
     */
    awaitable<result_void> authenticate(const std::string& username, const std::string& credential, auth_method_t method)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await authenticate_impl(username, credential, method);
    }

    /**
     * Authenticate using OAuth2 access token.
     * Convenience method for OAuth2 authentication.
     */
    awaitable<result_void> authenticate_oauth2(const std::string& username, const std::string& access_token)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await auth_xoauth2_impl(username, access_token);
    }

    awaitable<result_void> authenticate_oauth2(const std::string& username, mailxx::oauth2::token_source& source)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        auto auth = [&](const std::string& token) -> awaitable<result_void>
        {
            co_return co_await auth_xoauth2_impl(username, token);
        };
        auto should_retry = [](const error_info& err)
        {
            return err.code == errc::pop3_auth_failed;
        };
        co_return co_await mailxx::detail::oauth2_auth_with_retry(source, auth, should_retry);
    }

    awaitable<result<mailbox_stat_t>> stat()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await stat_impl();
    }

    awaitable<result<message_list_t>> list()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await list_impl();
    }

    awaitable<result<message_list_t>> list(unsigned message_no)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await list_impl(message_no);
    }

    awaitable<result<uidl_list_t>> uidl(unsigned message_no = 0)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await uidl_impl(message_no);
    }

    awaitable<result<std::string>> retr(unsigned long message_no)
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
    awaitable<result<std::string>> retr_with_progress(
        unsigned long message_no,
        unsigned long expected_size,
        progress_callback_t progress)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await retr_with_progress_impl(message_no, expected_size, std::move(progress));
    }

    awaitable<result<std::string>> top(unsigned message_no, unsigned lines)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await top_impl(message_no, lines);
    }

    awaitable<result<mailxx::message>> retr_message(unsigned message_no)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await retr_message_impl(message_no);
    }

    awaitable<result_void> dele(unsigned long message_no)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await dele_impl(message_no);
    }

    awaitable<result_void> rset()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await rset_impl();
    }

    awaitable<result_void> noop()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await noop_impl();
    }

    awaitable<result_void> quit()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await quit_impl();
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
    awaitable<result<std::string>> retr_with_reconnection(
        unsigned long message_no,
        const std::pair<std::string, std::string>& /*credentials*/)
    {
        if (!reconnection_policy_.enabled)
            co_return co_await retr(message_no);
        
        unsigned int attempt = 0;
        result<std::string> last_error = fail<std::string>(
            errc::net_connect_failed, "disconnected");
        
        while (true)
        {
            auto res = co_await retr(message_no);
            if (res)
                co_return res;

            last_error = std::move(res);
            const error_info err = last_error.error();

            if (!is_connection_error(err))
                co_return last_error;

            const session_snapshot snapshot = session_snapshot_;
            auto ready = ensure_reconnect_ready(snapshot);
            if (!ready)
                co_return fail<std::string>(ready.error());
            
            ++attempt;
            
            if (reconnection_policy_.max_attempts > 0 && 
                attempt > reconnection_policy_.max_attempts)
            {
                if (reconnection_policy_.on_reconnect_failed)
                {
                    std::string msg = err.message.empty() ? std::string(mailxx::to_string(err.code)) : err.message;
                    if (!err.detail.empty())
                    {
                        if (!msg.empty())
                            msg += " - ";
                        msg += err.detail;
                    }
                    std::runtime_error ex(msg);
                    reconnection_policy_.on_reconnect_failed(ex);
                }
                co_return last_error;
            }
            
            auto delay = reconnection_policy_.calculate_delay(attempt);
            
            if (reconnection_policy_.on_reconnect_attempt)
            {
                if (!reconnection_policy_.on_reconnect_attempt(attempt, delay))
                    co_return last_error;
            }
            
            // Wait before reconnecting
            steady_timer timer(dlg_.stream().get_executor());
            timer.expires_after(delay);
            MAILXX_TRY_CO_AWAIT(mailxx::to_result(timer.async_wait(use_nothrow_awaitable)));
            
            // Try to reconnect
            auto reconnect_res = co_await reconnect_with_snapshot(snapshot);
            if (!reconnect_res)
            {
                last_error = fail<std::string>(reconnect_res.error());
                if (!is_connection_error(reconnect_res.error()))
                    co_return last_error;
                continue;
            }
            
            if (reconnection_policy_.on_reconnect_success)
                reconnection_policy_.on_reconnect_success();
        }
    }

private:
    /// Check if an exception indicates a connection error
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

    [[nodiscard]] static result_void ensure_reconnect_ready(const session_snapshot& snapshot)
    {
        if (!snapshot.has_connection())
            return fail_void(map_pop3_error(error_kind::invalid_state),
                "Reconnection failure: no session stored.",
                make_pop3_detail("RECONNECT", "no session stored"));
        if (!snapshot.has_auth())
            return fail_void(map_pop3_error(error_kind::invalid_state),
                "Reconnection failure: no auth stored.",
                make_pop3_detail("RECONNECT", "no auth stored"));
        if (!snapshot.secret.has_value())
            return fail_void(map_pop3_error(error_kind::invalid_state),
                "Reconnection failure: no creds stored.",
                make_pop3_detail("RECONNECT", "no creds stored"));
        if (snapshot.tls_mode != mailxx::net::tls_mode::none && snapshot.tls_ctx == nullptr)
            return fail_void(map_pop3_error(error_kind::invalid_state),
                "Reconnection failure: no TLS context stored.",
                make_pop3_detail("RECONNECT", "no tls context stored"));
        return ok();
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

    static result<std::string> extract_apop_challenge(std::string_view greeting_line)
    {
        const auto start = greeting_line.find('<');
        if (start == std::string_view::npos)
            return fail<std::string>(map_pop3_error(error_kind::invalid_state),
                "APOP challenge missing.",
                make_pop3_detail("APOP", greeting_line));
        const auto end = greeting_line.find('>', start + 1);
        if (end == std::string_view::npos || end <= start)
            return fail<std::string>(map_pop3_error(error_kind::invalid_state),
                "APOP challenge missing.",
                make_pop3_detail("APOP", greeting_line));
        return ok(std::string(greeting_line.substr(start, end - start + 1)));
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

    awaitable<result_void> reconnect_with_snapshot(const session_snapshot& snapshot)
    {
        state_ = state_t::DISCONNECTED;

        MAILXX_TRY_CO_AWAIT(connect_impl(snapshot.host, snapshot.service, snapshot.tls_mode, snapshot.tls_ctx, snapshot.sni));

        if (state_ == state_t::CONNECTED)
            MAILXX_TRY_CO_AWAIT(read_greeting_impl());

        if (snapshot.tls_mode == mailxx::net::tls_mode::starttls && !options_.auto_starttls)
        {
            if (snapshot.tls_ctx == nullptr)
                co_return fail_void(map_pop3_error(error_kind::invalid_state),
                    "TLS context is required.",
                    make_pop3_detail("STLS", "STLS needs a context."));
            MAILXX_TRY_CO_AWAIT(capa_impl());
            MAILXX_TRY_CO_AWAIT(start_tls_impl(*snapshot.tls_ctx, snapshot.sni));
        }

        co_return co_await reauthenticate(snapshot);
    }

    awaitable<result_void> reauthenticate(const session_snapshot& snapshot)
    {
        const std::string& secret = snapshot.secret.value();
        switch (snapshot.auth)
        {
            case session_snapshot::auth_mechanism::user_pass:
                MAILXX_TRY_CO_AWAIT(login_impl(snapshot.username, secret));
                break;
            case session_snapshot::auth_mechanism::sasl_plain:
                MAILXX_TRY_CO_AWAIT(auth_plain_impl(snapshot.username, secret));
                break;
            case session_snapshot::auth_mechanism::xoauth2:
                MAILXX_TRY_CO_AWAIT(auth_xoauth2_impl(snapshot.username, secret));
                break;
            case session_snapshot::auth_mechanism::apop:
                MAILXX_TRY_CO_AWAIT(apop_impl(snapshot.username, secret));
                break;
            case session_snapshot::auth_mechanism::none:
                co_return fail_void(map_pop3_error(error_kind::invalid_state),
                    "Reconnection failure: no auth stored.",
                    make_pop3_detail("RECONNECT", "no auth stored"));
        }
        co_return ok();
    }

    result<std::string> resolve_sni(std::string_view host, std::string sni) const
    {
        if (sni.empty())
            sni.assign(host.begin(), host.end());
        auto res = validate_no_crlf_or_nul(sni, "sni");
        if (!res)
            return mailxx::fail<std::string>(res.error());
        return ok(std::move(sni));
    }

    awaitable<result_void> upgrade_to_tls(ssl::context& context, std::string sni)
    {
        dialog_type& dlg = dlg_;
        const std::size_t max_len = dlg.max_line_length();
        const auto timeout = dlg.timeout();

        mailxx::net::upgradable_stream stream = std::move(dlg.stream());
        auto tls_res = co_await stream.start_tls(context, std::move(sni), options_.tls);
        if (!tls_res)
            co_return mailxx::fail<void>(std::move(tls_res).error());
        dlg_ = dialog_type(std::move(stream), max_len, timeout);
        configure_trace();
        co_return ok();
    }

    awaitable<result_void> connect_impl(const std::string& host, const std::string& service,
        mailxx::net::tls_mode mode = mailxx::net::tls_mode::none,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        MAILXX_TRY(ensure_state(state_t::DISCONNECTED, "CONNECT"));
        MAILXX_TRY(validate_no_crlf_or_nul(host, "host"));
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
        MAILXX_TRY_ASSIGN(auto endpoints, mailxx::to_result(
            co_await resolver.async_resolve(host, service, use_nothrow_awaitable),
            mailxx::net::io_stage::resolve));

        mailxx::net::upgradable_stream stream(executor);
        MAILXX_TRY(mailxx::to_result(
            co_await async_connect(stream.lowest_layer(), endpoints, use_nothrow_awaitable),
            mailxx::net::io_stage::connect));
        
        if (mode == mailxx::net::tls_mode::implicit)
        {
            if (tls_ctx == nullptr)
                co_return fail_void(map_pop3_error(error_kind::invalid_state),
                    "TLS context is required.",
                    make_pop3_detail("CONNECT", "Implicit TLS needs a context."));
            std::string resolved_sni = MAILXX_CO_TRY(resolve_sni(host, std::move(sni)));
            remember_tls(mailxx::net::tls_mode::implicit, tls_ctx, resolved_sni);
            auto tls_res = co_await stream.start_tls(*tls_ctx, std::move(resolved_sni), options_.tls);
            if (!tls_res)
                co_return mailxx::fail<void>(std::move(tls_res).error());
        }

        dlg_ = dialog_type(std::move(stream), options_.max_line_length, options_.timeout);
        configure_trace();
        state_ = state_t::CONNECTED;

        if (mode == mailxx::net::tls_mode::starttls && options_.auto_starttls)
        {
            if (tls_ctx == nullptr)
                co_return fail_void(map_pop3_error(error_kind::invalid_state),
                    "TLS context is required.",
                    make_pop3_detail("STLS", "STLS needs a context."));
            MAILXX_TRY_CO_AWAIT(read_greeting_impl());
            MAILXX_TRY_CO_AWAIT(capa_impl());
            MAILXX_TRY_CO_AWAIT(start_tls_impl(*tls_ctx, std::move(sni)));
            MAILXX_TRY_CO_AWAIT(capa_impl());
        }
        co_return ok();
    }

    awaitable<result<std::string>> read_greeting_impl()
    {
        MAILXX_TRY(ensure_state(state_t::CONNECTED, "READ_GREETING"));
        std::string line = MAILXX_CO_TRY(co_await dlg_.read_line_r());
        last_greeting_line_ = line;
        auto [status, msg] = MAILXX_CO_TRY(parse_status(line, "GREETING"));
        if (!is_ok(status))
            co_return fail<std::string>(map_pop3_error(error_kind::response, status),
                "Connection to server failure.",
                make_pop3_detail("GREETING", line));
        state_ = state_t::GREETING;
        co_return ok(msg);
    }

    awaitable<result<capabilities_t>> capa_impl()
    {
        MAILXX_TRY(ensure_state_at_least(state_t::GREETING, "CAPA"));
        MAILXX_TRY_CO_AWAIT(send_command("CAPA"));
        MAILXX_TRY_CO_AWAIT(read_ok_response("Capabilities failure.", "CAPA"));

        capabilities_t caps;
        while (true)
        {
            std::string line = MAILXX_CO_TRY(co_await dlg_.read_line_r());
            if (line == END_OF_DATA)
                break;
            if (!line.empty() && line[0] == '.')
                line.erase(0, 1);
            caps.raw_lines.push_back(line);
            parse_capability_line(caps, line);
        }
        capabilities_ = caps;
        co_return ok(caps);
    }

    awaitable<result_void> start_tls_impl(ssl::context& context, std::string sni)
    {
        MAILXX_TRY(ensure_state(state_t::GREETING, "STLS"));
        // Require CAPA to be called first to avoid optimistic STLS.
        if (!capabilities_.has_value())
            co_return fail_void(map_pop3_error(error_kind::invalid_state),
                "STLS capability unknown; call CAPA first.",
                make_pop3_detail("STLS"));
        if (!capabilities_->stls)
            co_return fail_void(map_pop3_error(error_kind::invalid_state),
                "STLS not supported.",
                make_pop3_detail("STLS"));

        MAILXX_TRY_CO_AWAIT(send_command("STLS"));
        std::string line = MAILXX_CO_TRY(co_await dlg_.read_line_r());
        auto [status, msg] = MAILXX_CO_TRY(parse_status(line, "STLS"));
        if (!is_ok(status))
            co_return fail_void(map_pop3_error(error_kind::response, status),
                "STARTTLS failure.",
                make_pop3_detail("STLS", line));

        std::string resolved_sni = MAILXX_CO_TRY(resolve_sni(host_, std::move(sni)));
        remember_tls(mailxx::net::tls_mode::starttls, &context, resolved_sni);
        MAILXX_TRY_CO_AWAIT(upgrade_to_tls(context, std::move(resolved_sni)));
        co_return ok();
    }

    awaitable<result_void> login_impl(const std::string& username, const std::string& password)
    {
        MAILXX_TRY(ensure_state(state_t::GREETING, "LOGIN"));
        MAILXX_TRY(enforce_auth_tls_policy());
        MAILXX_TRY(validate_no_crlf_or_nul(username, "username"));
        MAILXX_TRY(validate_no_crlf_or_nul(password, "password"));
        MAILXX_TRY_CO_AWAIT(send_command("USER " + username));
        MAILXX_TRY_CO_AWAIT(read_ok_response("Username rejection.", "USER", error_kind::auth));

        MAILXX_TRY_CO_AWAIT(send_command("PASS " + password));
        MAILXX_TRY_CO_AWAIT(read_ok_response("Password rejection.", "PASS", error_kind::auth));
        state_ = state_t::TRANSACTION;
        remember_auth(session_snapshot::auth_mechanism::user_pass, username, password);
        co_return ok();
    }

    awaitable<result_void> auth_plain_impl(const std::string& username, const std::string& password)
    {
        MAILXX_TRY(ensure_state(state_t::GREETING, "AUTH PLAIN"));
        MAILXX_TRY(enforce_auth_tls_policy());
        MAILXX_TRY(validate_no_crlf_or_nul(username, "username"));
        MAILXX_TRY(validate_no_crlf_or_nul(password, "password"));
        std::string encoded;
        MAILXX_TRY_ASSIGN(encoded, sasl::encode_plain(username, password));
        
        MAILXX_TRY_CO_AWAIT(send_command("AUTH PLAIN"));
        std::string line = MAILXX_CO_TRY(co_await dlg_.read_line_r());
        
        if (!line.empty() && line[0] == '+')
        {
            MAILXX_TRY_CO_AWAIT(send_command(encoded));
            MAILXX_TRY_CO_AWAIT(read_ok_response("PLAIN authentication failure.", "AUTH PLAIN", error_kind::auth));
        }
        else
        {
            auto [status, msg] = MAILXX_CO_TRY(parse_status(line, "AUTH PLAIN"));
            if (!is_ok(status))
                co_return fail_void(map_pop3_error(error_kind::auth),
                    "PLAIN authentication failure.",
                    make_pop3_detail("AUTH PLAIN", line));
            (void)msg;
        }
        state_ = state_t::TRANSACTION;
        remember_auth(session_snapshot::auth_mechanism::sasl_plain, username, password);
        co_return ok();
    }

    awaitable<result_void> auth_xoauth2_impl(const std::string& username, const std::string& access_token)
    {
        MAILXX_TRY(ensure_state(state_t::GREETING, "AUTH XOAUTH2"));
        MAILXX_TRY(enforce_auth_tls_policy());
        MAILXX_TRY(validate_no_crlf_or_nul(username, "username"));
        MAILXX_TRY(validate_no_crlf_or_nul(access_token, "access_token"));
        std::string encoded;
        MAILXX_TRY_ASSIGN(encoded, sasl::encode_xoauth2(username, access_token));
        
        MAILXX_TRY_CO_AWAIT(send_command("AUTH XOAUTH2 " + encoded));
        std::string line = MAILXX_CO_TRY(co_await dlg_.read_line_r());
        
        if (!line.empty() && line[0] == '+')
        {
            MAILXX_TRY_CO_AWAIT(send_command(""));
            MAILXX_TRY_CO_AWAIT(read_ok_response("XOAUTH2 authentication failure.", "AUTH XOAUTH2", error_kind::auth));
        }
        else
        {
            auto [status, msg] = MAILXX_CO_TRY(parse_status(line, "AUTH XOAUTH2"));
            if (!is_ok(status))
                co_return fail_void(map_pop3_error(error_kind::auth),
                    "XOAUTH2 authentication failure.",
                    make_pop3_detail("AUTH XOAUTH2", line));
            (void)msg;
        }
        state_ = state_t::TRANSACTION;
        remember_auth(session_snapshot::auth_mechanism::xoauth2, username, access_token);
        co_return ok();
    }

    awaitable<result_void> apop_impl(const std::string& username, const std::string& password)
    {
        MAILXX_TRY(ensure_state(state_t::GREETING, "APOP"));
        MAILXX_TRY(validate_no_crlf_or_nul(username, "username"));
        MAILXX_TRY(validate_no_crlf_or_nul(password, "password"));

        if (last_greeting_line_.empty())
            co_return fail_void(map_pop3_error(error_kind::invalid_state),
                "APOP challenge missing.",
                make_pop3_detail("APOP"));

        const std::string challenge = MAILXX_CO_TRY(extract_apop_challenge(last_greeting_line_));
        const std::string digest = md5_hex(challenge + password);

        std::string cmd;
        mailxx::detail::append_sv(cmd, "APOP ");
        mailxx::detail::append_sv(cmd, username);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, digest);
        MAILXX_TRY_CO_AWAIT(send_command(cmd));
        MAILXX_TRY_CO_AWAIT(read_ok_response("APOP authentication failure.", "APOP", error_kind::auth));
        state_ = state_t::TRANSACTION;
        remember_auth(session_snapshot::auth_mechanism::apop, username, password);
        co_return ok();
    }

    awaitable<result_void> authenticate_impl(const std::string& username, const std::string& credential, auth_method_t method)
    {
        switch (method)
        {
            case auth_method_t::LOGIN:
                MAILXX_TRY_CO_AWAIT(login_impl(username, credential));
                break;
            case auth_method_t::PLAIN:
                MAILXX_TRY_CO_AWAIT(auth_plain_impl(username, credential));
                break;
            case auth_method_t::XOAUTH2:
                MAILXX_TRY_CO_AWAIT(auth_xoauth2_impl(username, credential));
                break;
            case auth_method_t::APOP:
                MAILXX_TRY_CO_AWAIT(apop_impl(username, credential));
                break;
        }
        co_return ok();
    }

    result_void enforce_auth_tls_policy()
    {
        if (dlg_.stream().is_tls() || !options_.require_tls_for_auth)
            return ok();
        if (options_.allow_cleartext_auth)
        {
            MAILXX_WARN("AUTH without TLS allowed by configuration.");
            return ok();
        }
        return fail_void(map_pop3_error(error_kind::invalid_state),
            "TLS required for authentication; call start_tls() or use tls_mode::implicit",
            make_pop3_detail("AUTH", "tls required"));
    }

    awaitable<result<mailbox_stat_t>> stat_impl()
    {
        MAILXX_TRY(ensure_state(state_t::TRANSACTION, "STAT"));
        MAILXX_TRY_CO_AWAIT(send_command("STAT"));
        std::string msg = MAILXX_CO_TRY(co_await read_ok_response("Reading statistics failure.", "STAT"));
        mailbox_stat_t stat;
        std::istringstream iss(msg);
        if (!(iss >> stat.messages_no >> stat.mailbox_size))
            co_return fail<mailbox_stat_t>(map_pop3_error(error_kind::response),
                "Parser failure.",
                make_pop3_detail("STAT", msg));
        co_return ok(stat);
    }

    awaitable<result<message_list_t>> list_impl()
    {
        MAILXX_TRY(ensure_state(state_t::TRANSACTION, "LIST"));
        MAILXX_TRY_CO_AWAIT(send_command("LIST"));
        MAILXX_TRY_CO_AWAIT(read_ok_response("Listing all messages failure.", "LIST"));

        message_list_t msg_list;
        while (true)
        {
            std::string line = MAILXX_CO_TRY(co_await dlg_.read_line_r());
            if (line == END_OF_DATA)
                break;
            if (!line.empty() && line[0] == '.')
                line.erase(0, 1);
            std::istringstream iss(line);
            unsigned num = 0;
            unsigned long size = 0;
            if (!(iss >> num >> size))
                co_return fail<message_list_t>(map_pop3_error(error_kind::response),
                    "LIST parse failure.",
                    make_pop3_detail("LIST", line));
            msg_list[num] = size;
        }
        co_return ok(msg_list);
    }

    awaitable<result<message_list_t>> list_impl(unsigned message_no)
    {
        MAILXX_TRY(ensure_state(state_t::TRANSACTION, "LIST"));
        std::string cmd;
        mailxx::detail::append_sv(cmd, "LIST ");
        mailxx::detail::append_uint(cmd, message_no);
        MAILXX_TRY_CO_AWAIT(send_command(cmd));
        std::string msg = MAILXX_CO_TRY(co_await read_ok_response("Listing message failure.", "LIST"));

        message_list_t msg_list;
        std::istringstream iss(msg);
        unsigned num = 0;
        unsigned long size = 0;
        if (!(iss >> num >> size))
            co_return fail<message_list_t>(map_pop3_error(error_kind::response),
                "LIST parse failure.",
                make_pop3_detail("LIST", msg));
        msg_list[num] = size;
        co_return ok(msg_list);
    }

    awaitable<result<uidl_list_t>> uidl_impl(unsigned message_no)
    {
        MAILXX_TRY(ensure_state(state_t::TRANSACTION, "UIDL"));
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
        MAILXX_TRY_CO_AWAIT(send_command(cmd));
        std::string msg = MAILXX_CO_TRY(co_await read_ok_response("Unique ID listing failure.", "UIDL"));

        uidl_list_t uidl_list;
        if (message_no != 0)
        {
            std::istringstream iss(msg);
            unsigned num = 0;
            std::string uidl;
            if (!(iss >> num >> uidl))
                co_return fail<uidl_list_t>(map_pop3_error(error_kind::response),
                    "UIDL parse failure.",
                    make_pop3_detail("UIDL", msg));
            uidl_list[num] = std::move(uidl);
            co_return ok(uidl_list);
        }

        while (true)
        {
            std::string line = MAILXX_CO_TRY(co_await dlg_.read_line_r());
            if (line == END_OF_DATA)
                break;
            if (!line.empty() && line[0] == '.')
                line.erase(0, 1);
            std::istringstream iss(line);
            unsigned num = 0;
            std::string uidl;
            if (!(iss >> num >> uidl))
                co_return fail<uidl_list_t>(map_pop3_error(error_kind::response),
                    "UIDL parse failure.",
                    make_pop3_detail("UIDL", line));
            uidl_list[num] = std::move(uidl);
        }
        co_return ok(uidl_list);
    }

    awaitable<result<std::string>> retr_impl(unsigned long message_no)
    {
        MAILXX_TRY(ensure_state(state_t::TRANSACTION, "RETR"));
        std::string cmd;
        mailxx::detail::append_sv(cmd, "RETR ");
        mailxx::detail::append_uint(cmd, message_no);
        MAILXX_TRY_CO_AWAIT(send_command(cmd));
        MAILXX_TRY_CO_AWAIT(read_ok_response("Fetching message failure.", "RETR"));

        std::string msg_str;
        while (true)
        {
            std::string line = MAILXX_CO_TRY(co_await dlg_.read_line_r());
            if (line == END_OF_DATA)
                break;
            if (!line.empty() && line[0] == '.')
                line.erase(0, 1);
            msg_str += line + "\r\n";
        }
        co_return ok(msg_str);
    }

    awaitable<result<std::string>> retr_with_progress_impl(
        unsigned long message_no,
        unsigned long expected_size,
        progress_callback_t progress)
    {
        MAILXX_TRY(ensure_state(state_t::TRANSACTION, "RETR"));
        std::string cmd;
        mailxx::detail::append_sv(cmd, "RETR ");
        mailxx::detail::append_uint(cmd, message_no);
        MAILXX_TRY_CO_AWAIT(send_command(cmd));
        MAILXX_TRY_CO_AWAIT(read_ok_response("Fetching message failure.", "RETR"));

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
            std::string line = MAILXX_CO_TRY(co_await dlg_.read_line_r());
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

        co_return ok(msg_str);
    }

    awaitable<result<std::string>> top_impl(unsigned message_no, unsigned lines)
    {
        MAILXX_TRY(ensure_state(state_t::TRANSACTION, "TOP"));
        std::string cmd;
        mailxx::detail::append_sv(cmd, "TOP ");
        mailxx::detail::append_uint(cmd, message_no);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_uint(cmd, lines);
        MAILXX_TRY_CO_AWAIT(send_command(cmd));
        MAILXX_TRY_CO_AWAIT(read_ok_response("Fetching top lines failure.", "TOP"));

        std::string msg_str;
        while (true)
        {
            std::string line = MAILXX_CO_TRY(co_await dlg_.read_line_r());
            if (line == END_OF_DATA)
                break;
            if (!line.empty() && line[0] == '.')
                line.erase(0, 1);
            msg_str += line + "\r\n";
        }
        co_return ok(msg_str);
    }

    awaitable<result<mailxx::message>> retr_message_impl(unsigned message_no)
    {
        // Note: retr_impl already checks TRANSACTION state
        std::string msg_str = MAILXX_CO_TRY(co_await retr_impl(message_no));
        mailxx::message msg;
        MAILXX_TRY_ASSIGN(msg, mailxx::message::parse_result(msg_str));
        co_return ok(std::move(msg));
    }

    awaitable<result_void> dele_impl(unsigned long message_no)
    {
        MAILXX_TRY(ensure_state(state_t::TRANSACTION, "DELE"));
        std::string cmd;
        mailxx::detail::append_sv(cmd, "DELE ");
        mailxx::detail::append_uint(cmd, message_no);
        MAILXX_TRY_CO_AWAIT(send_command(cmd));
        MAILXX_TRY_CO_AWAIT(read_ok_response("Removing message failure.", "DELE"));
        co_return ok();
    }

    awaitable<result_void> rset_impl()
    {
        MAILXX_TRY(ensure_state(state_t::TRANSACTION, "RSET"));
        MAILXX_TRY_CO_AWAIT(send_command("RSET"));
        MAILXX_TRY_CO_AWAIT(read_ok_response("Reset failure.", "RSET"));
        co_return ok();
    }

    awaitable<result_void> noop_impl()
    {
        MAILXX_TRY(ensure_state(state_t::TRANSACTION, "NOOP"));
        MAILXX_TRY_CO_AWAIT(send_command("NOOP"));
        MAILXX_TRY_CO_AWAIT(read_ok_response("Noop failure.", "NOOP"));
        co_return ok();
    }

    awaitable<result_void> quit_impl()
    {
        MAILXX_TRY(ensure_state_at_least(state_t::GREETING, "QUIT"));
        MAILXX_TRY_CO_AWAIT(send_command("QUIT"));
        MAILXX_TRY_CO_AWAIT(read_ok_response("Quit failure.", "QUIT"));
        state_ = state_t::UPDATE;
        co_return ok();
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

    awaitable<result_void> send_command(const std::string& command)
    {
        co_return co_await dlg_.write_line_r(command);
    }

    awaitable<result<std::string>> read_ok_response(
        const std::string& error_message,
        std::string_view command,
        error_kind kind = error_kind::response)
    {
        std::string line = MAILXX_CO_TRY(co_await dlg_.read_line_r());
        auto [status, msg] = MAILXX_CO_TRY(parse_status(line, command));
        if (!is_ok(status))
            co_return fail<std::string>(map_pop3_error(kind, status), error_message, make_pop3_detail(command, line));
        co_return ok(msg);
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

    [[nodiscard]] static result_void validate_no_crlf_or_nul(std::string_view value, const char* field)
    {
        if (!mailxx::detail::contains_crlf_or_nul(value))
            return ok();

        std::string message = "Invalid ";
        message += field ? field : "value";
        message += ": CR/LF or NUL not allowed.";
        std::string_view command = field ? std::string_view(field) : std::string_view("input");
        return fail_void(map_pop3_error(error_kind::invalid_state),
            std::move(message),
            make_pop3_detail(command));
    }

    [[nodiscard]] result_void ensure_state(state_t required, const char* operation) const
    {
        if (state_ != required)
            return fail_void(map_pop3_error(error_kind::invalid_state),
                std::string(operation) + ": invalid state",
                make_pop3_detail(operation, state_details_exact(required, state_)));
        return ok();
    }

    [[nodiscard]] result_void ensure_state_at_least(state_t minimum, const char* operation) const
    {
        if (static_cast<int>(state_) < static_cast<int>(minimum))
            return fail_void(map_pop3_error(error_kind::invalid_state),
                std::string(operation) + ": invalid state",
                make_pop3_detail(operation, state_details_at_least(minimum, state_)));
        return ok();
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

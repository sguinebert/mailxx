/*

imap/client.hpp
---------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once

#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/append.hpp>
#include <mailxx/detail/auth_policy.hpp>
#include <mailxx/detail/async_mutex.hpp>
#include <mailxx/detail/log.hpp>
#include <mailxx/detail/redact.hpp>
#include <mailxx/detail/sasl.hpp>
#include <mailxx/detail/sanitize.hpp>
#include <mailxx/imap/error.hpp>
#include <mailxx/imap/types.hpp>
#include <mailxx/mime/message.hpp>
#include <mailxx/net/dialog.hpp>
#include <mailxx/net/tls_mode.hpp>
#include <mailxx/net/upgradable_stream.hpp>

namespace mailxx::imap
{

using mailxx::asio::any_io_executor;
using mailxx::asio::awaitable;
using mailxx::asio::io_context;
using mailxx::asio::use_awaitable;
using mailxx::asio::async_connect;
using mailxx::asio::tcp;
using mailxx::asio::buffer;
namespace ssl = mailxx::asio::ssl;

class client
{
public:
    using executor_type = any_io_executor;
    using dialog_type = mailxx::net::dialog<mailxx::net::upgradable_stream>;

    class idle_session
    {
    public:
        idle_session() = default;
        idle_session(const idle_session&) = delete;
        idle_session& operator=(const idle_session&) = delete;

        idle_session(idle_session&& other) noexcept
            : owner_(other.owner_),
              lock_(std::move(other.lock_)),
              tag_(std::move(other.tag_)),
              active_(other.active_)
        {
            other.owner_ = nullptr;
            other.active_ = false;
            other.tag_.clear();
        }

        idle_session& operator=(idle_session&& other) noexcept
        {
            if (this != &other)
            {
                owner_ = other.owner_;
                lock_ = std::move(other.lock_);
                tag_ = std::move(other.tag_);
                active_ = other.active_;
                other.owner_ = nullptr;
                other.active_ = false;
                other.tag_.clear();
            }
            return *this;
        }

        ~idle_session() = default;

        awaitable<std::string> idle_read()
        {
            if (!active_ || owner_ == nullptr)
                throw error("IDLE is not active.", "");
            co_return co_await owner_->dialog().read_line(use_awaitable);
        }

        awaitable<response> idle_stop()
        {
            if (!active_ || owner_ == nullptr)
                throw error("IDLE is not active.", "");

            co_await owner_->dialog().write_line("DONE", use_awaitable);

            response resp;
            resp.tag = tag_;

            while (true)
            {
                std::string line = co_await owner_->dialog().read_line(use_awaitable);
                client::handle_line(resp, line, tag_);

                std::size_t literal_size = 0;
                if (client::extract_literal_size(line, literal_size))
                {
                    resp.literals.push_back(
                        co_await owner_->dialog().read_exactly(literal_size, use_awaitable));
                }

                if (client::is_tagged_line(line, tag_))
                    break;
            }

            active_ = false;
            owner_ = nullptr;
            lock_ = mailxx::detail::async_mutex::scoped_lock();
            co_return resp;
        }

    private:
        friend class client;

        idle_session(client* owner,
            mailxx::detail::async_mutex::scoped_lock lock,
            std::string tag,
            bool active)
            : owner_(owner),
              lock_(std::move(lock)),
              tag_(std::move(tag)),
              active_(active)
        {
        }

        client* owner_{nullptr};
        mailxx::detail::async_mutex::scoped_lock lock_;
        std::string tag_;
        bool active_{false};
    };

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

    awaitable<response> read_greeting()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await read_greeting_impl();
    }

    awaitable<response> command(std::string_view cmd)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await command_impl(cmd);
    }

    awaitable<response> capability()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await capability_impl();
    }

    awaitable<response> login(std::string_view username, std::string_view password)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await login_impl(username, password);
    }

    awaitable<response> authenticate(credentials cred, auth_method method)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await authenticate_impl(std::move(cred), method);
    }

    awaitable<response> logout()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await command_impl("LOGOUT");
    }

    awaitable<response> noop()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await command_impl("NOOP");
    }

    awaitable<response> append(std::string_view mailbox, const mailxx::message& msg,
        std::string_view flags = {}, std::string_view date_time = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        std::string payload;
        msg.format(payload);
        co_return co_await append_raw_impl(mailbox, payload, flags, date_time);
    }

    awaitable<response> append_raw(std::string_view mailbox, std::string_view data,
        std::string_view flags = {}, std::string_view date_time = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await append_raw_impl(mailbox, data, flags, date_time);
    }

    awaitable<std::pair<response, std::vector<mailbox_folder>>> list(std::string_view reference, std::string_view pattern)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        mailxx::detail::ensure_no_crlf_or_nul(reference, "reference");
        mailxx::detail::ensure_no_crlf_or_nul(pattern, "pattern");

        const std::string ref = mailxx::imap::to_mailbox(reference);
        const std::string pat = mailxx::imap::to_mailbox(pattern);

        std::string cmd;
        mailxx::detail::append_sv(cmd, "LIST");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, ref);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, pat);

        response resp = co_await command_impl(cmd);
        std::vector<mailbox_folder> folders;
        folders.reserve(resp.untagged_lines.size());
        for (const auto& line : resp.untagged_lines)
        {
            mailbox_folder folder;
            if (parse_list_line(line, folder))
                folders.push_back(std::move(folder));
        }

        co_return std::make_pair(std::move(resp), std::move(folders));
    }

    awaitable<std::pair<response, mailbox_stat>> select(std::string_view mailbox)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        mailxx::detail::ensure_no_crlf_or_nul(mailbox, "mailbox");

        const std::string box = mailxx::imap::to_mailbox(mailbox);
        std::string cmd;
        mailxx::detail::append_sv(cmd, "SELECT");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, box);

        response resp = co_await command_impl(cmd);
        mailbox_stat stat;
        for (const auto& line : resp.untagged_lines)
            parse_mailbox_stat(line, stat);
        co_return std::make_pair(std::move(resp), stat);
    }

    awaitable<std::pair<response, mailbox_stat>> examine(std::string_view mailbox)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        mailxx::detail::ensure_no_crlf_or_nul(mailbox, "mailbox");

        const std::string box = mailxx::imap::to_mailbox(mailbox);
        std::string cmd;
        mailxx::detail::append_sv(cmd, "EXAMINE");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, box);

        response resp = co_await command_impl(cmd);
        mailbox_stat stat;
        for (const auto& line : resp.untagged_lines)
            parse_mailbox_stat(line, stat);
        co_return std::make_pair(std::move(resp), stat);
    }

    awaitable<std::pair<response, std::vector<std::uint32_t>>> search(std::string_view criteria, bool uid = false)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        mailxx::detail::ensure_no_crlf_or_nul(criteria, "criteria");

        std::string cmd;
        if (uid)
            mailxx::detail::append_sv(cmd, "UID SEARCH");
        else
            mailxx::detail::append_sv(cmd, "SEARCH");
        if (!criteria.empty())
        {
            mailxx::detail::append_space(cmd);
            mailxx::detail::append_sv(cmd, criteria);
        }

        response resp = co_await command_impl(cmd);
        std::vector<std::uint32_t> ids;
        for (const auto& line : resp.untagged_lines)
        {
            auto parsed = parse_search_ids(line);
            if (!parsed.empty())
                ids.insert(ids.end(), parsed.begin(), parsed.end());
        }

        co_return std::make_pair(std::move(resp), std::move(ids));
    }

    awaitable<std::vector<std::uint32_t>> uid_search(std::string_view criteria)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        mailxx::detail::ensure_no_crlf_or_nul(criteria, "criteria");

        std::string cmd;
        mailxx::detail::append_sv(cmd, "UID SEARCH");
        if (!criteria.empty())
        {
            mailxx::detail::append_space(cmd);
            mailxx::detail::append_sv(cmd, criteria);
        }

        response resp = co_await command_impl(cmd);
        std::vector<std::uint32_t> ids;
        for (const auto& line : resp.untagged_lines)
        {
            auto parsed = parse_search_ids(line);
            if (!parsed.empty())
                ids.insert(ids.end(), parsed.begin(), parsed.end());
        }

        co_return ids;
    }

    awaitable<std::string> uid_fetch_rfc822(std::uint32_t uid)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        std::string cmd;
        mailxx::detail::append_sv(cmd, "UID FETCH");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_uint(cmd, uid);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, "(RFC822)");

        response resp = co_await command_impl(cmd);
        co_return select_fetch_literal(resp, "RFC822");
    }

    awaitable<std::string> uid_fetch_body(std::uint32_t uid, std::string_view section)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        mailxx::detail::ensure_no_crlf_or_nul(section, "section");

        std::string cmd;
        mailxx::detail::append_sv(cmd, "UID FETCH");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_uint(cmd, uid);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_char(cmd, '(');
        mailxx::detail::append_sv(cmd, section);
        mailxx::detail::append_char(cmd, ')');

        response resp = co_await command_impl(cmd);
        co_return select_fetch_literal(resp, "BODY[");
    }

    awaitable<response> fetch(std::string_view seq_set, std::string_view items, bool uid = false)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        mailxx::detail::ensure_no_crlf_or_nul(seq_set, "seq_set");
        mailxx::detail::ensure_no_crlf_or_nul(items, "items");

        std::string cmd;
        if (uid)
            mailxx::detail::append_sv(cmd, "UID FETCH");
        else
            mailxx::detail::append_sv(cmd, "FETCH");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, seq_set);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, items);

        co_return co_await command_impl(cmd);
    }

    awaitable<response> store(std::string_view seq_set, std::string_view item_name, std::string_view value,
        std::string_view mode, bool uid = false)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        mailxx::detail::ensure_no_crlf_or_nul(seq_set, "seq_set");
        mailxx::detail::ensure_no_crlf_or_nul(item_name, "item_name");
        mailxx::detail::ensure_no_crlf_or_nul(value, "value");
        mailxx::detail::ensure_no_crlf_or_nul(mode, "mode");

        std::string cmd;
        if (uid)
            mailxx::detail::append_sv(cmd, "UID STORE");
        else
            mailxx::detail::append_sv(cmd, "STORE");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, seq_set);
        mailxx::detail::append_space(cmd);
        std::string item = build_store_item(item_name, mode);
        mailxx::detail::append_sv(cmd, item);
        if (!value.empty())
        {
            mailxx::detail::append_space(cmd);
            mailxx::detail::append_sv(cmd, value);
        }

        co_return co_await command_impl(cmd);
    }

    awaitable<response> close()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await command_impl("CLOSE");
    }

    awaitable<void> start_tls(ssl::context& context, std::string sni = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_await start_tls_impl(context, std::move(sni));
    }

    awaitable<idle_session> idle_start()
    {
        auto lock = co_await mutex_.lock();

        std::string tag = std::to_string(++tag_counter_);
        std::string line = tag;
        mailxx::detail::append_space(line);
        mailxx::detail::append_sv(line, "IDLE");

        co_await dialog().write_line(line, use_awaitable);

        std::string reply_line = co_await dialog().read_line(use_awaitable);
        if (!reply_line.empty() && reply_line[0] == '+')
            co_return idle_session(this, std::move(lock), std::move(tag), true);

        if (is_tagged_line(reply_line, tag))
        {
            response resp;
            resp.tag = tag;
            handle_line(resp, reply_line, tag);
            throw error("IDLE rejection.", resp.text.empty() ? reply_line : resp.text);
        }

        throw error("IDLE failure.", reply_line);
    }

private:
    struct capabilities_cache
    {
        bool sasl_ir = false;
        std::vector<std::string> auth_mechanisms;
        std::vector<std::string> raw_tokens;

        void reset()
        {
            sasl_ir = false;
            auth_mechanisms.clear();
            raw_tokens.clear();
        }
    };

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
        dialog_->set_trace_protocol("IMAP");
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
        mailxx::detail::append_sv(line, " literal bytes=");
        mailxx::detail::append_uint(line, static_cast<std::uint64_t>(bytes));
        if (options_.redact_secrets_in_trace)
            line = mailxx::detail::redact_line(line);
        logger.trace_protocol("IMAP", mailxx::log::direction::send, line);
    }

    void reset_capabilities() noexcept
    {
        capabilities_.reset();
        capabilities_known_ = false;
    }

    awaitable<void> connect_impl(const std::string& host, const std::string& service,
        mailxx::net::tls_mode mode = mailxx::net::tls_mode::none,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        if (dialog_.has_value())
            throw error("Connection is already established.", "");
        mailxx::detail::ensure_no_crlf_or_nul(host, "host");
        mailxx::detail::ensure_no_crlf_or_nul(service, "service");
        remote_host_ = host;

        tcp::resolver resolver(executor_);
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

        dialog_.emplace(std::move(stream), options_.max_line_length, options_.timeout);
        configure_trace();
        tag_counter_ = 0;
        reset_capabilities();

        if (mode == mailxx::net::tls_mode::starttls && options_.auto_starttls)
        {
            if (tls_ctx == nullptr)
                throw error("TLS context is required.", "STARTTLS needs a context.");
            co_await read_greeting_impl();
            co_await start_tls_impl(*tls_ctx, std::move(sni));
            (void)co_await capability_impl();
        }
    }

    awaitable<response> read_greeting_impl()
    {
        response resp;
        std::string line = co_await dialog().read_line(use_awaitable);
        handle_line(resp, line, std::string_view{});
        update_literal_plus_from_line(line);
        std::size_t literal_size = 0;
        if (extract_literal_size(line, literal_size))
        {
            resp.literals.push_back(co_await dialog().read_exactly(literal_size, use_awaitable));
        }
        co_return resp;
    }

    awaitable<response> login_impl(std::string_view username, std::string_view password)
    {
        enforce_auth_tls_policy();
        mailxx::detail::ensure_no_crlf_or_nul(username, "username");
        mailxx::detail::ensure_no_crlf_or_nul(password, "password");
        const std::string user = mailxx::imap::to_astring(username);
        const std::string pass = mailxx::imap::to_astring(password);
        std::string cmd;
        mailxx::detail::append_sv(cmd, "LOGIN");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, user);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, pass);
        co_return co_await command_impl(cmd);
    }

    awaitable<response> capability_impl()
    {
        response resp = co_await command_impl("CAPABILITY");
        update_literal_plus(resp);
        parse_capabilities(resp);
        capabilities_known_ = true;
        co_return resp;
    }

    awaitable<response> authenticate_impl(credentials cred, auth_method method)
    {
        mailxx::detail::ensure_no_crlf_or_nul(cred.username, "username");
        mailxx::detail::ensure_no_crlf_or_nul(cred.secret, "secret");

        if (!capabilities_known_
            && (method == auth_method::auto_detect || method == auth_method::plain || method == auth_method::xoauth2))
        {
            (void)co_await capability_impl();
        }

        auth_method resolved = method;
        if (method == auth_method::auto_detect)
            resolved = resolve_auth_method();

        switch (resolved)
        {
            case auth_method::plain:
                co_return co_await authenticate_plain_impl(cred);
            case auth_method::xoauth2:
                co_return co_await authenticate_xoauth2_impl(cred);
            case auth_method::login:
                co_return co_await login_impl(cred.username, cred.secret);
            case auth_method::auto_detect:
                break;
        }

        co_return co_await login_impl(cred.username, cred.secret);
    }

    awaitable<response> authenticate_plain_impl(const credentials& cred)
    {
        enforce_auth_tls_policy();
        std::string encoded = mailxx::sasl::encode_plain(cred.username, cred.secret);
        mailxx::detail::ensure_no_crlf_or_nul(encoded, "sasl_plain");

        if (capabilities_.sasl_ir)
        {
            std::string cmd;
            mailxx::detail::append_sv(cmd, "AUTHENTICATE PLAIN");
            mailxx::detail::append_space(cmd);
            mailxx::detail::append_sv(cmd, encoded);
            co_return co_await command_with_one_continuation(cmd, "");
        }

        co_return co_await command_with_one_continuation("AUTHENTICATE PLAIN", encoded);
    }

    awaitable<response> authenticate_xoauth2_impl(const credentials& cred)
    {
        enforce_auth_tls_policy();
        std::string encoded = mailxx::sasl::encode_xoauth2(cred.username, cred.secret);
        mailxx::detail::ensure_no_crlf_or_nul(encoded, "sasl_xoauth2");

        if (capabilities_.sasl_ir)
        {
            std::string cmd;
            mailxx::detail::append_sv(cmd, "AUTHENTICATE XOAUTH2");
            mailxx::detail::append_space(cmd);
            mailxx::detail::append_sv(cmd, encoded);
            co_return co_await command_with_one_continuation(cmd, "");
        }

        co_return co_await command_with_one_continuation("AUTHENTICATE XOAUTH2", encoded);
    }

    awaitable<void> start_tls_impl(ssl::context& context, std::string sni)
    {
        response resp = co_await command_impl("STARTTLS");
        if (resp.st != status::ok)
            throw error("STARTTLS failure.", resp.text);

        dialog_type& dlg = dialog();
        const std::size_t max_len = dlg.max_line_length();
        const auto timeout = dlg.timeout();

        mailxx::net::upgradable_stream stream = std::move(dlg.stream());
        std::string resolved_sni = resolve_sni(remote_host_, std::move(sni));
        co_await stream.start_tls(context, std::move(resolved_sni), options_.tls);

        dialog_.emplace(std::move(stream), max_len, timeout);
        configure_trace();
        reset_capabilities();
    }

    awaitable<response> command_impl(std::string_view cmd)
    {
        mailxx::detail::ensure_no_crlf_or_nul(cmd, "command");

        std::string tag = std::to_string(++tag_counter_);

        std::string line = tag;
        if (!cmd.empty())
        {
            mailxx::detail::append_space(line);
            mailxx::detail::append_sv(line, cmd);
        }

        co_await dialog().write_line(line, use_awaitable);
        co_return co_await read_response_impl(tag);
    }

    void enforce_auth_tls_policy()
    {
        mailxx::detail::ensure_auth_allowed<error>(dialog().stream().is_tls(), options_);
    }

    awaitable<response> command_with_one_continuation(std::string_view cmd, std::string_view continuation_line)
    {
        mailxx::detail::ensure_no_crlf_or_nul(cmd, "command");
        mailxx::detail::ensure_no_crlf_or_nul(continuation_line, "continuation");

        std::string tag = std::to_string(++tag_counter_);

        std::string line = tag;
        if (!cmd.empty())
        {
            mailxx::detail::append_space(line);
            mailxx::detail::append_sv(line, cmd);
        }

        co_await dialog().write_line(line, use_awaitable);

        response resp;
        resp.tag = tag;

        bool continuation_sent = false;
        while (true)
        {
            std::string resp_line = co_await dialog().read_line(use_awaitable);
            handle_line(resp, resp_line, tag);

            std::size_t literal_size = 0;
            if (extract_literal_size(resp_line, literal_size))
            {
                resp.literals.push_back(co_await dialog().read_exactly(literal_size, use_awaitable));
            }

            if (!continuation_sent && !resp_line.empty() && resp_line[0] == '+')
            {
                continuation_sent = true;
                co_await dialog().write_line(continuation_line, use_awaitable);
            }

            if (is_tagged_line(resp_line, tag))
                break;
        }

        co_return resp;
    }

    awaitable<response> append_raw_impl(std::string_view mailbox, std::string_view data,
        std::string_view flags, std::string_view date_time)
    {
        const bool use_literal_plus = literal_plus_.has_value() && *literal_plus_;
        std::string cmd = mailxx::imap::detail::build_append_command(
            mailbox, data.size(), flags, date_time, use_literal_plus);

        std::string tag = std::to_string(++tag_counter_);
        std::string line = tag;
        mailxx::detail::append_space(line);
        mailxx::detail::append_sv(line, cmd);

        co_await dialog().write_line(line, use_awaitable);

        response resp;
        resp.tag = tag;

        if (!use_literal_plus)
        {
            bool got_continuation = false;
            while (true)
            {
                std::string resp_line = co_await dialog().read_line(use_awaitable);
                handle_line(resp, resp_line, tag);
                std::size_t literal_size = 0;
                if (extract_literal_size(resp_line, literal_size))
                {
                    resp.literals.push_back(co_await dialog().read_exactly(literal_size, use_awaitable));
                }

                if (!resp_line.empty() && resp_line[0] == '+')
                {
                    got_continuation = true;
                    break;
                }

                if (is_tagged_line(resp_line, tag))
                    co_return resp;
            }

            if (!got_continuation)
                throw error("APPEND: expected continuation response.", "");
        }

        trace_payload("APPEND", data.size());
        co_await dialog().write_raw(buffer(data.data(), data.size()), use_awaitable);
        co_await read_response_until_tag(resp, tag);
        co_return resp;
    }

    awaitable<response> read_response_impl(const std::string& tag)
    {
        response resp;
        resp.tag = tag;

        co_await read_response_until_tag(resp, tag);
        co_return resp;
    }

    awaitable<void> read_response_until_tag(response& resp, const std::string& tag)
    {
        while (true)
        {
            std::string line = co_await dialog().read_line(use_awaitable);
            handle_line(resp, line, tag);

            std::size_t literal_size = 0;
            if (extract_literal_size(line, literal_size))
            {
                resp.literals.push_back(co_await dialog().read_exactly(literal_size, use_awaitable));
            }

            if (is_tagged_line(line, tag))
                break;
        }
    }

    static bool extract_literal_size(std::string_view line, std::size_t& out)
    {
        if (line.size() < 3 || line.back() != '}')
            return false;

        const auto brace = line.rfind('{');
        if (brace == std::string_view::npos)
            return false;

        std::string_view inner = line.substr(brace + 1, line.size() - brace - 2);
        if (inner.empty())
            return false;

        if (inner.back() == '+')
            inner.remove_suffix(1);
        if (inner.empty())
            return false;

        std::size_t value = 0;
        for (char ch : inner)
        {
            if (ch < '0' || ch > '9')
                return false;
            value = value * 10 + static_cast<std::size_t>(ch - '0');
        }

        out = value;
        return true;
    }

    static bool is_tagged_line(std::string_view line, std::string_view tag)
    {
        if (tag.empty() || line.size() < tag.size())
            return false;
        if (!line.starts_with(tag))
            return false;
        if (line.size() <= tag.size())
            return false;
        return line[tag.size()] == ' ';
    }

    static std::string_view ltrim(std::string_view text)
    {
        while (!text.empty() && text.front() == ' ')
            text.remove_prefix(1);
        return text;
    }

    static bool iequals_ascii(std::string_view a, std::string_view b)
    {
        if (a.size() != b.size())
            return false;
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            char ca = a[i];
            char cb = b[i];
            if (ca >= 'a' && ca <= 'z')
                ca = static_cast<char>(ca - ('a' - 'A'));
            if (cb >= 'a' && cb <= 'z')
                cb = static_cast<char>(cb - ('a' - 'A'));
            if (ca != cb)
                return false;
        }
        return true;
    }

    static bool starts_with_ci(std::string_view text, std::string_view prefix)
    {
        if (text.size() < prefix.size())
            return false;
        return iequals_ascii(text.substr(0, prefix.size()), prefix);
    }

    static std::pair<std::string_view, std::string_view> split_token(std::string_view text)
    {
        text = ltrim(text);
        auto pos = text.find(' ');
        if (pos == std::string_view::npos)
            return {text, std::string_view{}};
        return {text.substr(0, pos), ltrim(text.substr(pos + 1))};
    }

    static bool parse_quoted_string(std::string_view& text, std::string& out)
    {
        text = ltrim(text);
        if (text.empty() || text.front() != '"')
            return false;
        text.remove_prefix(1);
        out.clear();
        while (!text.empty())
        {
            char ch = text.front();
            text.remove_prefix(1);
            if (ch == '"')
            {
                text = ltrim(text);
                return true;
            }
            if (ch == '\\' && !text.empty())
            {
                out.push_back(text.front());
                text.remove_prefix(1);
                continue;
            }
            out.push_back(ch);
        }
        return false;
    }

    static bool parse_atom(std::string_view& text, std::string& out)
    {
        text = ltrim(text);
        if (text.empty())
            return false;
        auto pos = text.find(' ');
        std::string_view token = pos == std::string_view::npos ? text : text.substr(0, pos);
        out.assign(token.begin(), token.end());
        text = pos == std::string_view::npos ? std::string_view{} : ltrim(text.substr(pos + 1));
        return true;
    }

    static bool parse_quoted_or_atom(std::string_view& text, std::string& out)
    {
        text = ltrim(text);
        if (text.empty())
            return false;
        if (text.front() == '"')
            return parse_quoted_string(text, out);
        return parse_atom(text, out);
    }

    static void parse_list_attributes(std::string_view attrs, std::vector<std::string>& out)
    {
        out.clear();
        attrs = ltrim(attrs);
        while (!attrs.empty())
        {
            auto [token, rest] = split_token(attrs);
            if (!token.empty())
                out.emplace_back(token.begin(), token.end());
            attrs = rest;
        }
    }

    static bool parse_list_line(std::string_view line, mailbox_folder& folder)
    {
        line = ltrim(line);
        auto [star, rest] = split_token(line);
        if (star != "*")
            return false;
        auto [keyword, rest2] = split_token(rest);
        if (!iequals_ascii(keyword, "LIST"))
            return false;
        rest2 = ltrim(rest2);
        if (rest2.empty() || rest2.front() != '(')
            return false;
        auto close = rest2.find(')');
        if (close == std::string_view::npos)
            return false;
        std::string_view attrs = rest2.substr(1, close - 1);
        parse_list_attributes(attrs, folder.attributes);

        rest2 = ltrim(rest2.substr(close + 1));
        std::string delimiter_token;
        if (!parse_quoted_or_atom(rest2, delimiter_token))
            return false;
        if (!delimiter_token.empty() && !iequals_ascii(delimiter_token, "NIL"))
            folder.delimiter = delimiter_token.front();
        else
            folder.delimiter = '\0';

        std::string name_token;
        if (!parse_quoted_or_atom(rest2, name_token))
            return false;
        if (!iequals_ascii(name_token, "NIL"))
            folder.name = std::move(name_token);
        else
            folder.name.clear();

        return true;
    }

    static std::string build_store_item(std::string_view item_name, std::string_view mode)
    {
        std::string item;
        if (mode.empty())
        {
            mailxx::detail::append_sv(item, item_name);
            return item;
        }
        if (item_name.empty())
        {
            mailxx::detail::append_sv(item, mode);
            return item;
        }
        if (iequals_ascii(mode, "FLAGS") && starts_with_ci(item_name, "FLAGS"))
        {
            mailxx::detail::append_sv(item, item_name);
            return item;
        }
        if ((mode.front() == '+' || mode.front() == '-') && iequals_ascii(mode.substr(1), "FLAGS")
            && starts_with_ci(item_name, "FLAGS"))
        {
            mailxx::detail::append_char(item, mode.front());
            mailxx::detail::append_sv(item, item_name);
            return item;
        }
        mailxx::detail::append_sv(item, mode);
        mailxx::detail::append_space(item);
        mailxx::detail::append_sv(item, item_name);
        return item;
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

    static status parse_status_word(std::string_view word)
    {
        const std::string upper = to_upper_ascii(word);
        if (upper == "OK")
            return status::ok;
        if (upper == "NO")
            return status::no;
        if (upper == "BAD")
            return status::bad;
        if (upper == "PREAUTH")
            return status::preauth;
        if (upper == "BYE")
            return status::bye;
        return status::unknown;
    }

    static void apply_status_from_untagged(response& resp, std::string_view line)
    {
        std::string_view rest = ltrim(line.substr(1));
        auto [word, tail] = split_token(rest);
        status st = parse_status_word(word);
        if (st != status::unknown && resp.st == status::unknown)
        {
            resp.st = st;
            resp.text.assign(tail.begin(), tail.end());
        }
    }

    static void apply_status_from_tagged(response& resp, std::string_view line, std::string_view tag)
    {
        std::string_view rest = ltrim(line.substr(tag.size()));
        auto [word, tail] = split_token(rest);
        status st = parse_status_word(word);
        resp.st = st;
        resp.text.assign(tail.begin(), tail.end());
    }

    static void handle_line(response& resp, const std::string& line, std::string_view tag)
    {
        if (!tag.empty() && is_tagged_line(line, tag))
        {
            resp.tagged_lines.push_back(line);
            apply_status_from_tagged(resp, line, tag);
            return;
        }

        if (!line.empty() && line[0] == '*')
        {
            resp.untagged_lines.push_back(line);
            apply_status_from_untagged(resp, line);
            return;
        }

        if (!line.empty() && line[0] == '+')
        {
            resp.continuation.push_back(line);
            if (resp.st == status::unknown && resp.text.empty())
            {
                std::string_view rest = ltrim(line.substr(1));
                resp.text.assign(rest.begin(), rest.end());
            }
            return;
        }

        resp.untagged_lines.push_back(line);
    }

    // Best-effort mapping of FETCH literals to untagged lines by appearance.
    static std::string select_fetch_literal(const response& resp, std::string_view marker)
    {
        if (resp.literals.size() == 1)
            return resp.literals.front();
        if (resp.literals.empty())
            return {};

        const std::string marker_upper = to_upper_ascii(marker);
        std::size_t literal_index = 0;
        for (const auto& line : resp.untagged_lines)
        {
            std::size_t literal_size = 0;
            const bool has_literal = extract_literal_size(line, literal_size);
            if (!has_literal)
                continue;

            std::string upper_line = to_upper_ascii(line);
            if (upper_line.find(marker_upper) != std::string::npos)
            {
                if (literal_index < resp.literals.size())
                    return resp.literals[literal_index];
                return {};
            }

            ++literal_index;
            if (literal_index >= resp.literals.size())
                break;
        }

        return {};
    }

    void parse_capabilities(const response& resp)
    {
        capabilities_.reset();
        for (const auto& line : resp.untagged_lines)
            parse_capability_line(capabilities_, line);
        for (const auto& line : resp.tagged_lines)
            parse_capability_line(capabilities_, line);
    }

    auth_method resolve_auth_method() const
    {
        if (has_auth_mechanism("XOAUTH2"))
            return auth_method::xoauth2;
        if (has_auth_mechanism("PLAIN"))
            return auth_method::plain;
        return auth_method::login;
    }

    bool has_auth_mechanism(std::string_view mechanism) const
    {
        const std::string key = to_upper_ascii(mechanism);
        for (const auto& mech : capabilities_.auth_mechanisms)
        {
            if (mech == key)
                return true;
        }
        return false;
    }

    static void parse_capability_line(capabilities_cache& caps, std::string_view line)
    {
        auto pos = line.find("CAPABILITY");
        if (pos == std::string_view::npos)
            return;
        std::string_view rest = line.substr(pos + std::string_view("CAPABILITY").size());
        rest = ltrim(rest);

        bool sasl_list = false;
        while (!rest.empty())
        {
            auto [token, remaining] = split_token(rest);
            if (token.empty())
                break;

            token = normalize_capability_token(token);
            if (token.empty())
            {
                rest = remaining;
                continue;
            }

            caps.raw_tokens.push_back(to_upper_ascii(token));

            if (iequals_ascii(token, "SASL-IR"))
                caps.sasl_ir = true;

            if (starts_with_ci(token, "AUTH="))
            {
                std::string_view mech = token.substr(5);
                add_auth_mechanism(caps, mech);
            }
            else if (starts_with_ci(token, "SASL="))
            {
                std::string_view list = token.substr(5);
                add_auth_mechanisms_from_list(caps, list);
            }
            else if (iequals_ascii(token, "SASL"))
            {
                sasl_list = true;
            }
            else if (sasl_list)
            {
                if (!iequals_ascii(token, "SASL-IR"))
                    add_auth_mechanism(caps, token);
            }

            rest = remaining;
        }
    }

    static void add_auth_mechanism(capabilities_cache& caps, std::string_view mechanism)
    {
        mechanism = normalize_capability_token(mechanism);
        if (mechanism.empty())
            return;
        std::string upper = to_upper_ascii(mechanism);
        for (const auto& existing : caps.auth_mechanisms)
        {
            if (existing == upper)
                return;
        }
        caps.auth_mechanisms.push_back(std::move(upper));
    }

    static void add_auth_mechanisms_from_list(capabilities_cache& caps, std::string_view list)
    {
        while (!list.empty())
        {
            auto pos = list.find(',');
            std::string_view token = pos == std::string_view::npos ? list : list.substr(0, pos);
            add_auth_mechanism(caps, token);
            if (pos == std::string_view::npos)
                break;
            list.remove_prefix(pos + 1);
        }
    }

    static std::string_view normalize_capability_token(std::string_view token)
    {
        token = ltrim(token);
        while (!token.empty() && (token.front() == '[' || token.front() == '('))
            token.remove_prefix(1);
        while (!token.empty() && (token.back() == ']' || token.back() == ')'))
            token.remove_suffix(1);
        return token;
    }

    executor_type executor_;
    options options_;
    mailxx::detail::async_mutex mutex_;
    std::optional<dialog_type> dialog_;
    std::string remote_host_;
    std::uint64_t tag_counter_{0};
    capabilities_cache capabilities_;
    bool capabilities_known_{false};
    std::optional<bool> literal_plus_;

    void update_literal_plus(const response& resp)
    {
        bool found_caps = false;
        bool has_literal_plus = false;
        for (const auto& line : resp.untagged_lines)
        {
            if (line_has_capability(line, found_caps))
                has_literal_plus = true;
        }
        for (const auto& line : resp.tagged_lines)
        {
            if (line_has_capability(line, found_caps))
                has_literal_plus = true;
        }
        if (found_caps)
            literal_plus_ = has_literal_plus;
    }

    void update_literal_plus_from_line(std::string_view line)
    {
        bool found_caps = false;
        bool has_literal_plus = line_has_capability(line, found_caps);
        if (found_caps)
            literal_plus_ = has_literal_plus;
    }

    static bool line_has_capability(std::string_view line, bool& found_caps)
    {
        auto pos = line.find("CAPABILITY");
        if (pos == std::string_view::npos)
            return false;
        found_caps = true;
        std::string_view rest = line.substr(pos + std::string_view("CAPABILITY").size());
        rest = ltrim(rest);
        while (!rest.empty())
        {
            auto [token, remaining] = split_token(rest);
            if (token.empty())
                break;
            if (token_has_literal_plus(token))
                return true;
            rest = remaining;
        }
        return false;
    }

    static bool token_has_literal_plus(std::string_view token)
    {
        token = normalize_capability_token(token);
        return iequals_ascii(token, "LITERAL+");
    }
};

} // namespace mailxx::imap

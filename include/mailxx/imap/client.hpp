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
#include <system_error>
#include <utility>
#include <array>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/asio_error.hpp>
#include <mailxx/detail/append.hpp>
#include <mailxx/detail/auth_policy.hpp>
#include <mailxx/detail/async_mutex.hpp>
#include <mailxx/detail/log.hpp>
#include <mailxx/detail/oauth2_retry.hpp>
#include <mailxx/detail/redact.hpp>
#include <mailxx/detail/result.hpp>
#include <mailxx/detail/sasl.hpp>
#include <mailxx/detail/sanitize.hpp>
#include <mailxx/detail/output_sink.hpp>
#include <mailxx/oauth2/token_source.hpp>
#include <mailxx/imap/error.hpp>
#include <mailxx/imap/error_mapping.hpp>
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
using mailxx::result;
using mailxx::result_void;
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

        awaitable<result<std::string>> idle_read()
        {
            if (!active_ || owner_ == nullptr)
                co_return mailxx::fail<std::string>(
                    mailxx::errc::imap_invalid_state,
                    "IDLE is not active.",
                    mailxx::imap::make_imap_detail({}, "IDLE", {}, 0, 0));

            dialog_type* dlg = nullptr;
            MAILXX_CO_TRY_ASSIGN(dlg, owner_->dialog_ptr());
            std::string line;
            MAILXX_CO_TRY_ASSIGN(line, co_await dlg->read_line_r());
            co_return mailxx::ok(std::move(line));
        }

        awaitable<result<response>> idle_stop()
        {
            if (!active_ || owner_ == nullptr)
                co_return mailxx::fail<response>(
                    mailxx::errc::imap_invalid_state,
                    "IDLE is not active.",
                    mailxx::imap::make_imap_detail({}, "IDLE", {}, 0, 0));

            client* owner = owner_;
            dialog_type* dlg = nullptr;
            MAILXX_CO_TRY_ASSIGN(dlg, owner_->dialog_ptr());
            MAILXX_TRY_CO_AWAIT(dlg->write_line_r("DONE"));

            response resp;
            resp.tag = tag_;

            while (true)
            {
                std::string line;
                MAILXX_CO_TRY_ASSIGN(line, co_await dlg->read_line_r());
                client::handle_line(resp, line, tag_);

                std::size_t literal_size = 0;
                if (client::extract_literal_size(line, literal_size))
                {
                    std::string literal;
                    MAILXX_CO_TRY_ASSIGN(literal, co_await dlg->read_exactly_r(literal_size));
                    if (literal.size() != literal_size)
                    {
                        co_return owner_->imap_fail<response>(
                            error_kind::parse,
                            "IMAP literal size mismatch.",
                            tag_,
                            "DONE",
                            line,
                            resp);
                    }
                    resp.literals.push_back(std::move(literal));
                }

                if (client::is_tagged_line(line, tag_))
                    break;
            }

            active_ = false;
            owner_ = nullptr;
            lock_ = mailxx::detail::async_mutex::scoped_lock();
            co_return owner->finalize_response(std::move(resp), "DONE");
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

    awaitable<result_void> connect(const std::string& host, unsigned short port)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await connect_impl(host, std::to_string(port), mailxx::net::tls_mode::none, nullptr, {});
    }

    awaitable<result_void> connect(const std::string& host, const std::string& service)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await connect_impl(host, service, mailxx::net::tls_mode::none, nullptr, {});
    }

    awaitable<result_void> connect(const std::string& host, unsigned short port, mailxx::net::tls_mode mode,
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

    awaitable<result<response>> read_greeting()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await read_greeting_impl();
    }

    awaitable<result<response>> command(std::string_view cmd)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await command_impl(cmd);
    }

    awaitable<result<response>> capability()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await capability_impl();
    }

    awaitable<result<response>> login(std::string_view username, std::string_view password)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await login_impl(username, password);
    }

    awaitable<result<response>> authenticate(credentials cred, auth_method method)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await authenticate_impl(std::move(cred), method);
    }

    awaitable<result<response>> authenticate(credentials cred, mailxx::oauth2::token_source& source)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        std::string username = std::move(cred.username);
        auto auth = [&](const std::string& token) -> awaitable<result<response>>
        {
            credentials refresh_cred{username, token};
            co_return co_await authenticate_impl(std::move(refresh_cred), auth_method::xoauth2);
        };
        auto should_retry = [](const error_info& err)
        {
            return err.code == errc::imap_tagged_no;
        };
        co_return co_await mailxx::detail::oauth2_auth_with_retry(source, auth, should_retry);
    }

    awaitable<result<response>> logout()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await command_impl("LOGOUT");
    }

    awaitable<result<response>> noop()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await command_impl("NOOP");
    }

    awaitable<result<response>> append(std::string_view mailbox, const mailxx::message& msg,
        std::string_view flags = {}, std::string_view date_time = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        std::string payload;
        auto fmt_res = msg.format_result(payload);
        if (!fmt_res)
            co_return mailxx::fail<response>(std::move(fmt_res).error());
        co_return co_await append_raw_impl(mailbox, payload, flags, date_time);
    }

    awaitable<result<response>> append_streaming(std::string_view mailbox, const mailxx::message& msg,
        std::string_view flags = {}, std::string_view date_time = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await append_streaming_impl(mailbox, msg, flags, date_time);
    }

    awaitable<result<response>> append_raw(std::string_view mailbox, std::string_view data,
        std::string_view flags = {}, std::string_view date_time = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await append_raw_impl(mailbox, data, flags, date_time);
    }

    awaitable<result<std::pair<response, std::vector<mailbox_folder>>>> list(
        std::string_view reference, std::string_view pattern)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(reference, "reference"));
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(pattern, "pattern"));

        std::string ref;
        MAILXX_CO_TRY_ASSIGN(ref, mailxx::imap::to_mailbox(reference));
        std::string pat;
        MAILXX_CO_TRY_ASSIGN(pat, mailxx::imap::to_mailbox(pattern));

        std::string cmd;
        mailxx::detail::append_sv(cmd, "LIST");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, ref);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, pat);

        response resp;
        MAILXX_CO_TRY_ASSIGN(resp, co_await command_impl(cmd));
        std::vector<mailbox_folder> folders;
        folders.reserve(resp.untagged_lines.size());
        for (const auto& line : resp.untagged_lines)
        {
            mailbox_folder folder;
            if (parse_list_line(line, folder))
                folders.push_back(std::move(folder));
        }

        co_return mailxx::ok(std::make_pair(std::move(resp), std::move(folders)));
    }

    awaitable<result<std::pair<response, mailbox_stat>>> select(std::string_view mailbox)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(mailbox, "mailbox"));

        std::string box;
        MAILXX_CO_TRY_ASSIGN(box, mailxx::imap::to_mailbox(mailbox));
        std::string cmd;
        mailxx::detail::append_sv(cmd, "SELECT");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, box);

        response resp;
        MAILXX_CO_TRY_ASSIGN(resp, co_await command_impl(cmd));
        mailbox_stat stat;
        for (const auto& line : resp.untagged_lines)
            parse_mailbox_stat(line, stat);
        co_return mailxx::ok(std::make_pair(std::move(resp), stat));
    }

    awaitable<result<std::pair<response, mailbox_stat>>> examine(std::string_view mailbox)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(mailbox, "mailbox"));

        std::string box;
        MAILXX_CO_TRY_ASSIGN(box, mailxx::imap::to_mailbox(mailbox));
        std::string cmd;
        mailxx::detail::append_sv(cmd, "EXAMINE");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, box);

        response resp;
        MAILXX_CO_TRY_ASSIGN(resp, co_await command_impl(cmd));
        mailbox_stat stat;
        for (const auto& line : resp.untagged_lines)
            parse_mailbox_stat(line, stat);
        co_return mailxx::ok(std::make_pair(std::move(resp), stat));
    }

    awaitable<result<std::pair<response, std::vector<std::uint32_t>>>> search(
        std::string_view criteria, bool uid = false)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(criteria, "criteria"));

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

        response resp;
        MAILXX_CO_TRY_ASSIGN(resp, co_await command_impl(cmd));
        std::vector<std::uint32_t> ids;
        for (const auto& line : resp.untagged_lines)
        {
            auto parsed = parse_search_ids(line);
            if (!parsed.empty())
                ids.insert(ids.end(), parsed.begin(), parsed.end());
        }

        co_return mailxx::ok(std::make_pair(std::move(resp), std::move(ids)));
    }

    awaitable<result<std::vector<std::uint32_t>>> uid_search(std::string_view criteria)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(criteria, "criteria"));

        std::string cmd;
        mailxx::detail::append_sv(cmd, "UID SEARCH");
        if (!criteria.empty())
        {
            mailxx::detail::append_space(cmd);
            mailxx::detail::append_sv(cmd, criteria);
        }

        response resp;
        MAILXX_CO_TRY_ASSIGN(resp, co_await command_impl(cmd));
        std::vector<std::uint32_t> ids;
        for (const auto& line : resp.untagged_lines)
        {
            auto parsed = parse_search_ids(line);
            if (!parsed.empty())
                ids.insert(ids.end(), parsed.begin(), parsed.end());
        }

        co_return mailxx::ok(std::move(ids));
    }

    awaitable<result<mailxx::message>> uid_fetch_rfc822(std::uint32_t uid)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        std::string cmd;
        mailxx::detail::append_sv(cmd, "UID FETCH");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_uint(cmd, uid);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, "(RFC822)");

        response resp;
        MAILXX_CO_TRY_ASSIGN(resp, co_await command_impl(cmd));
        std::string raw = select_fetch_literal(resp, "RFC822");
        mailxx::message msg;
        MAILXX_CO_TRY_ASSIGN(msg, mailxx::message::parse_result(raw));
        co_return mailxx::ok(std::move(msg));
    }

    awaitable<result<std::string>> uid_fetch_body(std::uint32_t uid, std::string_view section)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(section, "section"));

        std::string cmd;
        mailxx::detail::append_sv(cmd, "UID FETCH");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_uint(cmd, uid);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_char(cmd, '(');
        mailxx::detail::append_sv(cmd, section);
        mailxx::detail::append_char(cmd, ')');

        response resp;
        MAILXX_CO_TRY_ASSIGN(resp, co_await command_impl(cmd));
        co_return mailxx::ok(select_fetch_literal(resp, "BODY["));
    }

    awaitable<result<response>> fetch(std::string_view seq_set, std::string_view items, bool uid = false)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(seq_set, "seq_set"));
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(items, "items"));

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

    awaitable<result<response>> store(std::string_view seq_set, std::string_view item_name, std::string_view value,
        std::string_view mode, bool uid = false)
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(seq_set, "seq_set"));
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(item_name, "item_name"));
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(value, "value"));
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(mode, "mode"));

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

    awaitable<result<response>> close()
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await command_impl("CLOSE");
    }

    awaitable<result_void> start_tls(ssl::context& context, std::string sni = {})
    {
        [[maybe_unused]] auto guard = co_await mutex_.lock();
        co_return co_await start_tls_impl(context, std::move(sni));
    }

    awaitable<result<idle_session>> idle_start()
    {
        auto lock = co_await mutex_.lock();

        std::string tag = std::to_string(++tag_counter_);
        std::string line = tag;
        mailxx::detail::append_space(line);
        mailxx::detail::append_sv(line, "IDLE");

        dialog_type* dlg = nullptr;
        MAILXX_CO_TRY_ASSIGN(dlg, dialog_ptr());
        MAILXX_TRY_CO_AWAIT(dlg->write_line_r(line));

        std::string reply_line;
        MAILXX_CO_TRY_ASSIGN(reply_line, co_await dlg->read_line_r());
        if (!reply_line.empty() && reply_line[0] == '+')
            co_return mailxx::ok(idle_session(this, std::move(lock), std::move(tag), true));

        if (is_tagged_line(reply_line, tag))
        {
            response resp;
            resp.tag = tag;
            handle_line(resp, reply_line, tag);
            if (resp.st == status::no)
            {
                co_return imap_fail<idle_session>(
                    error_kind::tagged_no, "IMAP tagged NO.", tag, "IDLE", reply_line, resp);
            }
            if (resp.st == status::bad)
            {
                co_return imap_fail<idle_session>(
                    error_kind::tagged_bad, "IMAP tagged BAD.", tag, "IDLE", reply_line, resp);
            }
            if (resp.st == status::unknown)
            {
                co_return imap_fail<idle_session>(
                    error_kind::parse, "IMAP parse error.", tag, "IDLE", reply_line, resp);
            }
            co_return imap_fail<idle_session>(
                error_kind::continuation_expected,
                "IMAP continuation expected.",
                tag,
                "IDLE",
                reply_line,
                resp);
        }

        response resp;
        resp.tag = tag;
        co_return imap_fail<idle_session>(
            error_kind::continuation_expected,
            "IMAP continuation expected.",
            tag,
            "IDLE",
            reply_line,
            resp);
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

    [[nodiscard]] mailxx::detail::error_detail imap_detail(
        std::string_view tag,
        std::string_view command,
        std::string_view tagged_line,
        std::size_t untagged_count,
        std::size_t literals_count) const
    {
        std::string command_value;
        std::string tagged_value;
        if (options_.redact_secrets_in_trace)
        {
            command_value = mailxx::detail::redact_line(command);
            tagged_value = mailxx::detail::redact_line(tagged_line);
        }
        else
        {
            command_value.assign(command.begin(), command.end());
            tagged_value.assign(tagged_line.begin(), tagged_line.end());
        }
        return mailxx::imap::make_imap_detail(tag, command_value, tagged_value, untagged_count, literals_count);
    }

    [[nodiscard]] mailxx::detail::error_detail imap_detail(
        std::string_view tag,
        std::string_view command,
        std::string_view tagged_line,
        const response& resp) const
    {
        return imap_detail(tag, command, tagged_line, resp.untagged_lines.size(), resp.literals.size());
    }

    template<typename T>
    [[nodiscard]] result<T> imap_fail(
        error_kind kind,
        std::string_view message,
        std::string_view tag,
        std::string_view command,
        std::string_view tagged_line,
        std::size_t untagged_count,
        std::size_t literals_count) const
    {
        return mailxx::fail<T>(
            map_imap_error(kind),
            std::string(message),
            imap_detail(tag, command, tagged_line, untagged_count, literals_count));
    }

    template<typename T>
    [[nodiscard]] result<T> imap_fail(
        error_kind kind,
        std::string_view message,
        std::string_view tag,
        std::string_view command,
        std::string_view tagged_line,
        const response& resp) const
    {
        return imap_fail<T>(kind, message, tag, command, tagged_line,
            resp.untagged_lines.size(), resp.literals.size());
    }

    [[nodiscard]] static std::string_view tagged_line_or_text(const response& resp) noexcept
    {
        if (!resp.tagged_lines.empty())
            return resp.tagged_lines.back();
        return resp.text;
    }

    result<std::string> resolve_sni(std::string_view host, std::string sni) const
    {
        if (sni.empty())
            sni.assign(host.begin(), host.end());
        if (mailxx::detail::contains_crlf_or_nul(sni))
        {
            return mailxx::fail<std::string>(
                map_imap_error(error_kind::parse),
                "Invalid sni: CR/LF or NUL not allowed.",
                imap_detail({}, "SNI", {}, 0, 0));
        }
        return mailxx::ok(std::move(sni));
    }

    result<dialog_type*> dialog_ptr()
    {
        if (!dialog_.has_value())
            return mailxx::fail<dialog_type*>(
                mailxx::errc::imap_invalid_state,
                "Connection is not established.",
                imap_detail({}, "CONNECT", {}, 0, 0));
        return mailxx::ok(&*dialog_);
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

    awaitable<result_void> connect_impl(const std::string& host, const std::string& service,
        mailxx::net::tls_mode mode = mailxx::net::tls_mode::none,
        ssl::context* tls_ctx = nullptr, std::string sni = {})
    {
        if (dialog_.has_value())
            co_return mailxx::fail<void>(
                mailxx::errc::imap_invalid_state,
                "Connection is already established.",
                imap_detail({}, "CONNECT", {}, 0, 0));
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(host, "host"));
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(service, "service"));
        remote_host_ = host;

        tcp::resolver resolver(executor_);
        auto [resolve_ec, endpoints] =
            co_await resolver.async_resolve(host, service, mailxx::asio::use_nothrow_awaitable);
        if (resolve_ec)
            co_return mailxx::fail<void>(mailxx::error_from_asio(resolve_ec, mailxx::net::io_stage::resolve));

        mailxx::net::upgradable_stream stream(executor_);
        auto [connect_ec, endpoint] =
            co_await async_connect(stream.lowest_layer(), endpoints, mailxx::asio::use_nothrow_awaitable);
        (void)endpoint;
        if (connect_ec)
            co_return mailxx::fail<void>(mailxx::error_from_asio(connect_ec, mailxx::net::io_stage::connect));

        if (mode == mailxx::net::tls_mode::implicit)
        {
            if (tls_ctx == nullptr)
                co_return mailxx::fail<void>(
                    mailxx::errc::imap_invalid_state,
                    "TLS context is required.",
                    imap_detail({}, "CONNECT", "Implicit TLS needs a context.", 0, 0));
            std::string resolved_sni;
            MAILXX_CO_TRY_ASSIGN(resolved_sni, resolve_sni(host, std::move(sni)));
            MAILXX_TRY_CO_AWAIT(start_tls_stream(stream, *tls_ctx, std::move(resolved_sni)));
        }

        dialog_.emplace(std::move(stream), options_.max_line_length, options_.timeout);
        configure_trace();
        tag_counter_ = 0;
        reset_capabilities();

        if (mode == mailxx::net::tls_mode::starttls && options_.auto_starttls)
        {
            if (tls_ctx == nullptr)
                co_return mailxx::fail<void>(
                    mailxx::errc::imap_invalid_state,
                    "TLS context is required.",
                    imap_detail({}, "STARTTLS", "STARTTLS needs a context.", 0, 0));
            MAILXX_TRY_CO_AWAIT(read_greeting_impl());
            MAILXX_TRY_CO_AWAIT(start_tls_impl(*tls_ctx, std::move(sni)));
            MAILXX_TRY_CO_AWAIT(capability_impl());
        }

        co_return mailxx::ok();
    }

    awaitable<result<response>> read_greeting_impl()
    {
        response resp;
        dialog_type* dlg = nullptr;
        MAILXX_CO_TRY_ASSIGN(dlg, dialog_ptr());
        std::string line;
        MAILXX_CO_TRY_ASSIGN(line, co_await dlg->read_line_r());
        handle_line(resp, line, std::string_view{});
        update_literal_plus_from_line(line);
        std::size_t literal_size = 0;
        if (extract_literal_size(line, literal_size))
        {
            std::string literal;
            MAILXX_CO_TRY_ASSIGN(literal, co_await dlg->read_exactly_r(literal_size));
            if (literal.size() != literal_size)
            {
                co_return imap_fail<response>(
                    error_kind::parse,
                    "IMAP literal size mismatch.",
                    resp.tag,
                    "GREETING",
                    line,
                    resp);
            }
            resp.literals.push_back(std::move(literal));
        }
        co_return finalize_response(std::move(resp), "GREETING");
    }

    awaitable<result<response>> login_impl(std::string_view username, std::string_view password)
    {
        dialog_type* dlg = nullptr;
        MAILXX_CO_TRY_ASSIGN(dlg, dialog_ptr());
        MAILXX_CO_TRY_VOID(enforce_auth_tls_policy(*dlg));
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(username, "username"));
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(password, "password"));
        std::string user;
        MAILXX_CO_TRY_ASSIGN(user, mailxx::imap::to_astring(username));
        std::string pass;
        MAILXX_CO_TRY_ASSIGN(pass, mailxx::imap::to_astring(password));
        std::string cmd;
        mailxx::detail::append_sv(cmd, "LOGIN");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, user);
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, pass);
        co_return co_await command_impl(cmd);
    }

    awaitable<result<response>> capability_impl()
    {
        response resp;
        MAILXX_CO_TRY_ASSIGN(resp, co_await command_impl("CAPABILITY"));
        update_literal_plus(resp);
        parse_capabilities(resp);
        capabilities_known_ = true;
        co_return mailxx::ok(std::move(resp));
    }

    awaitable<result<response>> authenticate_impl(credentials cred, auth_method method)
    {
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(cred.username, "username"));
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(cred.secret, "secret"));

        if (!capabilities_known_
            && (method == auth_method::auto_detect || method == auth_method::plain || method == auth_method::xoauth2))
        {
            MAILXX_TRY_CO_AWAIT(capability_impl());
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

    awaitable<result<response>> authenticate_plain_impl(const credentials& cred)
    {
        dialog_type* dlg = nullptr;
        MAILXX_CO_TRY_ASSIGN(dlg, dialog_ptr());
        MAILXX_CO_TRY_VOID(enforce_auth_tls_policy(*dlg));
        auto encoded_res = mailxx::sasl::encode_plain(cred.username, cred.secret);
        if (!encoded_res)
        {
            co_return mailxx::fail<response>(
                encoded_res.error().code,
                "AUTHENTICATE PLAIN encoding failure.",
                format_codec_error(encoded_res.error()));
        }
        std::string encoded = std::move(*encoded_res);
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(encoded, "sasl_plain"));

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

    awaitable<result<response>> authenticate_xoauth2_impl(const credentials& cred)
    {
        dialog_type* dlg = nullptr;
        MAILXX_CO_TRY_ASSIGN(dlg, dialog_ptr());
        MAILXX_CO_TRY_VOID(enforce_auth_tls_policy(*dlg));
        auto encoded_res = mailxx::sasl::encode_xoauth2(cred.username, cred.secret);
        if (!encoded_res)
        {
            co_return mailxx::fail<response>(
                encoded_res.error().code,
                "AUTHENTICATE XOAUTH2 encoding failure.",
                format_codec_error(encoded_res.error()));
        }
        std::string encoded = std::move(*encoded_res);
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(encoded, "sasl_xoauth2"));

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

    awaitable<result_void> start_tls_impl(ssl::context& context, std::string sni)
    {
        MAILXX_TRY_CO_AWAIT(command_impl("STARTTLS"));

        dialog_type* dlg = nullptr;
        MAILXX_CO_TRY_ASSIGN(dlg, dialog_ptr());
        const std::size_t max_len = dlg->max_line_length();
        const auto timeout = dlg->timeout();

        mailxx::net::upgradable_stream stream = std::move(dlg->stream());
        dialog_.reset();

        std::string resolved_sni;
        MAILXX_CO_TRY_ASSIGN(resolved_sni, resolve_sni(remote_host_, std::move(sni)));
        MAILXX_TRY_CO_AWAIT(start_tls_stream(stream, context, std::move(resolved_sni)));

        dialog_.emplace(std::move(stream), max_len, timeout);
        configure_trace();
        reset_capabilities();
        co_return mailxx::ok();
    }

    awaitable<result_void> start_tls_stream(mailxx::net::upgradable_stream& stream,
        ssl::context& context, std::string sni)
    {
        auto tls_res = co_await stream.start_tls(context, std::move(sni), options_.tls);
        if (!tls_res)
            co_return mailxx::fail<void>(std::move(tls_res).error());
        co_return mailxx::ok();
    }

    awaitable<result<response>> command_impl(std::string_view cmd)
    {
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(cmd, "command"));

        std::string tag = std::to_string(++tag_counter_);

        std::string line = tag;
        if (!cmd.empty())
        {
            mailxx::detail::append_space(line);
            mailxx::detail::append_sv(line, cmd);
        }

        dialog_type* dlg = nullptr;
        MAILXX_CO_TRY_ASSIGN(dlg, dialog_ptr());
        MAILXX_TRY_CO_AWAIT(dlg->write_line_r(line));
        response resp;
        MAILXX_CO_TRY_ASSIGN(resp, co_await read_response_impl(*dlg, tag, cmd));
        co_return finalize_response(std::move(resp), cmd);
    }

    result_void enforce_auth_tls_policy(dialog_type& dlg)
    {
        if (dlg.stream().is_tls() || !options_.require_tls_for_auth)
            return mailxx::ok();
        if (options_.allow_cleartext_auth)
        {
            MAILXX_WARN("AUTH without TLS allowed by configuration.");
            return mailxx::ok();
        }
        return mailxx::fail<void>(
            mailxx::errc::imap_invalid_state,
            "TLS required for authentication; call start_tls() or use tls_mode::implicit",
            imap_detail({}, "AUTH", "tls required", 0, 0));
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

    awaitable<result<response>> command_with_one_continuation(
        std::string_view cmd, std::string_view continuation_line)
    {
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(cmd, "command"));
        MAILXX_CO_TRY_VOID(mailxx::detail::ensure_no_crlf_or_nul(continuation_line, "continuation"));

        std::string tag = std::to_string(++tag_counter_);

        std::string line = tag;
        if (!cmd.empty())
        {
            mailxx::detail::append_space(line);
            mailxx::detail::append_sv(line, cmd);
        }

        dialog_type* dlg = nullptr;
        MAILXX_CO_TRY_ASSIGN(dlg, dialog_ptr());
        MAILXX_TRY_CO_AWAIT(dlg->write_line_r(line));

        response resp;
        resp.tag = tag;

        bool continuation_sent = false;
        while (true)
        {
            std::string resp_line;
            MAILXX_CO_TRY_ASSIGN(resp_line, co_await dlg->read_line_r());
            handle_line(resp, resp_line, tag);

            std::size_t literal_size = 0;
            if (extract_literal_size(resp_line, literal_size))
            {
                std::string literal;
                MAILXX_CO_TRY_ASSIGN(literal, co_await dlg->read_exactly_r(literal_size));
                if (literal.size() != literal_size)
                {
                    co_return imap_fail<response>(
                        error_kind::parse,
                        "IMAP literal size mismatch.",
                        tag,
                        cmd,
                        resp_line,
                        resp);
                }
                resp.literals.push_back(std::move(literal));
            }

            if (!continuation_sent && !resp_line.empty() && resp_line[0] == '+')
            {
                continuation_sent = true;
                MAILXX_TRY_CO_AWAIT(dlg->write_line_r(continuation_line));
            }

            if (is_tagged_line(resp_line, tag))
                break;
        }

        if (!continuation_sent)
        {
            if (resp.st == status::no)
            {
                co_return imap_fail<response>(
                    error_kind::tagged_no,
                    "IMAP tagged NO.",
                    tag,
                    cmd,
                    tagged_line_or_text(resp),
                    resp);
            }
            if (resp.st == status::bad)
            {
                co_return imap_fail<response>(
                    error_kind::tagged_bad,
                    "IMAP tagged BAD.",
                    tag,
                    cmd,
                    tagged_line_or_text(resp),
                    resp);
            }
            if (resp.st == status::unknown)
            {
                co_return imap_fail<response>(
                    error_kind::parse,
                    "IMAP parse error.",
                    tag,
                    cmd,
                    tagged_line_or_text(resp),
                    resp);
            }
            co_return imap_fail<response>(
                error_kind::continuation_expected,
                "IMAP continuation expected.",
                tag,
                cmd,
                tagged_line_or_text(resp),
                resp);
        }

        co_return finalize_response(std::move(resp), cmd);
    }

    awaitable<result<response>> append_raw_impl(std::string_view mailbox, std::string_view data,
        std::string_view flags, std::string_view date_time)
    {
        const bool use_literal_plus = literal_plus_.has_value() && *literal_plus_;
        std::string cmd;
        MAILXX_CO_TRY_ASSIGN(cmd, mailxx::imap::detail::build_append_command(
            mailbox, data.size(), flags, date_time, use_literal_plus));

        std::string tag = std::to_string(++tag_counter_);
        std::string line = tag;
        mailxx::detail::append_space(line);
        mailxx::detail::append_sv(line, cmd);

        dialog_type* dlg = nullptr;
        MAILXX_CO_TRY_ASSIGN(dlg, dialog_ptr());
        MAILXX_TRY_CO_AWAIT(dlg->write_line_r(line));

        response resp;
        resp.tag = tag;

        if (!use_literal_plus)
        {
            bool got_continuation = false;
            while (true)
            {
                std::string resp_line;
                MAILXX_CO_TRY_ASSIGN(resp_line, co_await dlg->read_line_r());
                handle_line(resp, resp_line, tag);
                std::size_t literal_size = 0;
                if (extract_literal_size(resp_line, literal_size))
                {
                    std::string literal;
                    MAILXX_CO_TRY_ASSIGN(literal, co_await dlg->read_exactly_r(literal_size));
                    if (literal.size() != literal_size)
                    {
                        co_return imap_fail<response>(
                            error_kind::parse,
                            "IMAP literal size mismatch.",
                            tag,
                            cmd,
                            resp_line,
                            resp);
                    }
                    resp.literals.push_back(std::move(literal));
                }

                if (!resp_line.empty() && resp_line[0] == '+')
                {
                    got_continuation = true;
                    break;
                }

                if (is_tagged_line(resp_line, tag))
                {
                    if (resp.st == status::no)
                    {
                        co_return imap_fail<response>(
                            error_kind::tagged_no,
                            "IMAP tagged NO.",
                            tag,
                            cmd,
                            tagged_line_or_text(resp),
                            resp);
                    }
                    if (resp.st == status::bad)
                    {
                        co_return imap_fail<response>(
                            error_kind::tagged_bad,
                            "IMAP tagged BAD.",
                            tag,
                            cmd,
                            tagged_line_or_text(resp),
                            resp);
                    }
                    if (resp.st == status::unknown)
                    {
                        co_return imap_fail<response>(
                            error_kind::parse,
                            "IMAP parse error.",
                            tag,
                            cmd,
                            tagged_line_or_text(resp),
                            resp);
                    }
                    co_return imap_fail<response>(
                        error_kind::continuation_expected,
                        "IMAP continuation expected.",
                        tag,
                        cmd,
                        tagged_line_or_text(resp),
                        resp);
                }
            }

            if (!got_continuation)
            {
                co_return imap_fail<response>(
                    error_kind::continuation_expected,
                    "IMAP continuation expected.",
                    tag,
                    cmd,
                    tagged_line_or_text(resp),
                    resp);
            }
        }

        trace_payload("APPEND", data.size());
        MAILXX_TRY_CO_AWAIT(dlg->write_raw_r(buffer(data.data(), data.size())));
        MAILXX_TRY_CO_AWAIT(read_response_until_tag(*dlg, resp, tag, cmd));
        co_return finalize_response(std::move(resp), cmd);
    }

    class counting_sink : public mailxx::detail::output_sink
    {
    public:
        void write(std::string_view chunk) override { size_ += chunk.size(); }
        std::size_t size() const noexcept { return size_; }

    private:
        std::size_t size_{0};
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

    class streaming_sink : public mailxx::detail::output_sink
    {
    public:
        streaming_sink(streaming_queue* queue, std::size_t flush_threshold = 8192)
            : queue_(queue), flush_threshold_(flush_threshold)
        {
            buffer_.reserve(flush_threshold_);
        }

        void write(std::string_view chunk) override
        {
            buffer_.append(chunk.data(), chunk.size());
            if (buffer_.size() >= flush_threshold_)
                flush_buffer();
        }

        void finalize() { flush_buffer(); }

    private:
        void flush_buffer()
        {
            if (buffer_.empty())
                return;
            if (queue_)
                queue_->push(std::move(buffer_));
            buffer_.clear();
            buffer_.reserve(flush_threshold_);
        }

        streaming_queue* queue_;
        std::size_t flush_threshold_;
        std::string buffer_;
    };

    awaitable<result<response>> append_streaming_impl(std::string_view mailbox, const mailxx::message& msg,
        std::string_view flags, std::string_view date_time)
    {
        counting_sink cnt_sink;
        message_format_options_t fmt_opts;
        fmt_opts.dot_escape = false;
        fmt_opts.add_bcc_header = false;
        auto fmt_res = msg.format_to_result(cnt_sink, fmt_opts);
        if (!fmt_res)
            co_return mailxx::fail<response>(std::move(fmt_res).error());
        const std::size_t literal_size = cnt_sink.size();

        const bool use_literal_plus = literal_plus_.has_value() && *literal_plus_;
        std::string cmd;
        MAILXX_CO_TRY_ASSIGN(cmd, mailxx::imap::detail::build_append_command(
            mailbox, literal_size, flags, date_time, use_literal_plus));

        std::string tag = std::to_string(++tag_counter_);
        std::string line = tag;
        mailxx::detail::append_space(line);
        mailxx::detail::append_sv(line, cmd);

        dialog_type* dlg = nullptr;
        MAILXX_CO_TRY_ASSIGN(dlg, dialog_ptr());
        MAILXX_TRY_CO_AWAIT(dlg->write_line_r(line));

        response resp;
        resp.tag = tag;

        if (!use_literal_plus)
        {
            while (true)
            {
                std::string resp_line;
                MAILXX_CO_TRY_ASSIGN(resp_line, co_await dlg->read_line_r());
                handle_line(resp, resp_line, tag);
                update_literal_plus_from_line(resp_line);
                if (!resp_line.empty() && resp_line[0] == '+')
                    break;
                if (is_tagged_line(resp_line, tag))
                {
                    co_return imap_fail<response>(
                        error_kind::continuation_expected,
                        "IMAP continuation expected.",
                        tag,
                        cmd,
                        tagged_line_or_text(resp),
                        resp);
                }
            }
        }

        streaming_queue queue;
        streaming_sink data_sink(&queue);
        std::exception_ptr producer_error;
        std::thread producer([&, fmt_opts] {
            try
            {
                auto res = msg.format_to_result(data_sink, fmt_opts);
                if (!res)
                {
                    queue.set_error(res.error().message);
                    return;
                }
                data_sink.finalize();
                queue.set_done();
            }
            catch (...)
            {
                producer_error = std::current_exception();
                queue.set_error("format exception");
            }
        });

        std::string chunk;
        while (queue.pop(chunk))
        {
            auto write_res = co_await dlg->write_raw_r(buffer(chunk));
            if (!write_res)
            {
                queue.set_done();
                if (producer.joinable())
                    producer.join();
                co_return mailxx::fail<response>(std::move(write_res).error());
            }
        }
        queue.set_done();
        if (producer.joinable())
            producer.join();
        if (producer_error)
        {
            try { std::rethrow_exception(producer_error); }
            catch (const std::exception& exc)
            {
                co_return fail<response>(errc::imap_tagged_bad, "mime format error", exc.what());
            }
        }
        if (queue.has_error())
            co_return fail<response>(errc::imap_tagged_bad, "mime format error", queue.error_msg());

        while (true)
        {
            std::string resp_line;
            MAILXX_CO_TRY_ASSIGN(resp_line, co_await dlg->read_line_r());
            handle_line(resp, resp_line, tag);
            update_literal_plus_from_line(resp_line);
            std::size_t literal_resp = 0;
            if (extract_literal_size(resp_line, literal_resp))
            {
                std::string literal;
                MAILXX_CO_TRY_ASSIGN(literal, co_await dlg->read_exactly_r(literal_resp));
                if (literal.size() != literal_resp)
                {
                    co_return imap_fail<response>(
                        error_kind::parse,
                        "IMAP literal size mismatch.",
                        tag,
                        cmd,
                        resp_line,
                        resp);
                }
                resp.literals.push_back(std::move(literal));
            }
            if (is_tagged_line(resp_line, tag))
                break;
        }

        co_return finalize_response(std::move(resp), cmd);
    }

    awaitable<result<response>> read_response_impl(dialog_type& dlg, const std::string& tag, std::string_view command)
    {
        response resp;
        resp.tag = tag;

        MAILXX_TRY_CO_AWAIT(read_response_until_tag(dlg, resp, tag, command));
        co_return mailxx::ok(std::move(resp));
    }

    awaitable<result_void> read_response_until_tag(dialog_type& dlg, response& resp, const std::string& tag,
        std::string_view command)
    {
        while (true)
        {
            std::string line;
            MAILXX_CO_TRY_ASSIGN(line, co_await dlg.read_line_r());
            handle_line(resp, line, tag);

            std::size_t literal_size = 0;
            if (extract_literal_size(line, literal_size))
            {
                std::string literal;
                MAILXX_CO_TRY_ASSIGN(literal, co_await dlg.read_exactly_r(literal_size));
                if (literal.size() != literal_size)
                {
                    co_return imap_fail<void>(
                        error_kind::parse,
                        "IMAP literal size mismatch.",
                        tag,
                        command,
                        line,
                        resp);
                }
                resp.literals.push_back(std::move(literal));
            }

            if (is_tagged_line(line, tag))
                break;
        }
        co_return mailxx::ok();
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

    result<response> finalize_response(response&& resp, std::string_view command)
    {
        if (resp.st == status::no)
        {
            return imap_fail<response>(
                error_kind::tagged_no,
                "IMAP tagged NO.",
                resp.tag,
                command,
                tagged_line_or_text(resp),
                resp);
        }
        if (resp.st == status::bad)
        {
            return imap_fail<response>(
                error_kind::tagged_bad,
                "IMAP tagged BAD.",
                resp.tag,
                command,
                tagged_line_or_text(resp),
                resp);
        }
        if (resp.st == status::unknown)
        {
            return imap_fail<response>(
                error_kind::parse,
                "IMAP parse error.",
                resp.tag,
                command,
                tagged_line_or_text(resp),
                resp);
        }
        return mailxx::ok(std::move(resp));
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

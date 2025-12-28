#pragma once

#include <chrono>
#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <cstddef>
#include <system_error>
#include <mailxx/codec/codec.hpp>
#include <mailxx/detail/append.hpp>
#include <mailxx/detail/sanitize.hpp>
#include <mailxx/imap/utf7.hpp>
#include <mailxx/net/dialog.hpp>
#include <mailxx/net/tls_options.hpp>
#include <mailxx/net/upgradable_stream.hpp>

namespace mailxx::imap
{

enum class status
{
    ok,
    no,
    bad,
    preauth,
    bye,
    unknown
};

enum class auth_method
{
    login,
    plain,
    xoauth2,
    auto_detect
};

struct credentials
{
    std::string username;
    std::string secret; // password or bearer token
};

[[nodiscard]] inline std::string to_astring(std::string_view text)
{
    mailxx::detail::ensure_no_crlf_or_nul(text, "astring");
    std::string escaped = mailxx::codec::escape_string(std::string(text), "\"\\");
    return mailxx::codec::surround_string(escaped);
}

[[nodiscard]] inline std::string to_mailbox(std::string_view utf8_mailbox)
{
    return to_astring(mailxx::encode_modified_utf7(utf8_mailbox));
}

struct mailbox_stat
{
    std::uint32_t messages_no = 0;
    std::uint32_t recent = 0;
    std::uint32_t unseen = 0;
    std::uint32_t uid_next = 0;
    std::uint32_t uid_validity = 0;
};

struct mailbox_folder
{
    std::string name;
    char delimiter = '/';
    std::vector<std::string> attributes;
};

namespace detail
{
    [[nodiscard]] inline std::string_view ltrim(std::string_view text)
    {
        while (!text.empty() && text.front() == ' ')
            text.remove_prefix(1);
        return text;
    }

    [[nodiscard]] inline bool iequals_ascii(std::string_view a, std::string_view b)
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

    [[nodiscard]] inline std::pair<std::string_view, std::string_view> split_token(std::string_view text)
    {
        text = ltrim(text);
        auto pos = text.find(' ');
        if (pos == std::string_view::npos)
            return {text, std::string_view{}};
        return {text.substr(0, pos), ltrim(text.substr(pos + 1))};
    }

    [[nodiscard]] inline bool parse_uint32(std::string_view token, std::uint32_t& out)
    {
        if (token.empty())
            return false;
        std::uint32_t value = 0;
        auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value);
        if (ec != std::errc{} || ptr != token.data() + token.size())
            return false;
        out = value;
        return true;
    }

    [[nodiscard]] inline std::string build_append_command(std::string_view mailbox, std::size_t size,
        std::string_view flags, std::string_view date_time, bool literal_plus)
    {
        mailxx::detail::ensure_no_crlf_or_nul(mailbox, "mailbox");
        mailxx::detail::ensure_no_crlf_or_nul(flags, "flags");
        mailxx::detail::ensure_no_crlf_or_nul(date_time, "date_time");

        const std::string mailbox_q = mailxx::imap::to_mailbox(mailbox);
        std::string cmd;
        mailxx::detail::append_sv(cmd, "APPEND");
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_sv(cmd, mailbox_q);
        if (!flags.empty())
        {
            mailxx::detail::append_space(cmd);
            mailxx::detail::append_sv(cmd, flags);
        }
        if (!date_time.empty())
        {
            const std::string dt = mailxx::imap::to_astring(date_time);
            mailxx::detail::append_space(cmd);
            mailxx::detail::append_sv(cmd, dt);
        }
        mailxx::detail::append_space(cmd);
        mailxx::detail::append_char(cmd, '{');
        mailxx::detail::append_uint(cmd, static_cast<std::uint64_t>(size));
        if (literal_plus)
            mailxx::detail::append_char(cmd, '+');
        mailxx::detail::append_char(cmd, '}');
        return cmd;
    }
} // namespace detail

[[nodiscard]] inline bool parse_exists(std::string_view line, std::uint32_t& out)
{
    line = detail::ltrim(line);
    auto [star, rest] = detail::split_token(line);
    if (star != "*")
        return false;
    auto [num, rest2] = detail::split_token(rest);
    if (!detail::parse_uint32(num, out))
        return false;
    auto [keyword, rest3] = detail::split_token(rest2);
    (void)rest3;
    return detail::iequals_ascii(keyword, "EXISTS");
}

[[nodiscard]] inline bool parse_recent(std::string_view line, std::uint32_t& out)
{
    line = detail::ltrim(line);
    auto [star, rest] = detail::split_token(line);
    if (star != "*")
        return false;
    auto [num, rest2] = detail::split_token(rest);
    if (!detail::parse_uint32(num, out))
        return false;
    auto [keyword, rest3] = detail::split_token(rest2);
    (void)rest3;
    return detail::iequals_ascii(keyword, "RECENT");
}

[[nodiscard]] inline bool parse_ok_item(std::string_view line, std::string_view key, std::uint32_t& out)
{
    line = detail::ltrim(line);
    auto [star, rest] = detail::split_token(line);
    if (star != "*")
        return false;
    auto [ok_word, rest2] = detail::split_token(rest);
    if (!detail::iequals_ascii(ok_word, "OK"))
        return false;
    rest2 = detail::ltrim(rest2);
    if (rest2.empty() || rest2.front() != '[')
        return false;
    auto close = rest2.find(']');
    if (close == std::string_view::npos)
        return false;
    std::string_view inner = rest2.substr(1, close - 1);
    auto [inner_key, inner_rest] = detail::split_token(inner);
    if (!detail::iequals_ascii(inner_key, key))
        return false;
    auto [value_token, ignored] = detail::split_token(inner_rest);
    (void)ignored;
    return detail::parse_uint32(value_token, out);
}

[[nodiscard]] inline bool parse_unseen(std::string_view line, std::uint32_t& out)
{
    return parse_ok_item(line, "UNSEEN", out);
}

[[nodiscard]] inline bool parse_uidnext(std::string_view line, std::uint32_t& out)
{
    return parse_ok_item(line, "UIDNEXT", out);
}

[[nodiscard]] inline bool parse_uidvalidity(std::string_view line, std::uint32_t& out)
{
    return parse_ok_item(line, "UIDVALIDITY", out);
}

inline void parse_mailbox_stat(std::string_view line, mailbox_stat& stat)
{
    std::uint32_t value = 0;
    if (parse_exists(line, value))
    {
        stat.messages_no = value;
        return;
    }
    if (parse_recent(line, value))
    {
        stat.recent = value;
        return;
    }
    if (parse_unseen(line, value))
    {
        stat.unseen = value;
        return;
    }
    if (parse_uidnext(line, value))
    {
        stat.uid_next = value;
        return;
    }
    if (parse_uidvalidity(line, value))
    {
        stat.uid_validity = value;
        return;
    }
}

[[nodiscard]] inline std::vector<std::uint32_t> parse_search_ids(std::string_view line)
{
    std::vector<std::uint32_t> ids;
    line = detail::ltrim(line);
    auto [star, rest] = detail::split_token(line);
    if (star != "*")
        return ids;
    auto [keyword, rest2] = detail::split_token(rest);
    if (!detail::iequals_ascii(keyword, "SEARCH"))
        return ids;
    rest2 = detail::ltrim(rest2);
    while (!rest2.empty())
    {
        auto [id_token, remaining] = detail::split_token(rest2);
        std::uint32_t value = 0;
        if (!detail::parse_uint32(id_token, value))
            break;
        ids.push_back(value);
        rest2 = remaining;
    }
    return ids;
}

struct response
{
    std::string tag;
    status st = status::unknown;
    std::string text;
    std::vector<std::string> untagged_lines;
    std::vector<std::string> continuation;
    std::vector<std::string> tagged_lines;
    std::vector<std::string> literals;
};

struct options
{
    std::size_t max_line_length = mailxx::net::DEFAULT_MAX_LINE_LENGTH;
    std::optional<std::chrono::steady_clock::duration> timeout = std::nullopt;
    std::string default_sni;
    bool auto_starttls = false;
    bool allow_cleartext_auth = false;
    bool require_tls_for_auth = true;
    mailxx::net::tls_options tls;
    mailxx::net::tls_mode default_tls_mode = mailxx::net::tls_mode::none;
    bool redact_secrets_in_trace = true;
};

} // namespace mailxx::imap

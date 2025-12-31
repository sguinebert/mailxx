/*

error_mapping.hpp
-----------------

Centralized mapping between SMTP reply codes and mailxx::errc.

*/

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <mailxx/detail/result.hpp>
#include <mailxx/smtp/types.hpp>

namespace mailxx::smtp
{

enum class command_kind
{
    greeting,
    ehlo,
    helo,
    starttls,
    auth,
    mail_from,
    rcpt_to,
    data_cmd,
    data_body,
    rset,
    noop,
    quit,
    other
};

[[nodiscard]] constexpr std::string_view command_name(command_kind k) noexcept
{
    switch (k)
    {
        case command_kind::greeting: return "greeting";
        case command_kind::ehlo: return "ehlo";
        case command_kind::helo: return "helo";
        case command_kind::starttls: return "starttls";
        case command_kind::auth: return "auth";
        case command_kind::mail_from: return "mail_from";
        case command_kind::rcpt_to: return "rcpt_to";
        case command_kind::data_cmd: return "data_cmd";
        case command_kind::data_body: return "data_body";
        case command_kind::rset: return "rset";
        case command_kind::noop: return "noop";
        case command_kind::quit: return "quit";
        case command_kind::other: return "other";
    }
    return "other";
}

[[nodiscard]] constexpr bool is_temporary(int code) noexcept
{
    return code >= 400 && code < 500;
}

[[nodiscard]] constexpr bool is_permanent(int code) noexcept
{
    return code >= 500 && code < 600;
}

[[nodiscard]] inline errc map_smtp_reply(command_kind k, int code) noexcept
{
    if (code == 421)
        return errc::smtp_service_not_available;

    if (k == command_kind::auth)
    {
        if (code == 454 || code == 530 || code == 534 || code == 535)
            return errc::smtp_auth_failed;
        if (is_temporary(code) || is_permanent(code))
            return errc::smtp_auth_failed;
    }

    if (k == command_kind::rcpt_to)
    {
        if (is_temporary(code) || is_permanent(code))
            return errc::smtp_rejected_recipient;
    }

    if (k == command_kind::mail_from)
    {
        if (is_temporary(code) || is_permanent(code))
            return errc::smtp_mail_from_rejected;
    }

    if (k == command_kind::data_cmd)
    {
        if (code != 354)
            return errc::smtp_data_rejected;
    }

    if (k == command_kind::data_body)
    {
        if (is_temporary(code) || is_permanent(code))
            return errc::smtp_data_rejected;
    }

    if (is_temporary(code))
        return errc::smtp_temporary_failure;
    if (is_permanent(code))
        return errc::smtp_permanent_failure;

    return errc::smtp_bad_reply;
}

[[nodiscard]] inline std::string find_enhanced_status(const std::vector<std::string>& lines)
{
    for (const auto& line : lines)
    {
        for (std::size_t i = 0; i + 4 < line.size(); ++i)
        {
            const char a = line[i];
            const char b = line[i + 1];
            const char c = line[i + 2];
            const char d = line[i + 3];
            const char e = line[i + 4];
            if (a >= '2' && a <= '5' &&
                b == '.' &&
                c >= '0' && c <= '9' &&
                d == '.' &&
                e >= '0' && e <= '9')
            {
                return line.substr(i, 5);
            }
        }
    }
    return {};
}

[[nodiscard]] inline mailxx::detail::error_detail make_smtp_detail(
    std::string_view host,
    std::string_view service,
    command_kind k,
    std::string_view cmd_line_redacted,
    const reply& r,
    std::string_view previous = {})
{
    mailxx::detail::error_detail detail;
    detail.add("proto", "smtp");
    detail.add("host", host);
    detail.add("service", service);
    detail.add("command", command_name(k));
    detail.add("command.line", cmd_line_redacted);
    detail.add_int("reply.code", static_cast<std::uint64_t>(r.status));
    for (std::size_t i = 0; i < r.lines.size(); ++i)
    {
        std::string key = "reply.line";
        key += std::to_string(i);
        detail.add(key, r.lines[i]);
    }
    const std::string enhanced = find_enhanced_status(r.lines);
    if (!enhanced.empty())
        detail.add("enhanced", enhanced);
    if (!previous.empty())
        detail.add("previous", previous);
    return detail;
}

} // namespace mailxx::smtp

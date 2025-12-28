/*

error_detail.hpp
----------------

Header-only helper to build structured error_detail strings without throwing
(except potential allocation failures).

Each entry is formatted as key=value\n to ease parsing and redaction.

*/

#pragma once

#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <mailxx/detail/redact.hpp>

namespace mailxx::detail
{

[[nodiscard]] inline std::string redact_if_needed(std::string_view line, bool enable_redaction)
{
    if (!enable_redaction)
        return std::string(line);
    return redact_line(line);
}

class error_detail
{
public:
    error_detail() = default;

    error_detail& add(std::string_view key, std::string_view value)
    {
        append_key(key);
        out_.append(value.data(), value.size());
        out_.push_back('\n');
        return *this;
    }

    error_detail& add_int(std::string_view key, std::uint64_t v)
    {
        append_key(key);
        char buffer[32]{};
        const auto res = std::to_chars(std::begin(buffer), std::end(buffer), v);
        if (res.ec == std::errc{})
            out_.append(buffer, static_cast<std::size_t>(res.ptr - buffer));
        else
            out_.append("0");
        out_.push_back('\n');
        return *this;
    }

    error_detail& add_ec(std::string_view key, std::error_code ec)
    {
        append_key(key);
        char buffer[32]{};
        const auto res = std::to_chars(std::begin(buffer), std::end(buffer), ec.value());
        if (res.ec == std::errc{})
            out_.append(buffer, static_cast<std::size_t>(res.ptr - buffer));
        else
            out_.append("0");

        const std::string msg = ec.message();
        if (!msg.empty())
        {
            out_.push_back(' ');
            out_.append(msg);
        }
        out_.push_back('\n');
        return *this;
    }

    error_detail& add_lines(std::string_view key_prefix, const std::vector<std::string>& lines, bool redact = false)
    {
        for (std::size_t i = 0; i < lines.size(); ++i)
        {
            out_.append(key_prefix.data(), key_prefix.size());
            append_int(i);
            out_.push_back('=');
            out_.append(redact_if_needed(lines[i], redact));
            out_.push_back('\n');
        }
        return *this;
    }

    [[nodiscard]] std::string str() const
    {
        return out_;
    }

private:
    std::string out_;

    void append_key(std::string_view key)
    {
        out_.append(key.data(), key.size());
        out_.push_back('=');
    }

    void append_int(std::uint64_t v)
    {
        char buffer[32]{};
        const auto res = std::to_chars(std::begin(buffer), std::end(buffer), v);
        if (res.ec == std::errc{})
            out_.append(buffer, static_cast<std::size_t>(res.ptr - buffer));
        else
            out_.append("0");
    }
};

} // namespace mailxx::detail

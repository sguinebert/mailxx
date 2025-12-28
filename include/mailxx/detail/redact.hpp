#pragma once

#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace mailxx::detail
{

[[nodiscard]] inline bool iequals_ascii(std::string_view a, std::string_view b) noexcept
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

[[nodiscard]] inline bool starts_with_ci(std::string_view text, std::string_view prefix) noexcept
{
    if (text.size() < prefix.size())
        return false;
    return iequals_ascii(text.substr(0, prefix.size()), prefix);
}

inline void split_tokens(std::string_view text, std::vector<std::string_view>& out)
{
    out.clear();
    while (!text.empty())
    {
        while (!text.empty() && text.front() == ' ')
            text.remove_prefix(1);
        if (text.empty())
            break;
        const auto pos = text.find(' ');
        if (pos == std::string_view::npos)
        {
            out.push_back(text);
            break;
        }
        out.push_back(text.substr(0, pos));
        text.remove_prefix(pos + 1);
    }
}

[[nodiscard]] inline bool is_base64_char(unsigned char ch) noexcept
{
    return (ch >= 'A' && ch <= 'Z')
        || (ch >= 'a' && ch <= 'z')
        || (ch >= '0' && ch <= '9')
        || ch == '+'
        || ch == '/'
        || ch == '=';
}

[[nodiscard]] inline bool looks_like_base64(std::string_view text) noexcept
{
    if (text.empty())
        return false;
    for (unsigned char ch : text)
    {
        if (!is_base64_char(ch))
            return false;
    }
    return true;
}

[[nodiscard]] inline bool has_base64_markers(std::string_view text) noexcept
{
    for (unsigned char ch : text)
    {
        if (ch == '=' || ch == '+' || ch == '/' || (ch >= '0' && ch <= '9'))
            return true;
    }
    return false;
}

[[nodiscard]] inline std::string redact_line(std::string_view line)
{
    std::string_view trimmed = line;
    while (!trimmed.empty() && (trimmed.back() == '\r' || trimmed.back() == '\n'))
        trimmed.remove_suffix(1);

    const std::string_view suffix = line.substr(trimmed.size());

    std::size_t prefix_len = 0;
    while (prefix_len < trimmed.size() && trimmed[prefix_len] == ' ')
        ++prefix_len;

    const std::string_view prefix = trimmed.substr(0, prefix_len);
    const std::string_view core = trimmed.substr(prefix_len);
    if (core.empty())
        return std::string(line);

    std::vector<std::string_view> tokens;
    split_tokens(core, tokens);
    if (tokens.empty())
        return std::string(line);

    bool redacted = false;

    if (iequals_ascii(tokens.front(), "PASS"))
    {
        if (tokens.size() >= 2)
        {
            tokens.resize(2);
            tokens[1] = "<redacted>";
            redacted = true;
        }
    }
    else if (iequals_ascii(tokens.front(), "AUTH"))
    {
        if (tokens.size() >= 3)
        {
            tokens.resize(3);
            tokens[2] = "<redacted>";
            redacted = true;
        }
    }
    else
    {
        for (std::size_t i = 0; i < tokens.size(); ++i)
        {
            if (iequals_ascii(tokens[i], "LOGIN"))
            {
                if (i + 2 < tokens.size())
                {
                    tokens.resize(i + 3);
                    tokens[i + 2] = "<redacted>";
                    redacted = true;
                }
                break;
            }
            if (iequals_ascii(tokens[i], "AUTHENTICATE"))
            {
                if (i + 1 < tokens.size())
                {
                    if (i + 2 < tokens.size())
                    {
                        tokens.resize(i + 3);
                        tokens[i + 2] = "<redacted>";
                        redacted = true;
                    }
                }
                break;
            }
        }
    }

    if (!redacted && tokens.size() == 1)
    {
        const std::string_view token = tokens.front();
        if (looks_like_base64(token)
            && (token.size() >= 12 || has_base64_markers(token)))
        {
            tokens[0] = "<redacted>";
            redacted = true;
        }
    }

    if (!redacted)
        return std::string(line);

    std::string result;
    result.reserve(prefix.size() + core.size() + suffix.size() + 16);
    result.append(prefix);
    for (std::size_t i = 0; i < tokens.size(); ++i)
    {
        if (i > 0)
            result.push_back(' ');
        result.append(tokens[i].data(), tokens[i].size());
    }
    result.append(suffix.data(), suffix.size());
    return result;
}

} // namespace mailxx::detail

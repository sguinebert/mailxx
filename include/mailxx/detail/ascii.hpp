#pragma once

#include <string>
#include <string_view>
#include <cctype>

namespace mailxx
{
namespace detail
{
    [[nodiscard]] constexpr char ascii_tolower(char c) noexcept
    {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
    }

    [[nodiscard]] inline bool iequals_ascii(std::string_view a, std::string_view b) noexcept
    {
        if (a.size() != b.size())
            return false;

        for (std::size_t i = 0; i < a.size(); ++i)
        {
            if (ascii_tolower(a[i]) != ascii_tolower(b[i]))
                return false;
        }
        return true;
    }

    [[nodiscard]] inline std::string_view trim_view(std::string_view sv) noexcept
    {
        auto is_space = [](unsigned char c) noexcept { return std::isspace(c) != 0; };

        while (!sv.empty() && is_space(static_cast<unsigned char>(sv.front())))
            sv.remove_prefix(1);
        while (!sv.empty() && is_space(static_cast<unsigned char>(sv.back())))
            sv.remove_suffix(1);
        return sv;
    }

    [[nodiscard]] inline std::string trim_copy(std::string_view sv)
    {
        sv = trim_view(sv);
        return std::string(sv);
    }

    inline void trim_inplace(std::string& s)
    {
        std::string_view sv = trim_view(s);
        if (sv.size() == s.size())
            return;
        s.assign(sv.begin(), sv.end());
    }

    // RFC 5322: field-name = 1*ftext; ftext = %d33-57 / %d59-126 (printable US-ASCII except ":")
    [[nodiscard]] inline bool is_valid_header_name(std::string_view name) noexcept
    {
        if (name.empty())
            return false;

        for (char ch : name)
        {
            unsigned char c = static_cast<unsigned char>(ch);
            const bool ok = ((c >= 33 && c <= 57) || (c >= 59 && c <= 126));
            if (!ok)
                return false;
        }
        return true;
    }

    // Conservative validation: reject CR/LF and other control characters (except TAB).
    [[nodiscard]] inline bool is_valid_header_value(std::string_view value) noexcept
    {
        for (char ch : value)
        {
            unsigned char c = static_cast<unsigned char>(ch);

            if (ch == '\r' || ch == '\n')
                return false;
            if (c < 32 && ch != '\t')
                return false;
            if (c == 127)
                return false;
        }
        return true;
    }

    [[nodiscard]] constexpr bool is_ascii_alpha(char c) noexcept
    {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    [[nodiscard]] constexpr bool is_ascii_digit(char c) noexcept
    {
        return (c >= '0' && c <= '9');
    }

    [[nodiscard]] constexpr bool is_ascii_alnum(char c) noexcept
    {
        return is_ascii_alpha(c) || is_ascii_digit(c);
    }

    // RFC 5322 "atext" punctuation (without the alphanumerics). Dot is *not* part of atext.
    inline constexpr std::string_view ATEXT_PUNCT = "!#$%&'*+-/=?^_`{|}~";

    [[nodiscard]] constexpr bool is_atext(char c) noexcept
    {
        return is_ascii_alnum(c) || (ATEXT_PUNCT.find(c) != std::string_view::npos);
    }

    [[nodiscard]] inline bool is_dot_atom_text(std::string_view s) noexcept
    {
        if (s.empty())
            return false;
        if (s.front() == '.' || s.back() == '.')
            return false;

        bool prev_dot = false;
        for (char ch : s)
        {
            if (ch == '.')
            {
                if (prev_dot)
                    return false;
                prev_dot = true;
                continue;
            }

            if (!is_atext(ch))
                return false;
            prev_dot = false;
        }
        return true;
    }

    // Strict msg-id validation (normalized: no surrounding "<>").
    [[nodiscard]] inline bool is_valid_message_id_strict(std::string_view id) noexcept
    {
        id = trim_view(id);
        if (id.size() >= 2 && id.front() == '<' && id.back() == '>')
            id = trim_view(id.substr(1, id.size() - 2));

        if (id.empty())
            return false;

        // must contain exactly one '@'
        const auto at = id.find('@');
        if (at == std::string_view::npos || at == 0 || at + 1 >= id.size())
            return false;
        if (id.find('@', at + 1) != std::string_view::npos)
            return false;

        // no whitespace / CTLs / angle brackets
        for (char ch : id)
        {
            unsigned char c = static_cast<unsigned char>(ch);
            if (ch == '<' || ch == '>')
                return false;
            if (ch == '\r' || ch == '\n')
                return false;
            if (std::isspace(c) != 0)
                return false;
            if (c < 33 || c == 127)
                return false;
        }

        const auto left = id.substr(0, at);
        const auto right = id.substr(at + 1);
        return is_dot_atom_text(left) && is_dot_atom_text(right);
    }

    // Relaxed validation: still requires "@", but allows a broader character set (no spaces/CTLS).
    [[nodiscard]] inline bool is_valid_message_id_relaxed(std::string_view id) noexcept
    {
        id = trim_view(id);
        if (id.size() >= 2 && id.front() == '<' && id.back() == '>')
            id = trim_view(id.substr(1, id.size() - 2));

        if (id.empty())
            return false;

        const auto at = id.find('@');
        if (at == std::string_view::npos || at == 0 || at + 1 >= id.size())
            return false;

        // no whitespace / CTLs / angle brackets
        for (char ch : id)
        {
            unsigned char c = static_cast<unsigned char>(ch);
            if (ch == '<' || ch == '>')
                return false;
            if (ch == '\r' || ch == '\n')
                return false;
            if (std::isspace(c) != 0)
                return false;
            if (c < 33 || c == 127)
                return false;
        }

        return true;
    }

    // Header display-name quick checks (used for quoting decisions).
    [[nodiscard]] inline bool is_name_token_char(char c) noexcept
    {
        return is_ascii_alnum(c) || c == ' ' || c == '\t';
    }

    inline constexpr std::string_view QTEXT_PUNCT = "!#$%&'()*+,-.@/:;<=>?[]^_`{|}~";

    [[nodiscard]] inline bool is_qtext_char(char c) noexcept
    {
        return is_ascii_alnum(c) || c == ' ' || c == '\t' || (QTEXT_PUNCT.find(c) != std::string_view::npos);
    }

    inline constexpr std::string_view DTEXT_PUNCT = "!#$%&'*+-./@=?^_`{|}~";

    [[nodiscard]] inline bool is_dtext_char(char c) noexcept
    {
        return is_ascii_alnum(c) || (DTEXT_PUNCT.find(c) != std::string_view::npos);
    }

    // Group name: same as atext but also allows dot.
    [[nodiscard]] inline bool is_group_name_char(char c) noexcept
    {
        return is_ascii_alnum(c) || c == '.' || (ATEXT_PUNCT.find(c) != std::string_view::npos);
    }

    [[nodiscard]] inline bool is_group_name(std::string_view s) noexcept
    {
        for (char ch : s)
        {
            if (!is_group_name_char(ch))
                return false;
        }
        return true;
    }
}
}

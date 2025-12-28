/*

utf7.hpp
--------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <stdexcept>

namespace mailxx
{

namespace imap_utf7_detail
{
inline int base64_value(char ch)
{
    if (ch >= 'A' && ch <= 'Z')
        return ch - 'A';
    if (ch >= 'a' && ch <= 'z')
        return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9')
        return ch - '0' + 52;
    if (ch == '+')
        return 62;
    if (ch == ',')
        return 63;
    return -1;
}

inline std::string encode_modified_base64(const std::vector<unsigned char>& bytes)
{
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);

    std::size_t i = 0;
    while (i + 3 <= bytes.size())
    {
        unsigned char b0 = bytes[i++];
        unsigned char b1 = bytes[i++];
        unsigned char b2 = bytes[i++];
        out.push_back(alphabet[(b0 >> 2) & 0x3F]);
        out.push_back(alphabet[((b0 & 0x03) << 4) | (b1 >> 4)]);
        out.push_back(alphabet[((b1 & 0x0F) << 2) | (b2 >> 6)]);
        out.push_back(alphabet[b2 & 0x3F]);
    }

    std::size_t remaining = bytes.size() - i;
    if (remaining == 1)
    {
        unsigned char b0 = bytes[i];
        out.push_back(alphabet[(b0 >> 2) & 0x3F]);
        out.push_back(alphabet[(b0 & 0x03) << 4]);
    }
    else if (remaining == 2)
    {
        unsigned char b0 = bytes[i];
        unsigned char b1 = bytes[i + 1];
        out.push_back(alphabet[(b0 >> 2) & 0x3F]);
        out.push_back(alphabet[((b0 & 0x03) << 4) | (b1 >> 4)]);
        out.push_back(alphabet[(b1 & 0x0F) << 2]);
    }

    return out;
}

inline std::vector<unsigned char> decode_modified_base64(std::string_view text)
{
    std::vector<unsigned char> out;
    if (text.empty())
        return out;

    if (text.size() % 4 == 1)
        throw std::invalid_argument("Invalid modified UTF-7.");

    out.reserve(text.size() * 3 / 4);
    std::size_t i = 0;

    while (i + 4 <= text.size())
    {
        int s0 = base64_value(text[i++]);
        int s1 = base64_value(text[i++]);
        int s2 = base64_value(text[i++]);
        int s3 = base64_value(text[i++]);
        if (s0 < 0 || s1 < 0 || s2 < 0 || s3 < 0)
            throw std::invalid_argument("Invalid modified UTF-7.");

        out.push_back(static_cast<unsigned char>((s0 << 2) | (s1 >> 4)));
        out.push_back(static_cast<unsigned char>((s1 << 4) | (s2 >> 2)));
        out.push_back(static_cast<unsigned char>((s2 << 6) | s3));
    }

    std::size_t remaining = text.size() - i;
    if (remaining == 2)
    {
        int s0 = base64_value(text[i++]);
        int s1 = base64_value(text[i++]);
        if (s0 < 0 || s1 < 0)
            throw std::invalid_argument("Invalid modified UTF-7.");
        out.push_back(static_cast<unsigned char>((s0 << 2) | (s1 >> 4)));
    }
    else if (remaining == 3)
    {
        int s0 = base64_value(text[i++]);
        int s1 = base64_value(text[i++]);
        int s2 = base64_value(text[i++]);
        if (s0 < 0 || s1 < 0 || s2 < 0)
            throw std::invalid_argument("Invalid modified UTF-7.");
        out.push_back(static_cast<unsigned char>((s0 << 2) | (s1 >> 4)));
        out.push_back(static_cast<unsigned char>((s1 << 4) | (s2 >> 2)));
    }
    else if (remaining != 0)
    {
        throw std::invalid_argument("Invalid modified UTF-7.");
    }

    return out;
}

inline std::uint32_t decode_utf8(std::string_view text, std::size_t& index)
{
    if (index >= text.size())
        throw std::invalid_argument("Invalid UTF-8.");

    unsigned char b0 = static_cast<unsigned char>(text[index]);
    if (b0 < 0x80)
    {
        index += 1;
        return b0;
    }

    if ((b0 >> 5) == 0x6)
    {
        if (index + 1 >= text.size())
            throw std::invalid_argument("Invalid UTF-8.");
        unsigned char b1 = static_cast<unsigned char>(text[index + 1]);
        if ((b1 & 0xC0) != 0x80)
            throw std::invalid_argument("Invalid UTF-8.");
        std::uint32_t cp = ((b0 & 0x1F) << 6) | (b1 & 0x3F);
        if (cp < 0x80)
            throw std::invalid_argument("Invalid UTF-8.");
        index += 2;
        return cp;
    }

    if ((b0 >> 4) == 0xE)
    {
        if (index + 2 >= text.size())
            throw std::invalid_argument("Invalid UTF-8.");
        unsigned char b1 = static_cast<unsigned char>(text[index + 1]);
        unsigned char b2 = static_cast<unsigned char>(text[index + 2]);
        if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80)
            throw std::invalid_argument("Invalid UTF-8.");
        std::uint32_t cp = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
        if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))
            throw std::invalid_argument("Invalid UTF-8.");
        index += 3;
        return cp;
    }

    if ((b0 >> 3) == 0x1E)
    {
        if (index + 3 >= text.size())
            throw std::invalid_argument("Invalid UTF-8.");
        unsigned char b1 = static_cast<unsigned char>(text[index + 1]);
        unsigned char b2 = static_cast<unsigned char>(text[index + 2]);
        unsigned char b3 = static_cast<unsigned char>(text[index + 3]);
        if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80)
            throw std::invalid_argument("Invalid UTF-8.");
        std::uint32_t cp = ((b0 & 0x07) << 18) | ((b1 & 0x3F) << 12) |
            ((b2 & 0x3F) << 6) | (b3 & 0x3F);
        if (cp < 0x10000 || cp > 0x10FFFF)
            throw std::invalid_argument("Invalid UTF-8.");
        index += 4;
        return cp;
    }

    throw std::invalid_argument("Invalid UTF-8.");
}

inline void append_utf16_units(std::uint32_t codepoint, std::vector<std::uint16_t>& out)
{
    if (codepoint <= 0xFFFF)
    {
        if (codepoint >= 0xD800 && codepoint <= 0xDFFF)
            throw std::invalid_argument("Invalid UTF-8.");
        out.push_back(static_cast<std::uint16_t>(codepoint));
        return;
    }

    if (codepoint > 0x10FFFF)
        throw std::invalid_argument("Invalid UTF-8.");

    std::uint32_t value = codepoint - 0x10000;
    out.push_back(static_cast<std::uint16_t>(0xD800 + (value >> 10)));
    out.push_back(static_cast<std::uint16_t>(0xDC00 + (value & 0x3FF)));
}

inline void append_utf8(std::uint32_t codepoint, std::string& out)
{
    if (codepoint <= 0x7F)
    {
        out.push_back(static_cast<char>(codepoint));
    }
    else if (codepoint <= 0x7FF)
    {
        out.push_back(static_cast<char>(0xC0 | (codepoint >> 6)));
        out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    }
    else if (codepoint <= 0xFFFF)
    {
        out.push_back(static_cast<char>(0xE0 | (codepoint >> 12)));
        out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    }
    else if (codepoint <= 0x10FFFF)
    {
        out.push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
        out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    }
    else
    {
        throw std::invalid_argument("Invalid modified UTF-7.");
    }
}
} // namespace imap_utf7_detail

inline std::string encode_modified_utf7(std::string_view utf8)
{
    std::string out;
    out.reserve(utf8.size());

    std::vector<std::uint16_t> utf16_units;

    auto flush_utf16 = [&]()
    {
        if (utf16_units.empty())
            return;

        std::vector<unsigned char> bytes;
        bytes.reserve(utf16_units.size() * 2);
        for (std::uint16_t unit : utf16_units)
        {
            bytes.push_back(static_cast<unsigned char>(unit >> 8));
            bytes.push_back(static_cast<unsigned char>(unit & 0xFF));
        }

        std::string encoded = imap_utf7_detail::encode_modified_base64(bytes);
        out.push_back('&');
        out += encoded;
        out.push_back('-');
        utf16_units.clear();
    };

    std::size_t index = 0;
    while (index < utf8.size())
    {
        std::uint32_t cp = imap_utf7_detail::decode_utf8(utf8, index);

        if (cp == '&')
        {
            flush_utf16();
            out += "&-";
            continue;
        }

        if (cp >= 0x20 && cp <= 0x7E)
        {
            flush_utf16();
            out.push_back(static_cast<char>(cp));
            continue;
        }

        imap_utf7_detail::append_utf16_units(cp, utf16_units);
    }

    flush_utf16();
    return out;
}

inline std::string decode_modified_utf7(std::string_view mutf7)
{
    std::string out;
    out.reserve(mutf7.size());

    std::size_t i = 0;
    while (i < mutf7.size())
    {
        unsigned char ch = static_cast<unsigned char>(mutf7[i]);
        if (ch & 0x80)
            throw std::invalid_argument("Invalid modified UTF-7.");

        if (ch != '&')
        {
            out.push_back(static_cast<char>(ch));
            i += 1;
            continue;
        }

        if (i + 1 >= mutf7.size())
            throw std::invalid_argument("Invalid modified UTF-7.");

        if (mutf7[i + 1] == '-')
        {
            out.push_back('&');
            i += 2;
            continue;
        }

        std::size_t end = mutf7.find('-', i + 1);
        if (end == std::string_view::npos)
            throw std::invalid_argument("Invalid modified UTF-7.");

        std::string_view b64 = mutf7.substr(i + 1, end - (i + 1));
        std::vector<unsigned char> bytes = imap_utf7_detail::decode_modified_base64(b64);
        if (bytes.size() % 2 != 0)
            throw std::invalid_argument("Invalid modified UTF-7.");

        std::size_t j = 0;
        while (j < bytes.size())
        {
            std::uint16_t unit = static_cast<std::uint16_t>((bytes[j] << 8) | bytes[j + 1]);
            j += 2;

            if (unit >= 0xD800 && unit <= 0xDBFF)
            {
                if (j + 1 >= bytes.size())
                    throw std::invalid_argument("Invalid modified UTF-7.");
                std::uint16_t low = static_cast<std::uint16_t>((bytes[j] << 8) | bytes[j + 1]);
                j += 2;
                if (low < 0xDC00 || low > 0xDFFF)
                    throw std::invalid_argument("Invalid modified UTF-7.");
                std::uint32_t cp = 0x10000 + (((unit - 0xD800) << 10) | (low - 0xDC00));
                imap_utf7_detail::append_utf8(cp, out);
            }
            else if (unit >= 0xDC00 && unit <= 0xDFFF)
            {
                throw std::invalid_argument("Invalid modified UTF-7.");
            }
            else
            {
                imap_utf7_detail::append_utf8(unit, out);
            }
        }

        i = end + 1;
    }

    return out;
}

} // namespace mailxx

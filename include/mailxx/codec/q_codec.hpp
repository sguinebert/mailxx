/*

q_codec.hpp
-----------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/


#pragma once

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4251)
#endif

#include <cctype>
#include <string>
#include <vector>
#include <tuple>
#include <boost/algorithm/string.hpp>
#include <mailxx/codec/codec.hpp>
#include <mailxx/codec/base64.hpp>
#include <mailxx/detail/result.hpp>
#include <mailxx/config.hpp>


namespace mailxx
{


/**
Q codec.

ASCII and UTF-8 charsets are recognized.
**/
class MAILXX_EXPORT q_codec : public codec
{
public:

    /**
    Setting the encoder and decoder line policies.

    @param line1_policy First line policy to set.
    @param lines_policy Other lines policy than the first one to set.
    @param codec_method Method for encoding/decoding.
    **/
    q_codec(std::string::size_type line1_policy, std::string::size_type lines_policy)
        : codec(line1_policy, lines_policy)
    {
    }

    q_codec(const q_codec&) = delete;

    q_codec(q_codec&&) = delete;

    /**
    Default destructor.
    **/
    ~q_codec() = default;

    void operator=(const q_codec&) = delete;

    void operator=(q_codec&&) = delete;

    /**
    Encoding a text by applying the given method.

    `header_prefix_len` is the length already consumed on the first line (`From: ` and
    the same). The first encoded word fits in `line1_policy - header_prefix_len`.
    Continuation words fit in `lines_policy` after a two-space indent when a prefix
    was given. The encoded-word delimiters and the charset are subtracted from both.

    @param text              String to encode.
    @param charset           Charset used by the string.
    @param method            Allowed encoding methods.
    @param header_prefix_len Characters already used on the first header line.
    @return                  Encoded words, each including its `=?...?=` wrapper.
    **/
    result<std::vector<std::string>> encode(const std::string& text, const std::string& charset, codec_t method,
        std::string::size_type header_prefix_len = 0) const
    {
        const std::string charset_up = boost::to_upper_copy(charset);
        const std::string::size_type overhead = ENCODED_WORD_FIXED + charset_up.size();
        if (line1_policy_ <= header_prefix_len + overhead || lines_policy_ <= overhead)
            return fail<std::vector<std::string>>(errc::codec_invalid_input, "invalid Q encoding", "line policy too small");

        const std::string::size_type first_room = line1_policy_ - header_prefix_len - overhead;
        const std::string::size_type continuation_indent = header_prefix_len == 0 ? 0 : NEW_LINE_INDENT;
        if (lines_policy_ <= continuation_indent + overhead)
            return fail<std::vector<std::string>>(errc::codec_invalid_input, "invalid Q encoding", "line policy too small");
        const std::string::size_type next_room = lines_policy_ - continuation_indent - overhead;

        std::vector<std::string> text_c;
        std::string codec_flag;
        if (method == codec_t::BASE64)
        {
            codec_flag = BASE64_CODEC_STR;
            base64 b64(first_room, next_room);
            text_c = b64.encode(text);
        }
        else if (method == codec_t::QUOTED_PRINTABLE)
        {
            codec_flag = QP_CODEC_STR;
            auto enc_res = encode_q_payload(text, first_room, next_room);
            if (!enc_res)
                return fail<std::vector<std::string>>(std::move(enc_res).error());
            text_c = std::move(*enc_res);
        }
        else
            return fail<std::vector<std::string>>(errc::codec_invalid_input, "invalid Q encoding method");

        const std::string prefix = std::string(ENCODED_WORD_START) + charset_up + ENCODED_WORD_SEP + codec_flag + ENCODED_WORD_SEP;
        std::vector<std::string> enc_text;
        enc_text.reserve(text_c.size());
        for (const auto& chunk : text_c)
        {
            if (chunk.empty())
                continue;
            enc_text.push_back(prefix + chunk + std::string(ENCODED_WORD_END));
        }

        return ok(std::move(enc_text));
    }

    /**
    Decoding a string.

    @param text        String to decode.
    @return            Decoded string, its charset and its codec method.
    **/
    result<std::tuple<std::string, std::string, codec_t>> decode(const std::string& text) const
    {
        std::string::size_type charset_pos = text.find(QUESTION_MARK_CHAR);
        if (charset_pos == std::string::npos)
            return fail<std::tuple<std::string, std::string, codec_t>>(errc::codec_invalid_input,
                "invalid Q encoding", "missing charset separator");
        std::string::size_type method_pos = text.find(QUESTION_MARK_CHAR, charset_pos + 1);
        if (method_pos == std::string::npos)
            return fail<std::tuple<std::string, std::string, codec_t>>(errc::codec_invalid_input,
                "invalid Q encoding", "missing codec type separator");
        std::string charset = boost::to_upper_copy(text.substr(charset_pos + 1, method_pos - charset_pos - 1));
        if (charset.empty() || !is_charset_token(charset))
            return fail<std::tuple<std::string, std::string, codec_t>>(errc::codec_invalid_input,
                "invalid Q encoding", "missing charset");
        std::string::size_type content_pos = text.find(QUESTION_MARK_CHAR, method_pos + 1);
        if (content_pos == std::string::npos)
            return fail<std::tuple<std::string, std::string, codec_t>>(errc::codec_invalid_input,
                "invalid Q encoding", "missing content separator");
        std::string method = text.substr(method_pos + 1, content_pos - method_pos - 1);
        codec_t method_type;
        std::string text_c = text.substr(content_pos + 1);

        std::string dec_text;
        if (boost::iequals(method, BASE64_CODEC_STR))
        {
            base64 b64(line1_policy_, lines_policy_);
            auto decoded = b64.decode(text_c);
            if (!decoded)
            {
                std::string detail = format_codec_error(decoded.error());
                return fail<std::tuple<std::string, std::string, codec_t>>(errc::codec_invalid_input,
                    "invalid Q encoding", std::move(detail));
            }
            dec_text = std::move(*decoded);
            method_type = codec_t::BASE64;
        }
        else if (boost::iequals(method, QP_CODEC_STR))
        {
            auto decoded = decode_qp(text_c);
            if (!decoded)
                return fail<std::tuple<std::string, std::string, codec_t>>(std::move(decoded).error());
            dec_text = std::move(*decoded);
            method_type = codec_t::QUOTED_PRINTABLE;
        }
        else
            return fail<std::tuple<std::string, std::string, codec_t>>(errc::codec_invalid_input,
                "invalid Q encoding", "bad encoding method");

        return ok(std::make_tuple(std::move(dec_text), std::move(charset), method_type));
    }

    /**
    Checking if a string is Q encoded and decodes it.

    @param text        String to decode.
    @return            Decoded string, its charset and its codec method.
    The result stays text, charset, and codec. The caller builds a `string_t` when it needs one.
    **/
    result<std::tuple<std::string, std::string, codec_t>> check_decode(const std::string& text) const
    {
        std::string::size_type question_mark_counter = 0;
        const std::string::size_type QUESTION_MARKS_NO = 4;
        bool is_encoded = false;
        bool just_decoded_encoded_word = false;
        std::string dec_text, encoded_part;
        std::string charset = CHARSET_ASCII;
        // If there is no q encoding, then it's ascii or utf8.
        codec_t method_type = codec_t::ASCII;

        for (auto ch = text.begin(); ch != text.end(); ch++)
        {
            if (*ch == codec::QUESTION_MARK_CHAR)
                ++question_mark_counter;

            if (*ch == codec::EQUAL_CHAR && ch + 1 != text.end() && *(ch + 1) == codec::QUESTION_MARK_CHAR && !is_encoded)
                is_encoded = true;
            else if (*ch == codec::QUESTION_MARK_CHAR && ch + 1 != text.end() && *(ch + 1) == codec::EQUAL_CHAR && question_mark_counter == QUESTION_MARKS_NO)
            {
                is_encoded = false;
                question_mark_counter = 0;
                auto text_charset = decode(encoded_part);
                if (!text_charset)
                    return fail<std::tuple<std::string, std::string, codec_t>>(std::move(text_charset).error());
                dec_text += std::get<0>(*text_charset);
                charset = std::get<1>(*text_charset);
                method_type = std::get<2>(*text_charset);
                just_decoded_encoded_word = true;

                encoded_part.clear();
                ch++;
            }
            else if (is_encoded == true)
                encoded_part.append(1, *ch);
            else if (just_decoded_encoded_word && std::isspace(static_cast<unsigned char>(*ch)))
            {
                auto next = ch;
                while (next != text.end() && std::isspace(static_cast<unsigned char>(*next)))
                    ++next;

                if (next != text.end() && *next == codec::EQUAL_CHAR && next + 1 != text.end() && *(next + 1) == codec::QUESTION_MARK_CHAR)
                    continue;

                dec_text.append(1, *ch);
                just_decoded_encoded_word = false;
            }
            else
            {
                dec_text.append(1, *ch);
                just_decoded_encoded_word = false;
            }
        }

        if (is_encoded && question_mark_counter < QUESTION_MARKS_NO)
            return fail<std::tuple<std::string, std::string, codec_t>>(errc::codec_invalid_input,
                "invalid Q encoding", "bad Q codec format");

        return ok(std::make_tuple(std::move(dec_text), std::move(charset), method_type));
    }

private:
    static std::string format_codec_error(const error_info& err)
    {
        if (err.detail.empty())
            return err.message;
        std::string detail = err.message;
        detail += ": ";
        detail += err.detail;
        return detail;
    }

    /**
    String representation of Base64 method.
    **/
    inline static const std::string BASE64_CODEC_STR{"B"};

    /**
    String representation of Quoted Printable method.
    **/
    inline static const std::string QP_CODEC_STR{"Q"};

    static constexpr std::string_view ENCODED_WORD_START{"=?"};
    static constexpr char ENCODED_WORD_SEP = '?';
    static constexpr std::string_view ENCODED_WORD_END{"?="};
    static constexpr std::string::size_type ENCODED_WORD_FIXED = 7;
    static constexpr std::string::size_type NEW_LINE_INDENT = 2;

    /**
    Decoding by using variation of the Quoted Printable method.

    @param text String to decode.
    @return     Decoded string.
    **/
    result<std::string> decode_qp(const std::string& text) const
    {
        std::string dec_text;
        dec_text.reserve(text.size());
        for (std::string::size_type i = 0; i < text.size(); ++i)
        {
            const unsigned char ch = static_cast<unsigned char>(text[i]);
            if (ch == static_cast<unsigned char>(UNDERSCORE_CHAR))
            {
                dec_text.push_back(SPACE_CHAR);
                continue;
            }
            if (ch != static_cast<unsigned char>(EQUAL_CHAR))
            {
                dec_text.push_back(static_cast<char>(ch));
                continue;
            }
            if (i + 2 >= text.size())
                return fail<std::string>(errc::codec_invalid_input, "invalid Q encoding", "truncated hexadecimal");
            const char high = std::toupper(static_cast<unsigned char>(text[i + 1]));
            const char low = std::toupper(static_cast<unsigned char>(text[i + 2]));
            if (HEX_DIGITS.find(high) == std::string::npos || HEX_DIGITS.find(low) == std::string::npos)
                return fail<std::string>(errc::codec_invalid_input, "invalid Q encoding", "bad hexadecimal digit");
            dec_text.push_back(static_cast<char>((hex_digit_to_int(high) << 4) + hex_digit_to_int(low)));
            i += 2;
        }
        return ok(std::move(dec_text));
    }

    result<std::vector<std::string>> encode_q_payload(const std::string& text, std::string::size_type first_room,
        std::string::size_type next_room) const
    {
        std::vector<std::string> lines;
        std::string line;
        std::string::size_type room = first_room;
        auto break_line = [&]()
        {
            if (!line.empty())
                lines.push_back(std::move(line));
            line.clear();
            room = next_room;
        };

        for (unsigned char ch : text)
        {
            std::string atom;
            if (ch == static_cast<unsigned char>(SPACE_CHAR))
                atom = std::string(1, UNDERSCORE_CHAR);
            else if (ch > static_cast<unsigned char>(SPACE_CHAR) && ch <= static_cast<unsigned char>(TILDE_CHAR) &&
                ch != static_cast<unsigned char>(EQUAL_CHAR) && ch != static_cast<unsigned char>(QUESTION_MARK_CHAR) &&
                ch != static_cast<unsigned char>(UNDERSCORE_CHAR))
                atom = std::string(1, static_cast<char>(ch));
            else
            {
                atom.push_back(EQUAL_CHAR);
                atom.push_back(HEX_DIGITS[(ch >> 4) & 0x0F]);
                atom.push_back(HEX_DIGITS[ch & 0x0F]);
            }

            if (!line.empty() && line.size() + atom.size() > room)
                break_line();
            if (atom.size() > room)
                return fail<std::vector<std::string>>(errc::codec_invalid_input, "invalid Q encoding", "line policy too small");
            line += atom;
        }
        if (!line.empty())
            lines.push_back(std::move(line));
        return ok(std::move(lines));
    }

    static bool is_charset_token(const std::string& charset)
    {
        if (charset.empty())
            return false;
        for (unsigned char ch : charset)
        {
            if (std::isalnum(ch) || ch == '-' || ch == '_')
                continue;
            return false;
        }
        return true;
    }

    /**
    Checking if a character is allowed.

    @param ch Character to check.
    @return   True if allowed, false if not.
    **/
    bool is_q_allowed(char ch) const
    {
        return (ch > SPACE_CHAR && ch <= TILDE_CHAR && ch != QUESTION_MARK_CHAR);
    }
};


} // namespace mailxx


#ifdef _MSC_VER
#pragma warning(pop)
#endif


#ifdef _MSC_VER
#pragma warning(pop)
#endif


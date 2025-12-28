/*

q_codec.hpp
-----------

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
#include <vector>
#include <tuple>
#include <boost/algorithm/string.hpp>
#include <mailxx/codec/codec.hpp>
#include <mailxx/codec/base64.hpp>
#include <mailxx/codec/quoted_printable.hpp>
#include <mailxx/export.hpp>


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
    @throw codec_error  Bad encoding method.
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

    @param text    String to encode.
    @param charset Charset used by the string.
    @param method  Allowed encoding methods.
    @return        Encoded string.
    @todo          Merge text and charset into a single parameter of type `string_t`.
    @todo          It must take another parameter for the header name length in order to remove the hardcoded constant.
    **/
    std::vector<std::string> encode(const std::string& text, const std::string& charset, codec_t method) const
    {
        // TODO: The constant has to depend of the header length.
        const std::string::size_type Q_FLAGS_LEN = 12;
        std::vector<std::string> enc_text, text_c;
        std::string codec_flag;
        if (method == codec_t::BASE64)
        {
            codec_flag = BASE64_CODEC_STR;
            base64 b64(line1_policy_ - Q_FLAGS_LEN, lines_policy_ - Q_FLAGS_LEN);
            text_c = b64.encode(text);
        }
        else if (method == codec_t::QUOTED_PRINTABLE)
        {
            codec_flag = QP_CODEC_STR;
            quoted_printable qp(line1_policy_ - Q_FLAGS_LEN, lines_policy_ - Q_FLAGS_LEN);
            qp.q_codec_mode(true);
            text_c = qp.encode(text);
        }
        else
            throw codec_error("Bad encoding method.");

        // TODO: Name the magic constant for Q delimiters.
        for (auto s = text_c.begin(); s != text_c.end(); s++)
            enc_text.push_back("=?" + boost::to_upper_copy(charset) + "?" + codec_flag + "?" + *s + "?=");

        return enc_text;
    }

    /**
    Decoding a string.

    @param text        String to decode.
    @return            Decoded string, its charset and its codec method.
    @throw codec_error Missing Q codec separator for charset.
    @throw codec_error Missing Q codec separator for codec type.
    @throw codec_error Missing last Q codec separator.
    @throw codec_error Bad encoding method.
    @throw *           `decode_qp(const string&)`, `base64::decode(const string&)`.
    **/
    std::tuple<std::string, std::string, codec_t> decode(const std::string& text) const
    {
        std::string::size_type charset_pos = text.find(QUESTION_MARK_CHAR);
        if (charset_pos == std::string::npos)
            throw codec_error("Missing Q codec separator for charset.");
        std::string::size_type method_pos = text.find(QUESTION_MARK_CHAR, charset_pos + 1);
        if (method_pos == std::string::npos)
            throw codec_error("Missing Q codec separator for codec type.");
        std::string charset = boost::to_upper_copy(text.substr(charset_pos + 1, method_pos - charset_pos - 1));
        if (charset.empty())
            throw codec_error("Missing Q codec charset.");
        std::string::size_type content_pos = text.find(QUESTION_MARK_CHAR, method_pos + 1);
        if (content_pos == std::string::npos)
            throw codec_error("Missing last Q codec separator.");
        std::string method = text.substr(method_pos + 1, content_pos - method_pos - 1);
        codec_t method_type;
        std::string text_c = text.substr(content_pos + 1);

        std::string dec_text;
        if (boost::iequals(method, BASE64_CODEC_STR))
        {
            base64 b64(line1_policy_, lines_policy_);
            dec_text = b64.decode(text_c);
            method_type = codec_t::BASE64;
        }
        else if (boost::iequals(method, QP_CODEC_STR))
        {
            dec_text = decode_qp(text_c);
            method_type = codec_t::QUOTED_PRINTABLE;
        }
        else
            throw codec_error("Bad encoding method.");

        return std::make_tuple(dec_text, charset, method_type);
    }

    /**
    Checking if a string is Q encoded and decodes it.

    @param text        String to decode.
    @return            Decoded string, its charset and its codec method.
    @throw codec_error Bad Q codec format.
    @todo              Returning value to hold `string_t` instead of two `std::string`.
    **/
    std::tuple<std::string, std::string, codec_t> check_decode(const std::string& text) const
    {
        std::string::size_type question_mark_counter = 0;
        const std::string::size_type QUESTION_MARKS_NO = 4;
        bool is_encoded = false;
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
                dec_text += std::get<0>(text_charset);
                charset = std::get<1>(text_charset);
                method_type = std::get<2>(text_charset);

                encoded_part.clear();
                ch++;
            }
            else if (is_encoded == true)
                encoded_part.append(1, *ch);
            else
                dec_text.append(1, *ch);
        }

        if (is_encoded && question_mark_counter < QUESTION_MARKS_NO)
            throw codec_error("Bad Q codec format.");

        return std::make_tuple(dec_text, charset, method_type);
    }

private:

    /**
    String representation of Base64 method.
    **/
    inline static const std::string BASE64_CODEC_STR{"B"};

    /**
    String representation of Quoted Printable method.
    **/
    inline static const std::string QP_CODEC_STR{"Q"};

    /**
    Decoding by using variation of the Quoted Printable method.

    @param text String to decode.
    @return     Decoded string.
    @throw *    `quoted_printable::decode(const vector<string>&)`
    **/
    std::string decode_qp(const std::string& text) const
    {
        quoted_printable qp(line1_policy_, lines_policy_);
        qp.q_codec_mode(true);
        std::vector<std::string> lines;
        lines.push_back(text);
        return qp.decode(lines);
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


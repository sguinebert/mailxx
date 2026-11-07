/*

percent.hpp
-----------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/


#pragma once

#include <string>
#include <vector>
#include <cctype>
#include <boost/algorithm/string.hpp>
#include <mailxx/codec/codec.hpp>
#include <mailxx/detail/result.hpp>
#include <mailxx/config.hpp>


namespace mailxx
{


/**
Percent encoding and decoding as described in RFC 2231 section 4.
**/
class MAILXX_EXPORT percent : public codec
{
public:

    /**
    Setting the encoder and decoder line policies.

    @param line1_policy First line policy to set.
    @param lines_policy Other lines policy than the first one to set.
    **/
    percent(std::string::size_type line1_policy, std::string::size_type lines_policy)
        : codec(line1_policy, lines_policy)
    {
    }

    percent(const percent&) = delete;

    percent(percent&&) = delete;

    /**
    Default destructor.
    **/
    ~percent() = default;

    void operator=(const percent&) = delete;

    void operator=(percent&&) = delete;

    /**
    Encoding a string.

    The charset introducer is written on the first segment. A line break falls
    between characters and never inside a `%HH` escape.

    @param txt     String to encode.
    @param charset Charset of the attribute value.
    @return        Encoded segments, one per output line.
    **/
    std::vector<std::string> encode(const std::string& txt, const std::string& charset) const
    {
        const std::string introducer = boost::to_upper_copy(charset) + ATTRIBUTE_CHARSET_SEPARATOR_STR +
            ATTRIBUTE_CHARSET_SEPARATOR_STR;
        std::vector<std::string> enc_text;
        std::string line = introducer;
        std::string::size_type policy = line1_policy_ == 0 ? 1 : line1_policy_;

        auto push_line = [&]()
        {
            if (!line.empty())
                enc_text.push_back(std::move(line));
            line.clear();
            policy = lines_policy_ == 0 ? 1 : lines_policy_;
        };

        if (line.size() > policy)
            push_line();

        for (unsigned char ch : txt)
        {
            const bool literal = std::isalnum(ch) != 0;
            const std::string::size_type need = literal ? 1 : 3;
            if (!line.empty() && line.size() + need > policy)
                push_line();

            if (literal)
                line.push_back(static_cast<char>(ch));
            else
            {
                line.push_back(PERCENT_HEX_FLAG);
                line.push_back(HEX_DIGITS[(ch >> 4) & 0x0F]);
                line.push_back(HEX_DIGITS[ch & 0x0F]);
            }
        }
        if (!line.empty())
            enc_text.push_back(std::move(line));
        return enc_text;
    }

    /**
    Decoding a percent encoded string.

    @param txt String to decode.
    @return    Decoded string.
    **/
    result<std::string> decode(const std::string& txt) const
    {
        std::string dec_text;
        for (std::string::const_iterator ch = txt.begin(); ch != txt.end(); ch++)
        {
            if (*ch == codec::PERCENT_HEX_FLAG)
            {
                if (ch + 1 == txt.end() || ch + 2 == txt.end())
                    return fail<std::string>(errc::codec_invalid_input, "invalid percent input", "bad character");
                if (std::isxdigit(static_cast<unsigned char>(*(ch + 1))) == 0 || std::isxdigit(static_cast<unsigned char>(*(ch + 2))) == 0)
                    return fail<std::string>(errc::codec_invalid_input, "invalid percent input", "bad character");

                char next_char = std::toupper(static_cast<unsigned char>(*(ch + 1)));
                char next_next_char = std::toupper(static_cast<unsigned char>(*(ch + 2)));
                int nc_val = codec::hex_digit_to_int(next_char);
                int nnc_val = codec::hex_digit_to_int(next_next_char);
                dec_text += ((nc_val << 4) + nnc_val);
                ch += 2;
            }
            else
                dec_text += *ch;
        }
        return ok(std::move(dec_text));
    }
};


} // namespace mailxx


/*

percent.hpp
-----------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <boost/algorithm/string.hpp>
#include <mailxx/codec/codec.hpp>
#include <mailxx/export.hpp>


namespace mailxx
{


/**
Percent encoding and decoding as described in RFC 2231 section 4.

@todo Line policies not implemented.
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

    @param txt String to encode.
    @return    Encoded string.
    @todo      Implement the line policies.
    @todo      Replace `txt` to be `string_t`, then no need for the charset parameter.
    **/
    std::vector<std::string> encode(const std::string& txt, const std::string& charset) const
    {
        std::vector<std::string> enc_text;
        std::string line;
        std::string::size_type line_len = 0;
        // Soon as the first line is added, switch the policy to the other lines policy.
        std::string::size_type policy = line1_policy_;

        std::stringstream enc_line;
        enc_line << boost::to_upper_copy(charset) + ATTRIBUTE_CHARSET_SEPARATOR_STR + ATTRIBUTE_CHARSET_SEPARATOR_STR;
        for (std::string::const_iterator ch = txt.begin(); ch != txt.end(); ch++)
        {
            if (std::isalnum(static_cast<unsigned char>(*ch)))
            {
                enc_line << *ch;
                line_len++;
            }
            else
            {
                enc_line << codec::PERCENT_HEX_FLAG << std::setfill('0') << std::hex << std::uppercase << std::setw(2) <<
                    static_cast<unsigned int>(static_cast<uint8_t>(*ch));
                line_len += 3;
            }

            if (line_len >= policy - 3)
            {
                enc_text.push_back(enc_line.str());
                enc_line.str("");
                line_len = 0;
                policy = lines_policy_;
            }
        }
        enc_text.push_back(enc_line.str());

        return enc_text;
    }

    /**
    Decoding a percent encoded string.

    @param txt String to decode.
    @return    Decoded string.
    @todo      Implement the line policies.
    **/
    std::string decode(const std::string& txt) const
    {
        std::string dec_text;
        for (std::string::const_iterator ch = txt.begin(); ch != txt.end(); ch++)
        {
            if (*ch == codec::PERCENT_HEX_FLAG)
            {
                if (ch + 1 == txt.end() || ch + 2 == txt.end())
                    throw codec_error("Bad character.");
                if (std::isxdigit(static_cast<unsigned char>(*(ch + 1))) == 0 || std::isxdigit(static_cast<unsigned char>(*(ch + 2))) == 0)
                    throw codec_error("Bad character.");

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
        return dec_text;
    }
};


} // namespace mailxx


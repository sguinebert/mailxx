/*

bit8.hpp
--------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once


#include <string>
#include <vector>
#include <boost/algorithm/string/trim.hpp>
#include <mailxx/codec/codec.hpp>
#include <mailxx/export.hpp>


namespace mailxx
{


/**
Eight bit codec.
**/
class MAILXX_EXPORT bit8 : public codec
{
public:

    /**
    Setting the encoder and decoder line policies.

    @param line1_policy First line policy to set.
    @param lines_policy Other lines policy than the first one to set.
    **/
    bit8(std::string::size_type line1_policy, std::string::size_type lines_policy)
        : codec(line1_policy, lines_policy)
    {
    }

    bit8(const bit8&) = delete;

    bit8(bit8&&) = delete;

    /**
    Default destructor.
    **/
    ~bit8() = default;

    void operator=(const bit8&) = delete;

    void operator=(bit8&&) = delete;

    /**
    Encoding a string into vector of 8bit encoded strings by applying the line policy.

    @param text        String to encode.
    @return            Vector of eight bit encoded strings.
    @throw codec_error Bad character.
    **/
    std::vector<std::string> encode(const std::string& text) const
    {
        std::vector<std::string> enc_text;
        std::string line;
        std::string::size_type line_len = 0;
        bool is_first_line = true;

        auto add_new_line = [&enc_text, &line_len](std::string& line)
        {
            enc_text.push_back(line);
            line.clear();
            line_len = 0;
        };

        for (auto ch = text.begin(); ch != text.end(); ch++)
        {
            if (is_allowed(*ch))
            {
                line += *ch;
                line_len++;
            }
            else if (*ch == '\r' && (ch + 1) != text.end() && *(ch + 1) == '\n')
            {
                add_new_line(line);
                // skip both crlf characters
                ch++;
            }
            else
                throw codec_error("Bad character `" + std::string(1, *ch) + "`.");

            if (is_first_line)
            {
                if (line_len == line1_policy_)
                {
                    is_first_line = false;
                    add_new_line(line);
                }
            }
            else if (line_len == lines_policy_)
            {
                add_new_line(line);
            }
        }
        if (!line.empty())
            enc_text.push_back(line);
        while (!enc_text.empty() && enc_text.back().empty())
            enc_text.pop_back();

        return enc_text;
    }

    /**
    Decoding a vector of 8bit strings to string by applying the line policy.

    @param text        Vector of eight bit encoded strings.
    @return            Decoded string.
    @throw codec_error Line policy overflow.
    @throw codec_error Bad character.
    **/
    std::string decode(const std::vector<std::string>& text) const
    {
        std::string dec_text;
        for (const auto& line : text)
        {
            if (line.length() > lines_policy_)
                throw codec_error("Line policy overflow.");

            for (auto ch : line)
            {
                if (!is_allowed(ch))
                    throw codec_error("Bad character `" + std::string(1, ch) + "`.");

                dec_text += ch;
            }
            dec_text += "\r\n";
        }
        boost::trim_right(dec_text);

        return dec_text;
    }

private:

    /**
    Checking if a character is in the 8bit character set.

    @param ch Character to check.
    @return   True if it is, false if not.
    **/
    bool is_allowed(char ch) const
    {
        return (ch != NIL_CHAR && ch != CR_CHAR && ch != LF_CHAR);
    }
};


} // namespace mailxx


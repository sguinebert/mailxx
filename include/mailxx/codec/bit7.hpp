/*

bit7.hpp
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
#include <mailxx/detail/result.hpp>
#include <mailxx/config.hpp>


namespace mailxx
{


/**
Seven bit codec.
**/
class MAILXX_EXPORT bit7 : public codec
{
public:

    /**
    Setting the encoder and decoder line policies.

    @param line1_policy First line policy to set.
    @param lines_policy Other lines policy than the first one to set.
    **/
    bit7(std::string::size_type line1_policy, std::string::size_type lines_policy)
        : codec(line1_policy, lines_policy)
    {
    }

    bit7(const bit7&) = delete;

    bit7(bit7&&) = delete;

    /**
    Default destructor.
    **/
    ~bit7() = default;

    void operator=(const bit7&) = delete;

    void operator=(bit7&&) = delete;

    /**
    Encoding a string into vector of 7bit encoded strings by applying the line policy.

    @param text        String to encode.
    @return            Vector of seven bit encoded strings.
    **/
    result<std::vector<std::string>> encode(const std::string& text) const
    {
        std::vector<std::string> enc_text;
        std::string line;
        std::string::size_type line_len = 0;
        const std::string DELIMITERS = " ,;";
        std::string::size_type delim_pos = 0;
        std::string::size_type policy = line1_policy_;
        const bool is_folding = (line1_policy_ != lines_policy_);

        auto add_new_line = [&enc_text, &line_len, &delim_pos, &policy, this](bool is_folding, std::string& line)
        {
            if (is_folding && delim_pos > 0)
            {
                enc_text.push_back(line.substr(0, delim_pos));
                line = line.substr(delim_pos);
                line_len -= delim_pos;
                delim_pos = 0;
            }
            else
            {
                enc_text.push_back(line);
                line.clear();
                line_len = 0;
            }
            policy = lines_policy_;
        };

        for (auto ch = text.begin(); ch != text.end(); ch++)
        {
            if (is_allowed(*ch))
            {
                line += *ch;
                line_len++;

                if (DELIMITERS.find(*ch) != std::string::npos)
                    delim_pos = line_len;
            }
            else if (*ch == '\r' && (ch + 1) != text.end() && *(ch + 1) == '\n')
            {
                add_new_line(is_folding, line);
                // Skip both crlf characters.
                ch++;
            }
            else
            {
                std::string detail = "bad character `";
                detail += *ch;
                detail += "`";
                return fail<std::vector<std::string>>(errc::codec_invalid_input, "invalid 7bit input", std::move(detail));
            }

            if (line_len == policy)
                add_new_line(is_folding, line);
        }
        if (!line.empty())
            enc_text.push_back(line);
        while (!enc_text.empty() && enc_text.back().empty())
            enc_text.pop_back();

        return ok(std::move(enc_text));
    }

    /**
    Decoding a vector of 7bit encoded strings to string by applying the line policy.

    @param text        Vector of 7bit encoded strings.
    @return            Decoded string.
    **/
    result<std::string> decode(const std::vector<std::string>& text) const
    {
        std::string dec_text;
        for (const auto& line : text)
        {
            if (line.length() > lines_policy_)
                return fail<std::string>(errc::codec_invalid_input, "invalid 7bit input", "line policy overflow");

            for (auto ch : line)
            {
                if (!is_allowed(ch))
                {
                    std::string detail = "bad character `";
                    detail += ch;
                    detail += "`";
                    return fail<std::string>(errc::codec_invalid_input, "invalid 7bit input", std::move(detail));
                }

                dec_text += ch;
            }
            dec_text += "\r\n";
        }
        boost::trim_right(dec_text);

        return ok(std::move(dec_text));
    }

private:

    /**
    Checking if a character is in the 7bit character set.

    @param ch Character to check.
    @return   True if it is, false if not.
    **/
    bool is_allowed(char ch) const
    {
        if (strict_mode_)
            return (ch > NIL_CHAR && ch <= TILDE_CHAR && ch != CR_CHAR && ch != LF_CHAR);
        else
            return (ch != NIL_CHAR && ch != CR_CHAR && ch != LF_CHAR);
    }
};


} // namespace mailxx


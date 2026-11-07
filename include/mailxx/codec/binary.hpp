/*

binary.hpp
----------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/


#pragma once

#include <string>
#include <vector>
#include <mailxx/codec/codec.hpp>
#include <mailxx/config.hpp>


namespace mailxx
{


/**
Binary codec.
**/
class MAILXX_EXPORT binary : public codec
{
public:

    /**
    Setting the encoder and decoder line policies.

    @param line1_policy First line policy to set.
    @param lines_policy Other lines policy than the first one to set.
    **/
    binary(std::string::size_type line1_policy, std::string::size_type lines_policy)
        : codec(line1_policy, lines_policy)
    {
    }

    binary(const binary&) = delete;

    binary(binary&&) = delete;

    /**
    Default destructor.
    **/
    ~binary() = default;

    void operator=(const binary&) = delete;

    void operator=(binary&&) = delete;

    /**
    Encoding a string into vector of binary encoded strings.

    @param text String to encode.
    @return     Vector with binary encoded strings.
    **/
    std::vector<std::string> encode(const std::string& text) const
    {
        std::vector<std::string> enc_text;
        enc_text.push_back(text);
        return enc_text;
    }

    /**
    Decoding a vector of binary encoded strings.

    The CRLF between blocks is restored. No CRLF is appended after the last block:
    a trailing CRLF belongs to the MIME frame, not to the body.

    @param text Vector of binary encoded strings.
    @return     Decoded string.
    **/
    std::string decode(const std::vector<std::string>& text) const
    {
        std::string::size_type total = 0;
        for (const auto& line : text)
            total += line.size();
        if (text.size() > 1)
            total += (text.size() - 1) * END_OF_LINE.size();

        std::string dec_text;
        dec_text.reserve(total);
        for (std::size_t i = 0; i < text.size(); ++i)
        {
            if (i != 0)
                dec_text += END_OF_LINE;
            dec_text += text[i];
        }
        return dec_text;
    }
};


} // namespace mailxx


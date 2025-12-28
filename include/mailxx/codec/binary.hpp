/*

binary.hpp
----------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once

#include <string>
#include <vector>
#include <mailxx/codec/codec.hpp>
#include <mailxx/export.hpp>


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

    @param text Vector of binary encoded strings.
    @return     Decoded string.
    @todo       Line policy to be verified.
    **/
    std::string decode(const std::vector<std::string>& text) const
    {
        std::string dec_text;
        for (const auto& line : text)
            dec_text += line + END_OF_LINE;
        return dec_text;
    }
};


} // namespace mailxx


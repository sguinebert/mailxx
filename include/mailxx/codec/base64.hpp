/*

base64.hpp
----------

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
#include <cctype>
#include <mailxx/codec/codec.hpp>
#include <mailxx/export.hpp>


namespace mailxx
{


/**
Base64 codec.

@todo Add static method `string encode(string)` to be used by `smtp`?
@todo Does it need the first line policy?
**/
class MAILXX_EXPORT base64 : public codec
{
public:

    /**
    Base64 character set.
    **/
    inline static const std::string CHARSET{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};

    /**
    Setting the encoder and decoder line policies.

    Since Base64 encodes three characters into four, the split is made after each fourth character. It seems that email clients do not merge properly
    many lines of encoded text if the split is not grouped by four characters. For that reason, the constructor sets line policies to be divisible by
    the number four.

    @param line1_policy First line policy to set.
    @param lines_policy Other lines policy than the first one to set.
    **/
    base64(std::string::size_type line1_policy, std::string::size_type lines_policy)
        : codec(line1_policy, lines_policy)
    {
        // Line policies to be divisible by four.
        line1_policy_ -= line1_policy_ % SEXTETS_NO;
        lines_policy_ -= lines_policy_ % SEXTETS_NO;
    }

    base64(const base64&) = delete;

    base64(base64&&) = delete;

    /**
    Default destructor.
    **/
    ~base64() = default;

    void operator=(const base64&) = delete;

    void operator=(base64&&) = delete;

    /**
    Encoding a string into vector of Base64 encoded strings by applying the line policy.

    @param text     String to encode.
    @return         Vector of Base64 encoded strings.
    **/
    std::vector<std::string> encode(const std::string& text) const
    {
        std::vector<std::string> enc_text;
        unsigned char octets[OCTETS_NO];
        unsigned char sextets[SEXTETS_NO];
        int sextets_counter = 0;
        std::string line;
        std::string::size_type line_len = 0;
        std::string::size_type policy = line1_policy_;

        auto add_new_line = [&enc_text, &line_len, &policy, this](std::string& line)
        {
            enc_text.push_back(line);
            line.clear();
            line_len = 0;
            policy = lines_policy_;
        };

        for (std::string::size_type cur_char = 0; cur_char < text.length(); cur_char++)
        {
            octets[sextets_counter++] = text[cur_char];
            if (sextets_counter == OCTETS_NO)
            {
                sextets[0] = (octets[0] & 0xfc) >> 2;
                sextets[1] = ((octets[0] & 0x03) << 4) + ((octets[1] & 0xf0) >> 4);
                sextets[2] = ((octets[1] & 0x0f) << 2) + ((octets[2] & 0xc0) >> 6);
                sextets[3] = octets[2] & 0x3f;

                for(int i = 0; i < SEXTETS_NO; i++)
                    line += CHARSET[sextets[i]];
                sextets_counter = 0;
                line_len += SEXTETS_NO;
            }

            if (line_len >= policy)
                add_new_line(line);
        }

        // encode remaining characters if any

        if (sextets_counter > 0)
        {
            // If the remaining three characters match exatcly rest of the line, then move them onto next line. Email clients do not show properly subject when
            // the next line has the empty content, containing only the encoding stuff.
            if (line_len >= policy - OCTETS_NO)
                add_new_line(line);

            for (int i = sextets_counter; i < OCTETS_NO; i++)
                octets[i] = '\0';

            sextets[0] = (octets[0] & 0xfc) >> 2;
            sextets[1] = ((octets[0] & 0x03) << 4) + ((octets[1] & 0xf0) >> 4);
            sextets[2] = ((octets[1] & 0x0f) << 2) + ((octets[2] & 0xc0) >> 6);
            sextets[3] = octets[2] & 0x3f;

            for (int i = 0; i < sextets_counter + 1; i++)
            {
                if (line_len >= policy)
                    add_new_line(line);
                line += CHARSET[sextets[i]];
                line_len++;
            }

            while (sextets_counter++ < OCTETS_NO)
            {
                if (line_len >= policy)
                    add_new_line(line);
                line += EQUAL_CHAR;
                line_len++;
            }
        }

        if (!line.empty())
            enc_text.push_back(line);

        return enc_text;
    }

    /**
    Decoding a vector of Base64 encoded strings to string by applying the line policy.

    @param text        Vector of Base64 encoded strings.
    @return            Decoded string.
    @throw codec_error Bad character.
    @todo              Line policy not verified.
    **/
    std::string decode(const std::vector<std::string>& text) const
    {
        std::string dec_text;
        unsigned char sextets[SEXTETS_NO];
        unsigned char octets[OCTETS_NO];
        int count_4_chars = 0;

        for (const auto& line : text)
        {
            if (line.length() > lines_policy_)
                throw codec_error("Bad line policy.");

            for (std::string::size_type ch = 0; ch < line.length() && line[ch] != EQUAL_CHAR; ch++)
            {
                if (!is_allowed(line[ch]))
                    throw codec_error("Bad character `" + std::string(1, line[ch]) + "`.");

                sextets[count_4_chars++] = line[ch];
                if (count_4_chars == SEXTETS_NO)
                {
                    for (int i = 0; i < SEXTETS_NO; i++)
                        sextets[i] = static_cast<unsigned char>(CHARSET.find(sextets[i]));

                    octets[0] = (sextets[0] << 2) + ((sextets[1] & 0x30) >> 4);
                    octets[1] = ((sextets[1] & 0xf) << 4) + ((sextets[2] & 0x3c) >> 2);
                    octets[2] = ((sextets[2] & 0x3) << 6) + sextets[3];

                    for (int i = 0; i < OCTETS_NO; i++)
                        dec_text += octets[i];
                    count_4_chars = 0;
                }
            }

            // decode remaining characters if any

            if (count_4_chars > 0)
            {
                for (int i = count_4_chars; i < SEXTETS_NO; i++)
                    sextets[i] = '\0';

                for (int i = 0; i < SEXTETS_NO; i++)
                    sextets[i] = static_cast<unsigned char>(CHARSET.find(sextets[i]));

                octets[0] = (sextets[0] << 2) + ((sextets[1] & 0x30) >> 4);
                octets[1] = ((sextets[1] & 0xf) << 4) + ((sextets[2] & 0x3c) >> 2);
                octets[2] = ((sextets[2] & 0x3) << 6) + sextets[3];

                for (int i = 0; i < count_4_chars - 1; i++)
                    dec_text += octets[i];
            }
        }

        return dec_text;
    }

    /**
    Decoding a Base64 string to a string.

    @param text Base64 encoded string.
    @return     Encoded string.
    @throw *    `decode(const std::vector<std::string>&)`.
    **/
    std::string decode(const std::string& text) const
    {
        std::vector<std::string> v;
        v.push_back(text);
        return decode(v);
    }

private:

    /**
    Checking if the given character is in the base64 character set.

    @param ch Character to check.
    @return   True if it is, false if not.
    **/
    bool is_allowed(char ch) const
    {
        return (std::isalnum(static_cast<unsigned char>(ch)) || ch == PLUS_CHAR || ch == SLASH_CHAR);
    }

	/**
	Number of six bit chunks.
	**/
	static constexpr unsigned short SEXTETS_NO = 4;

	/**
	Number of eight bit characters.
	**/
	static constexpr unsigned short OCTETS_NO = SEXTETS_NO - 1;
};


} // namespace mailxx


#ifdef _MSC_VER
#pragma warning(pop)
#endif


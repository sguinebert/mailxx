/*

base64_stream.hpp
-----------------

Streaming Base64 encoder to avoid buffering entire payloads.

*/

#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <string>

#include <mailxx/codec/base64.hpp>
#include <mailxx/detail/output_sink.hpp>

namespace mailxx
{

class base64_stream_encoder
{
public:
    explicit base64_stream_encoder(std::size_t line_policy = 76, std::string eol = "\r\n")
        : line_policy_(line_policy - (line_policy % 4)), eol_(std::move(eol))
    {
    }

    void update(std::span<const std::byte> chunk, detail::output_sink& sink)
    {
        for (std::byte b : chunk)
        {
            buffer_[pending_] = b;
            ++pending_;
            if (pending_ == 3)
            {
                emit_block(buffer_[0], buffer_[1], buffer_[2], sink);
                pending_ = 0;
            }
        }
    }

    void finalize(detail::output_sink& sink)
    {
        if (pending_ == 1)
        {
            emit_partial(buffer_[0], std::byte{0}, true, sink);
        }
        else if (pending_ == 2)
        {
            emit_partial(buffer_[0], buffer_[1], false, sink);
        }
        pending_ = 0;
    }

private:
    static constexpr std::string_view charset = base64::CHARSET;

    void emit_newline(detail::output_sink& sink)
    {
        if (line_policy_ == 0)
            return;
        sink.write(eol_);
        column_ = 0;
    }

    void emit_chars(const char* chars, detail::output_sink& sink, std::size_t count = 4)
    {
        for (std::size_t i = 0; i < count; ++i)
        {
            if (line_policy_ > 0 && column_ >= line_policy_)
                emit_newline(sink);
            sink.write(std::string_view(chars + i, 1));
            ++column_;
        }
    }

    void emit_block(std::byte b0, std::byte b1, std::byte b2, detail::output_sink& sink)
    {
        const unsigned char octet0 = static_cast<unsigned char>(b0);
        const unsigned char octet1 = static_cast<unsigned char>(b1);
        const unsigned char octet2 = static_cast<unsigned char>(b2);

        char out[4];
        out[0] = charset[(octet0 & 0xfc) >> 2];
        out[1] = charset[((octet0 & 0x03) << 4) | ((octet1 & 0xf0) >> 4)];
        out[2] = charset[((octet1 & 0x0f) << 2) | ((octet2 & 0xc0) >> 6)];
        out[3] = charset[octet2 & 0x3f];
        emit_chars(out, sink);
    }

    void emit_partial(std::byte b0, std::byte b1, bool single, detail::output_sink& sink)
    {
        const unsigned char octet0 = static_cast<unsigned char>(b0);
        const unsigned char octet1 = static_cast<unsigned char>(b1);

        char out[4];
        out[0] = charset[(octet0 & 0xfc) >> 2];
        out[1] = charset[((octet0 & 0x03) << 4) | ((octet1 & 0xf0) >> 4)];
        if (single)
        {
            out[2] = '=';
            out[3] = '=';
        }
        else
        {
            out[2] = charset[(octet1 & 0x0f) << 2];
            out[3] = '=';
        }
        emit_chars(out, sink);
    }

    std::array<std::byte, 3> buffer_{};
    std::size_t pending_{0};
    std::size_t column_{0};
    std::size_t line_policy_;
    std::string eol_;
};

} // namespace mailxx


#pragma once

#include <string>
#include <string_view>
#include <charconv>
#include <cstdint>
#include <system_error>

namespace mailxx
{
namespace detail
{

inline void append_sv(std::string& out, std::string_view sv)
{
    out.reserve(out.size() + sv.size());
    out.append(sv.data(), sv.size());
}

inline void append_char(std::string& out, char ch)
{
    out.reserve(out.size() + 1);
    out.push_back(ch);
}

inline void append_space(std::string& out)
{
    append_char(out, ' ');
}

inline void append_crlf(std::string& out)
{
    out.reserve(out.size() + 2);
    out.append("\r\n", 2);
}

inline void append_uint(std::string& out, std::uint64_t value)
{
    char buffer[20];
    const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value);
    if (result.ec != std::errc())
        return;
    const auto len = static_cast<std::size_t>(result.ptr - buffer);
    out.reserve(out.size() + len);
    out.append(buffer, len);
}

inline void append_angle_addr(std::string& out, std::string_view addr)
{
    out.reserve(out.size() + addr.size() + 2);
    out.push_back('<');
    out.append(addr.data(), addr.size());
    out.push_back('>');
}

} // namespace detail
} // namespace mailxx

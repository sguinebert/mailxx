#pragma once

#include <ostream>
#include <string_view>

namespace mailxx::net
{

/**
TLS mode for protocol connections.
**/
enum class tls_mode
{
    none,
    starttls,
    implicit
};

[[nodiscard]] constexpr std::string_view to_string(tls_mode mode) noexcept
{
    switch (mode)
    {
        case tls_mode::none: return "none";
        case tls_mode::starttls: return "starttls";
        case tls_mode::implicit: return "implicit";
    }
    return "unknown";
}

inline std::ostream& operator<<(std::ostream& os, tls_mode mode)
{
    return os << to_string(mode);
}

} // namespace mailxx::net

#pragma once

#include <stdexcept>
#include <string>

namespace mailxx::net
{

/**
Error thrown for TLS verification or pinning failures.
**/
class tls_error : public std::runtime_error
{
public:
    explicit tls_error(const std::string& message)
        : std::runtime_error(message)
    {
    }

    tls_error(const std::string& message, const std::string& details)
        : std::runtime_error(details.empty() ? message : message + " " + details)
    {
    }
};

} // namespace mailxx::net

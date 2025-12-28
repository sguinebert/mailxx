/*

throwing.hpp
------------

Helpers to bridge mailxx::result into exceptions for users who prefer
exception-based error handling.

*/

#pragma once

#include <stdexcept>
#include <utility>

#include <mailxx/config.hpp>
#include <mailxx/detail/result.hpp>

namespace mailxx
{

#if !MAILXX_THROWING_ENABLED
#error "MAILXX_NO_EXCEPTIONS is defined; throwing.hpp is disabled."
#endif

class exception : public std::runtime_error
{
public:
    explicit exception(error_info info)
        : std::runtime_error(info.message.empty() ? std::string(to_string(info.code)) : info.message),
          info_(std::move(info))
    {
    }

    [[nodiscard]] const error_info& info() const noexcept { return info_; }

private:
    error_info info_;
};

template<class T>
[[nodiscard]] inline T unwrap(result<T>&& r)
{
    if (!r)
        throw exception(std::move(r.error()));
    return std::move(*r);
}

inline void unwrap(result<void>&& r)
{
    if (!r)
        throw exception(std::move(r.error()));
}

} // namespace mailxx

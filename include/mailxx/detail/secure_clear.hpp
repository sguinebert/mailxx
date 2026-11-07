#pragma once

#include <string>
#include <openssl/crypto.h>

namespace mailxx::detail
{

inline void secure_clear(std::string& value) noexcept
{
    if (!value.empty())
        OPENSSL_cleanse(value.data(), value.size());
    value.clear();
}

struct secret_guard
{
    std::string* value = nullptr;

    secret_guard() = default;
    explicit secret_guard(std::string* target) noexcept : value(target) {}
    secret_guard(const secret_guard&) = delete;
    secret_guard& operator=(const secret_guard&) = delete;

    ~secret_guard()
    {
        if (value != nullptr)
            secure_clear(*value);
    }
};

} // namespace mailxx::detail

#pragma once

#include <vector>
#include <mailxx/detail/asio_decl.hpp>

namespace mailxx::net
{

using mailxx::asio::tcp;

[[nodiscard]] inline bool is_loopback_address(const mailxx::asio::ip::address& address) noexcept
{
    if (address.is_v4())
        return address.to_v4().to_bytes()[0] == 127;
    return address.is_loopback();
}

template<typename Results>
[[nodiscard]] std::vector<tcp::endpoint> loopback_endpoints(const Results& results)
{
    std::vector<tcp::endpoint> endpoints;
    for (const auto& entry : results)
    {
        const tcp::endpoint endpoint = entry.endpoint();
        if (is_loopback_address(endpoint.address()))
            endpoints.push_back(endpoint);
    }
    return endpoints;
}

} // namespace mailxx::net

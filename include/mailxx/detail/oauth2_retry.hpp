/*

oauth2_retry.hpp
----------------

OAuth2 retry helper for SASL authentication with token refresh.

*/

#pragma once

#include <string>
#include <type_traits>
#include <utility>

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/awaitable_traits.hpp>
#include <mailxx/detail/result.hpp>
#include <mailxx/oauth2/token_source.hpp>

namespace mailxx::detail
{

template<class AuthFn, class RetryPred>
mailxx::asio::awaitable<awaitable_value_t<decltype(std::declval<AuthFn>()(std::declval<const std::string&>()))>>
oauth2_auth_with_retry(mailxx::oauth2::token_source& source, AuthFn&& auth, RetryPred&& should_retry)
{
    using auth_awaitable_t = decltype(std::declval<AuthFn>()(std::declval<const std::string&>()));
    using result_t = awaitable_value_t<auth_awaitable_t>;
    using value_t = typename result_t::value_type;

    auto token_res = source.get_access_token();
    if (!token_res)
        co_return mailxx::fail<value_t>(token_res.error());

    std::string token = std::move(token_res).value();
    result_t first = co_await auth(token);
    if (first)
        co_return first;

    const error_info& err = first.error();
    if (!should_retry(err))
        co_return first;

    auto refresh_res = source.refresh_access_token();
    if (!refresh_res)
        co_return mailxx::fail<value_t>(refresh_res.error());

    std::string refreshed = std::move(refresh_res).value();
    co_return co_await auth(refreshed);
}

} // namespace mailxx::detail

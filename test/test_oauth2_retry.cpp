/*

test_oauth2_retry.cpp
---------------------

Verify OAuth2 retry logic with token refresh and no network I/O.

*/

#define BOOST_TEST_MODULE oauth2_retry_test

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <string>

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/oauth2_retry.hpp>
#include <mailxx/oauth2/token_source.hpp>


BOOST_AUTO_TEST_CASE(oauth2_retry_on_auth_failed)
{
    mailxx::asio::io_context ctx;
    int refresh_calls = 0;
    int auth_calls = 0;
    std::string first_token;
    std::string second_token;

    const auto now = std::chrono::system_clock::now();
    mailxx::oauth2::token initial{"access1", "refresh", now + std::chrono::hours{1}};
    mailxx::oauth2::token_source source(initial,
        [&](const mailxx::oauth2::token& current) -> mailxx::result<mailxx::oauth2::token>
        {
            ++refresh_calls;
            mailxx::oauth2::token refreshed{
                "access2",
                current.refresh_token,
                std::chrono::system_clock::now() + std::chrono::hours{1}};
            return mailxx::ok(refreshed);
        });

    mailxx::asio::co_spawn(ctx,
        [&]() -> mailxx::asio::awaitable<void>
        {
            auto auth = [&](const std::string& token) -> mailxx::asio::awaitable<mailxx::result_void>
            {
                ++auth_calls;
                if (auth_calls == 1)
                {
                    first_token = token;
                    co_return mailxx::fail_void(mailxx::errc::smtp_auth_failed, "auth failed");
                }
                second_token = token;
                co_return mailxx::ok();
            };
            auto should_retry = [](const mailxx::error_info& err)
            {
                return err.code == mailxx::errc::smtp_auth_failed;
            };

            auto res = co_await mailxx::detail::oauth2_auth_with_retry(source, auth, should_retry);
            BOOST_TEST(res.has_value());
            co_return;
        },
        mailxx::asio::detached);

    ctx.run();

    BOOST_TEST(auth_calls == 2);
    BOOST_TEST(refresh_calls == 1);
    BOOST_TEST(first_token == "access1");
    BOOST_TEST(second_token == "access2");
}

BOOST_AUTO_TEST_CASE(oauth2_retry_not_called_on_success)
{
    mailxx::asio::io_context ctx;
    int refresh_calls = 0;
    int auth_calls = 0;

    const auto now = std::chrono::system_clock::now();
    mailxx::oauth2::token initial{"access1", "refresh", now + std::chrono::hours{1}};
    mailxx::oauth2::token_source source(initial,
        [&](const mailxx::oauth2::token&) -> mailxx::result<mailxx::oauth2::token>
        {
            ++refresh_calls;
            mailxx::oauth2::token refreshed{
                "access2",
                "refresh",
                std::chrono::system_clock::now() + std::chrono::hours{1}};
            return mailxx::ok(refreshed);
        });

    mailxx::asio::co_spawn(ctx,
        [&]() -> mailxx::asio::awaitable<void>
        {
            auto auth = [&](const std::string&) -> mailxx::asio::awaitable<mailxx::result_void>
            {
                ++auth_calls;
                co_return mailxx::ok();
            };
            auto should_retry = [](const mailxx::error_info& err)
            {
                return err.code == mailxx::errc::smtp_auth_failed;
            };

            auto res = co_await mailxx::detail::oauth2_auth_with_retry(source, auth, should_retry);
            BOOST_TEST(res.has_value());
            co_return;
        },
        mailxx::asio::detached);

    ctx.run();

    BOOST_TEST(auth_calls == 1);
    BOOST_TEST(refresh_calls == 0);
}

BOOST_AUTO_TEST_CASE(oauth2_retry_skips_non_auth_errors)
{
    mailxx::asio::io_context ctx;
    int refresh_calls = 0;
    int auth_calls = 0;

    const auto now = std::chrono::system_clock::now();
    mailxx::oauth2::token initial{"access1", "refresh", now + std::chrono::hours{1}};
    mailxx::oauth2::token_source source(initial,
        [&](const mailxx::oauth2::token&) -> mailxx::result<mailxx::oauth2::token>
        {
            ++refresh_calls;
            mailxx::oauth2::token refreshed{
                "access2",
                "refresh",
                std::chrono::system_clock::now() + std::chrono::hours{1}};
            return mailxx::ok(refreshed);
        });

    mailxx::asio::co_spawn(ctx,
        [&]() -> mailxx::asio::awaitable<void>
        {
            auto auth = [&](const std::string&) -> mailxx::asio::awaitable<mailxx::result_void>
            {
                ++auth_calls;
                co_return mailxx::fail_void(mailxx::errc::net_eof, "net error");
            };
            auto should_retry = [](const mailxx::error_info& err)
            {
                return err.code == mailxx::errc::smtp_auth_failed;
            };

            auto res = co_await mailxx::detail::oauth2_auth_with_retry(source, auth, should_retry);
            BOOST_TEST(!res.has_value());
            BOOST_TEST(mailxx::to_string(res.error().code) == "net_eof");
            co_return;
        },
        mailxx::asio::detached);

    ctx.run();

    BOOST_TEST(auth_calls == 1);
    BOOST_TEST(refresh_calls == 0);
}

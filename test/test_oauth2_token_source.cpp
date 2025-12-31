/*

test_oauth2_token_source.cpp
----------------------------

Copyright (C) 2025, Sylvain Guinebert.

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#define BOOST_TEST_MODULE oauth2_token_source_test

#include <boost/test/unit_test.hpp>

#include <chrono>

#include <mailxx/oauth2/token_source.hpp>


BOOST_AUTO_TEST_CASE(refresh_called_when_expired)
{
    int calls = 0;
    const auto now = std::chrono::system_clock::now();
    mailxx::oauth2::token initial{"old_access", "refresh", now - std::chrono::minutes{5}};

    mailxx::oauth2::token_source source(initial,
        [&](const mailxx::oauth2::token& current) -> mailxx::result<mailxx::oauth2::token> {
            ++calls;
            BOOST_TEST(current.access_token == "old_access");
            mailxx::oauth2::token refreshed{
                "new_access",
                current.refresh_token,
                std::chrono::system_clock::now() + std::chrono::hours{1}};
            return mailxx::ok(refreshed);
        });

    auto res = source.get_access_token();
    BOOST_TEST(calls == 1);
    BOOST_TEST(res.has_value());
    BOOST_TEST(res.value() == "new_access");
}

BOOST_AUTO_TEST_CASE(refresh_not_called_when_valid)
{
    int calls = 0;
    const auto now = std::chrono::system_clock::now();
    mailxx::oauth2::token initial{"access", "refresh", now + std::chrono::minutes{10}};

    mailxx::oauth2::token_source source(initial,
        [&](const mailxx::oauth2::token&) -> mailxx::result<mailxx::oauth2::token> {
            ++calls;
            return mailxx::fail<mailxx::oauth2::token>(
                mailxx::errc::net_io_failed,
                "refresh should not be called");
        });

    auto res = source.get_access_token();
    BOOST_TEST(calls == 0);
    BOOST_TEST(res.has_value());
    BOOST_TEST(res.value() == "access");
}

BOOST_AUTO_TEST_CASE(refresh_error_propagated)
{
    int calls = 0;
    const auto now = std::chrono::system_clock::now();
    mailxx::oauth2::token initial{"access", "refresh", now - std::chrono::minutes{1}};

    mailxx::oauth2::token_source source(initial,
        [&](const mailxx::oauth2::token&) -> mailxx::result<mailxx::oauth2::token> {
            ++calls;
            return mailxx::fail<mailxx::oauth2::token>(
                mailxx::errc::net_io_failed,
                "refresh failed");
        });

    auto res = source.get_access_token();
    BOOST_TEST(calls == 1);
    BOOST_TEST(!res.has_value());
    BOOST_TEST(mailxx::to_string(res.error().code) == "net_io_failed");
}

/*

test_pop3_reconnect_snapshot.cpp
--------------------------------

Copyright (C) 2025, Sylvain Guinebert.

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#define MAILXX_TESTING
#define BOOST_TEST_MODULE pop3_reconnect_snapshot_test

#include <boost/asio.hpp>
#include <boost/test/unit_test.hpp>
#include <mailxx/net/tls_mode.hpp>
#include <mailxx/pop3/client.hpp>


BOOST_AUTO_TEST_CASE(pop3_snapshot_after_auth)
{
    boost::asio::io_context io_ctx;
    mailxx::pop3::options opts;
    opts.store_credentials_for_reconnect = true;

    mailxx::pop3::client conn(io_ctx.get_executor(), opts);
    conn.debug_remember_connection("pop.example.com", "995",
        mailxx::net::tls_mode::implicit, nullptr, "pop.example.com");
    conn.debug_remember_user_pass("user", "pass");

    const auto snap = conn.debug_snapshot();
    BOOST_TEST(snap.host == "pop.example.com");
    BOOST_TEST(snap.service == "995");
    BOOST_TEST(snap.tls_mode == mailxx::net::tls_mode::implicit);
    BOOST_TEST(snap.has_auth);
    BOOST_TEST(snap.username == "user");
    BOOST_TEST(snap.secret.has_value());
    BOOST_TEST(snap.secret.value() == "pass");
}

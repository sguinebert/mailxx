/*

test_redact.cpp
---------------

Copyright (C) 2025, Sylvain Guinebert.

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#define BOOST_TEST_MODULE redact_test

#include <boost/test/unit_test.hpp>
#include <mailxx/detail/redact.hpp>


BOOST_AUTO_TEST_CASE(redact_pass)
{
    BOOST_TEST(mailxx::detail::redact_command("PASS secret") == "PASS <redacted>");
}

BOOST_AUTO_TEST_CASE(redact_auth_plain)
{
    BOOST_TEST(mailxx::detail::redact_command("AUTH PLAIN dGVzdA==") == "AUTH <redacted>");
}

BOOST_AUTO_TEST_CASE(redact_login)
{
    BOOST_TEST(mailxx::detail::redact_command("LOGIN user pass") == "LOGIN user <redacted>");
}

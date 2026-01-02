/*

test_redact.cpp
---------------

Copyright (C) 2025, Sylvain Guinebert.

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/


#define BOOST_TEST_MODULE redact_test

#include <boost/test/unit_test.hpp>
#include <mailxx/detail/redact.hpp>


BOOST_AUTO_TEST_CASE(redact_pass)
{
    BOOST_TEST(mailxx::detail::redact_line("PASS secret") == "PASS <redacted>");
}

BOOST_AUTO_TEST_CASE(redact_auth_plain)
{
    BOOST_TEST(mailxx::detail::redact_line("AUTH PLAIN dGVzdA==") == "AUTH <redacted>");
}

BOOST_AUTO_TEST_CASE(redact_login)
{
    BOOST_TEST(mailxx::detail::redact_line("LOGIN user pass") == "LOGIN user <redacted>");
}

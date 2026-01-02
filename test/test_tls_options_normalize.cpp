/*

test_tls_options_normalize.cpp
------------------------------

Copyright (C) 2025, Sylvain Guinebert.

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/


#define BOOST_TEST_MODULE tls_options_normalize_test

#include <boost/test/unit_test.hpp>
#include <mailxx/net/tls_options.hpp>


BOOST_AUTO_TEST_CASE(normalize_hex_fingerprint)
{
    BOOST_TEST(mailxx::net::normalize_fingerprint("AA:bb:cc") == "aabbcc");
}

BOOST_AUTO_TEST_CASE(normalize_base64_fingerprint)
{
    BOOST_TEST(mailxx::net::normalize_fingerprint("YWJjYQ") == "YWJjYQ==");
}

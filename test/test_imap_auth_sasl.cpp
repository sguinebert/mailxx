/*

test_imap_auth_sasl.cpp
-----------------------

Copyright (C) 2025, Sylvain Guinebert.

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/


#define BOOST_TEST_MODULE imap_auth_sasl_test

#include <string>
#include <string_view>
#include <boost/test/unit_test.hpp>
#include <mailxx/codec/base64.hpp>
#include <mailxx/detail/sasl.hpp>
#include <mailxx/detail/result.hpp>


static mailxx::result<std::string> decode_base64_single_line(std::string_view encoded)
{
    const auto policy = static_cast<std::string::size_type>(mailxx::codec::line_len_policy_t::NONE);
    mailxx::base64 b64(policy, policy);
    return b64.decode(encoded);
}


BOOST_AUTO_TEST_CASE(sasl_plain_encoding)
{
    auto encoded = mailxx::sasl::encode_plain("user", "pass");
    BOOST_REQUIRE(encoded);
    auto decoded = decode_base64_single_line(*encoded);
    BOOST_REQUIRE(decoded);
    std::string expected;
    expected.push_back('\0');
    expected += "user";
    expected.push_back('\0');
    expected += "pass";
    BOOST_TEST(*decoded == expected);
}

BOOST_AUTO_TEST_CASE(sasl_xoauth2_encoding)
{
    auto encoded = mailxx::sasl::encode_xoauth2("user@example.com", "token");
    BOOST_REQUIRE(encoded);
    auto decoded = decode_base64_single_line(*encoded);
    BOOST_REQUIRE(decoded);
    std::string expected;
    expected += "user=user@example.com";
    expected.push_back('\x01');
    expected += "auth=Bearer token";
    expected.push_back('\x01');
    expected.push_back('\x01');
    BOOST_TEST(*decoded == expected);
}

BOOST_AUTO_TEST_CASE(sasl_login_encoding)
{
    auto encoded = mailxx::sasl::encode_login("login");
    BOOST_REQUIRE(encoded);
    auto decoded = decode_base64_single_line(*encoded);
    BOOST_REQUIRE(decoded);
    BOOST_TEST(*decoded == "login");
}

/*

test_imap_append_build.cpp
--------------------------

Copyright (C) 2025, Sylvain Guinebert.

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#define BOOST_TEST_MODULE imap_append_build_test

#include <stdexcept>
#include <boost/test/unit_test.hpp>
#include <mailxx/imap/types.hpp>


BOOST_AUTO_TEST_CASE(imap_append_build_basic)
{
    auto cmd = mailxx::imap::detail::build_append_command(
        "INBOX", 3, std::string_view{}, std::string_view{}, false);
    BOOST_REQUIRE(cmd);
    BOOST_TEST(cmd.value() == "APPEND \"INBOX\" {3}");
}

BOOST_AUTO_TEST_CASE(imap_append_build_flags_datetime)
{
    auto cmd = mailxx::imap::detail::build_append_command(
        "Archive", 10, "(\\Seen)", "01-Jan-2024 00:00:00 +0000", false);
    BOOST_REQUIRE(cmd);
    BOOST_TEST(cmd.value() == "APPEND \"Archive\" (\\Seen) \"01-Jan-2024 00:00:00 +0000\" {10}");
}

BOOST_AUTO_TEST_CASE(imap_append_build_literal_plus)
{
    auto cmd = mailxx::imap::detail::build_append_command(
        "INBOX", 5, std::string_view{}, std::string_view{}, true);
    BOOST_REQUIRE(cmd);
    BOOST_TEST(cmd.value() == "APPEND \"INBOX\" {5+}");
}

BOOST_AUTO_TEST_CASE(imap_append_sanitize)
{
    auto bad_mailbox = mailxx::imap::detail::build_append_command(
        "INBOX\r\n", 1, std::string_view{}, std::string_view{}, false);
    BOOST_TEST(!bad_mailbox);
    BOOST_TEST(bad_mailbox.error().code == mailxx::errc::codec_invalid_input);

    auto bad_flags = mailxx::imap::detail::build_append_command(
        "INBOX", 1, "FLAGS\r\n", {}, false);
    BOOST_TEST(!bad_flags);
    BOOST_TEST(bad_flags.error().code == mailxx::errc::codec_invalid_input);
}

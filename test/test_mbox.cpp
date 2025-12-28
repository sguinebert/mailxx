/*

test_mbox.cpp
-------------

Checks mbox writer/reader roundtrip with dot-escaped From lines.

*/

#define BOOST_TEST_MODULE mbox_test

#include <string>
#include <sstream>
#include <chrono>
#include <boost/test/unit_test.hpp>
#include <mailxx/storage/mbox.hpp>

using mailxx::storage::mbox_reader;
using mailxx::storage::mbox_writer;
using mailxx::storage::from_line_metadata;

BOOST_AUTO_TEST_CASE(mbox_roundtrip_two_messages)
{
    std::string msg1 = "From: a@example.com\r\n\r\nHello\r\nFrom line\r\n";
    std::string msg2 = "From: b@example.com\r\n\r\nSecond\r\n>From preserved\r\n";

    std::stringstream ss;
    mbox_writer writer(ss);
    writer.append_message(msg1, {"sender@example.com", "Mon Jan  1 00:00:00 2025"});
    writer.append_message(msg2, {"sender@example.com", "Mon Jan  1 00:00:01 2025"});

    mbox_reader reader(ss);
    auto m1 = reader.next();
    auto m2 = reader.next();
    auto m3 = reader.next();

    BOOST_REQUIRE(m1.has_value());
    BOOST_REQUIRE(m2.has_value());
    BOOST_CHECK(!m3.has_value());

    BOOST_CHECK_EQUAL(*m1, "From: a@example.com\n\nHello\nFrom line\n");
    BOOST_CHECK_EQUAL(*m2, "From: b@example.com\n\nSecond\nFrom preserved\n");
}

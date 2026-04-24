/*

test_message_parse_date.cpp
---------------------------

Validates RFC 5322 date parsing edge cases.

*/

#define BOOST_TEST_MODULE message_parse_date_test

#include <chrono>
#include <string>

#include <boost/test/unit_test.hpp>

#include <mailxx/mime/message.hpp>

namespace
{

struct parse_probe : mailxx::message
{
    using mailxx::message::parse_date;
};

std::chrono::zoned_time<std::chrono::seconds> make_zoned_time(
    int year, int month, int day, int hour, int minute, int second,
    int offset_hours, int offset_minutes = 0)
{
    std::chrono::year_month_day ymd{
        std::chrono::year{year},
        std::chrono::month{static_cast<unsigned>(month)},
        std::chrono::day{static_cast<unsigned>(day)}
    };
    auto local_tp = std::chrono::local_days{ymd}
        + std::chrono::hours{hour}
        + std::chrono::minutes{minute}
        + std::chrono::seconds{second};
    auto offset = std::chrono::hours{offset_hours} + std::chrono::minutes{offset_minutes};
    auto sys_tp = std::chrono::sys_time<std::chrono::seconds>{local_tp.time_since_epoch() - offset};
    return std::chrono::zoned_time<std::chrono::seconds>{std::chrono::current_zone(), sys_tp};
}

} // namespace

BOOST_AUTO_TEST_CASE(parse_date_accepts_optional_seconds)
{
    parse_probe msg;
    auto parsed = msg.parse_date("Fri, 21 Nov 1997 09:55 -0600");

    BOOST_REQUIRE(parsed);
    BOOST_CHECK(parsed->get_sys_time() == make_zoned_time(1997, 11, 21, 9, 55, 0, -6, 0).get_sys_time());
}

BOOST_AUTO_TEST_CASE(parse_date_accepts_gmt_zone_name)
{
    parse_probe msg;
    auto parsed = msg.parse_date("Fri, 24 Apr 2026 13:01:37 GMT");

    BOOST_REQUIRE(parsed);
    BOOST_CHECK(parsed->get_sys_time() == make_zoned_time(2026, 4, 24, 13, 1, 37, 0, 0).get_sys_time());
}

BOOST_AUTO_TEST_CASE(message_parse_accepts_gmt_date_header)
{
    const std::string msg_str =
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: parse gmt date\r\n"
        "Date: Fri, 24 Apr 2026 13:01:37 GMT\r\n"
        "\r\n"
        "hello\r\n";

    mailxx::message msg;

    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.date_time().get_sys_time() == make_zoned_time(2026, 4, 24, 13, 1, 37, 0, 0).get_sys_time());
    BOOST_CHECK(msg.subject() == "parse gmt date");
}

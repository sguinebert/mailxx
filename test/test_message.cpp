/*

test_message.cpp
----------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#define BOOST_TEST_MODULE message_test

#include <string>
#include <istream>
#include <fstream>
#include <utility>
#include <list>
#include <tuple>
#include <chrono>
#include <boost/test/unit_test.hpp>
#include <mailxx/mime/mailboxes.hpp>
#include <mailxx/mime/message.hpp>


#define MAILXX_CHECK_RESULT_EQ(expr, expected) \
    do { \
        auto _res = (expr); \
        BOOST_CHECK(_res && *_res == (expected)); \
    } while (0)

using std::string;
using std::ifstream;
using std::ofstream;
using std::list;
using std::tuple;
using std::make_tuple;
using mailxx::string_t;
#if defined(__cpp_char8_t)
using mailxx::u8string_t;
#endif
using mailxx::codec;
using mailxx::mail_address;
using mailxx::mail_group;
using mailxx::mime;
using mailxx::message;
// using mailxx::mime_error;
// using mailxx::message_error;
// using mailxx::codec_error;

// Helper function to create a zoned_time from local datetime components and UTC offset
inline std::chrono::zoned_time<std::chrono::seconds> make_zoned_time(
    int year, int month, int day, int hour, int minute, int second,
    int offset_hours, int offset_minutes = 0)
{
    std::chrono::year_month_day ymd{std::chrono::year{year}, std::chrono::month{static_cast<unsigned>(month)}, std::chrono::day{static_cast<unsigned>(day)}};
    auto local_tp = std::chrono::local_days{ymd} + std::chrono::hours{hour} + std::chrono::minutes{minute} + std::chrono::seconds{second};
    auto offset = std::chrono::hours{offset_hours} + std::chrono::minutes{offset_minutes};
    auto sys_tp = std::chrono::sys_time<std::chrono::seconds>{local_tp.time_since_epoch() - offset};
    return std::chrono::zoned_time<std::chrono::seconds>{std::chrono::current_zone(), sys_tp};
}

#ifdef __cpp_char8_t
#define utf8_string std::u8string
#else
#define utf8_string std::string
#endif


/**
Verifying setters and getters for sender/reply/recipient addresses, message date, subject, content type, transfer encoding and short ASCII content.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_addresses)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "contact@mailxx.dev"));
    msg.add_recipient(mail_address("contact", "contact@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_group("all", {mail_address("Mailxx", "qwertyuiop@hotmail.com")}));
    msg.add_cc_recipient(mail_group("mailxx", {mail_address("", "example@mailxx.dev"), mail_address("Sylvain Guinebert", "contact@mailxx.dev")}));
    msg.add_cc_recipient(mail_address("Sylvain Guinebert", "contact@mailxx.dev"));
    msg.add_cc_recipient(mail_address("Sylvain @ Guinebert", "qwertyuiop@gmail.com"));
    msg.add_cc_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_cc_recipient(mail_group("all", {mail_address("", "qwertyuiop@hotmail.com"), mail_address("Sylvain", "qwertyuiop@gmail.com"),
        mail_address("Sylvain @ Guinebert", "qwertyuiop@zoho.com")}));
    msg.add_bcc_recipient(mail_address("Sylvain Guinebert", "contact@mailxx.dev"));
    msg.add_bcc_recipient(mail_address("Sylvain @ Guinebert", "qwertyuiop@gmail.com"));
    msg.add_bcc_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("Hello, World!");
    msg.content("Hello, World!");
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);

    MAILXX_CHECK_RESULT_EQ(msg.from_to_string(), "mailxx <address@mailxx.dev>");
    MAILXX_CHECK_RESULT_EQ(msg.reply_address_to_string(), "Sylvain Guinebert <contact@mailxx.dev>");
    auto recipients_res = msg.recipients_to_string();
    BOOST_REQUIRE(recipients_res);
    BOOST_CHECK(*recipients_res == "contact <contact@mailxx.dev>,\r\n"
        "  mailxx <address@mailxx.dev>,\r\n"
        "  all: Sylvain <qwertyuiop@hotmail.com>;");
    auto cc_res = msg.cc_recipients_to_string();

    BOOST_REQUIRE(cc_res);

    BOOST_CHECK(*cc_res == "Sylvain Guinebert <contact@mailxx.dev>,\r\n"
        "  \"Sylvain @ Guinebert\" <qwertyuiop@gmail.com>,\r\n"
        "  mailxx <address@mailxx.dev>,\r\n"
        "  mailxx: <karas@mailxx.dev>,\r\n"
        "  Sylvain Guinebert <contact@mailxx.dev>;\r\n"
        "  all: <qwertyuiop@hotmail.com>,\r\n"
        "  Sylvain <qwertyuiop@gmail.com>,\r\n"
        "  \"Sylvain @ Guinebert\" <qwertyuiop@zoho.com>;");
    auto bcc_res = msg.bcc_recipients_to_string();

    BOOST_REQUIRE(bcc_res);

    BOOST_CHECK(*bcc_res == "Sylvain Guinebert <contact@mailxx.dev>,\r\n"
        "  \"Sylvain @ Guinebert\" <qwertyuiop@gmail.com>,\r\n"
        "  mailxx <address@mailxx.dev>");
    BOOST_CHECK(msg.date_time() == ldt);
    BOOST_CHECK(msg.content_type().media_type() == mime::media_type_t::NONE && msg.content_type().media_subtype().empty() && msg.content_type().charset().empty());
    BOOST_CHECK(msg.content_transfer_encoding() == mime::content_transfer_encoding_t::NONE);
    BOOST_CHECK(msg.content() == "Hello, World!");
}


/**
Formatting a message without author.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_no_from)
{
    message msg;
    msg.sender(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("format no from");
    string msg_str;
    BOOST_CHECK(!msg.format(msg_str));
}


/**
Formatting a message with two authors but no sender.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_no_sender_two_authors)
{
    message msg;
    msg.add_from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_from(mail_address("karas", "karas@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("format no sender two authors");
    string msg_str;
    BOOST_CHECK(!msg.format(msg_str));
}

/**
Formatting a message without a subject.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_no_subject)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2025, 5, 20, 19, 28, 17, 2, 0);
    msg.date_time(ldt);

    string msg_str;
    BOOST_CHECK(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Tue, 20 May 2025 21:28:17 +0200\r\n");
}


/**
Formatting other headers.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_other_headers)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("Hello, World!");
    msg.content("Hello, World!");
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    BOOST_REQUIRE(msg.add_header("User-Agent", "mailxx"));
    BOOST_REQUIRE(msg.add_header("Content-Language", "en-US"));
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "Content-Language: en-US\r\n"
        "User-Agent: mailxx\r\n"
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: Hello, World!\r\n"
        "\r\n"
        "Hello, World!\r\n");
    BOOST_CHECK(msg.headers().size() == 2);

    msg.remove_header("User-Agent");
    msg_str.clear();
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "Content-Language: en-US\r\n"
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: Hello, World!\r\n"
        "\r\n"
        "Hello, World!\r\n");
    BOOST_CHECK(msg.headers().size() == 1);
}


/**
Formatting multiline content with lines containing leading dots, with the escaping dot flag off.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_dotted_no_escape)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format dotted no escape");
    msg.content(".Hello, World!\r\n"
        "hello again\r\n"
        "..test\r\n"
        "\r\n"
        ".\r\n"
        "\r\n"
        "yaba.daba.doo.\r\n"
        "\r\n"
        "..\r\n"
        "\r\n");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: format dotted no escape\r\n"
        "\r\n"
        ".Hello, World!\r\n"
        "hello again\r\n"
        "..test\r\n"
        "\r\n"
        ".\r\n"
        "\r\n"
        "yaba.daba.doo.\r\n"
        "\r\n"
        "..\r\n");
}


/**
Formatting multiline content with lines containing leading dots, with the escaping dot flag on.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_dotted_escape)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format dotted escape");
    msg.content(".Hello, World!\r\n"
        "hello again\r\n"
        "..test\r\n"
        "\r\n"
        ".\r\n"
        "\r\n"
        "yaba.daba.doo.\r\n"
        "\r\n"
        "..\r\n"
        "\r\n");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str, {true}));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: format dotted escape\r\n"
        "\r\n"
        "..Hello, World!\r\n"
        "hello again\r\n"
        "...test\r\n"
        "\r\n"
        "..\r\n"
        "\r\n"
        "yaba.daba.doo.\r\n"
        "\r\n"
        "...\r\n");
}

/**
Formatting a message with bcc_headers set and format option `add_bcc_headers` set to true
adds BCC headers to the message

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_exports_bcc_headers_when_add_bcc_headers_is_set)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.add_bcc_recipient(mail_address("bcc_addr_1", "bcc_addr_1@mailxx.dev"));
    msg.add_bcc_recipient(mail_address("bcc_addr_2", "bcc_addr_2@mailxx.dev"));
    msg.subject("BCC addresses are formatted");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str, {true, true}));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Bcc: \"bcc_addr_1\" <bcc_addr_1@mailxx.dev>,\r\n"
        "  \"bcc_addr_2\" <bcc_addr_2@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: BCC addresses are formatted\r\n\r\n");
}

/**
Formatting a message with bcc_headers set and format option `add_bcc_headers` set to false
does not add BCC headers to the message

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_does_not_exports_bcc_headers_when_add_bcc_headers_is_not_set)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.add_bcc_recipient(mail_address("bcc_addr_1", "bcc_addr_1@mailxx.dev"));
    msg.subject("BCC addresses are not formatted");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str, {true, false}));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: BCC addresses are not formatted\r\n\r\n");
}


/**
Formatting long default content (which is text with ASCII charset) default encoded (which is Seven Bit) to lines with the recommended length.

Since content type and transfer encoding are default, no such headers are created.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_long_text_default_default)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format long text default default");
    msg.content("This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n\r\n\r\n"
        "Here is also a check for a sequence of blank lines.\r\n\r\n\r\n");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: format long text default default\r\n"
        "\r\n"
        "This is a very long message that has blank lines and very long lines. It is no\r\n"
        "t clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust mess\r\n"
        "age formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and se\r\n"
        "e how wrapping behaves when characters are multi-byte. It should not matter wh\r\n"
        "ether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. T\r\n"
        "his test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n");
}


/**
Formatting long text default charset (which is ASCII) Base64 encoded to lines with the recommended length.

Since charset is default, it is not set in the content type header.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_long_text_default_base64)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format long text default base64");
    msg.content_transfer_encoding(mime::content_transfer_encoding_t::BASE_64);
    msg.content_type(message::media_type_t::TEXT, "plain");
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.content("This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n\r\n\r\n"
        "Here is also a check for a sequence of blank lines.\r\n\r\n\r\n");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Subject: format long text default base64\r\n"
        "\r\n"
        "VGhpcyBpcyBhIHZlcnkgbG9uZyBtZXNzYWdlIHRoYXQgaGFzIGJsYW5rIGxpbmVzIGFuZCB2ZXJ5\r\n"
        "IGxvbmcgbGluZXMuIEl0IGlzIG5vdCBjbGVhciBob3cgdGhlIHRleHQgd2lsbCB3cmFwDQpzbyBJ\r\n"
        "IGhvcGUgdGhpcyB0ZXh0IHNob3dzIHRoYXQuDQoNCldlIHNob3VsZCBzZWUgaG93IGNvbW1vbiBt\r\n"
        "YWlsIGNsaWVudHMgd3JhcCB0ZXh0LCBhbmQgYmFzZWQgb24gdGhhdCBhZGp1c3QgbWVzc2FnZSBm\r\n"
        "b3JtYXR0aW5nLiBNYXliZSB0aGVyZSBpcyBubyBuZWVkLCBiZWNhdXNlIGxpYm1haWx4eCBpcyBu\r\n"
        "b3QgbWVhbnQgdG8NCmZvcm1hdCB0ZXh0Lg0KDQpJbiBhbnkgY2FzZSwgYWZ0ZXIgY2hlY2tpbmcg\r\n"
        "QVNDSUkgd2Ugc2hvdWxkIGFsc28gY2hlY2sgVVRGLTggY2hhcmFjdGVycyBhbmQgc2VlIGhvdyB3\r\n"
        "cmFwcGluZyBiZWhhdmVzIHdoZW4gY2hhcmFjdGVycyBhcmUgbXVsdGktYnl0ZS4gSXQgc2hvdWxk\r\n"
        "IG5vdCBtYXR0ZXIgd2hldGhlciB0aGUgZW5jb2RpbmcNCmlzIGJhc2U2NCBvciBxdW90ZWQgcHJp\r\n"
        "bnRhYmxlLCBiZWNhdXNlIEFTQ0lJIGNoYXJhY3RlcnMgd3JhcCBpbnRvIG5ldyBsaW5lcy4gVGhp\r\n"
        "cyB0ZXN0IHNob3VsZCBzaG93IHdoZXRoZXIgdGhlcmUgYXJlIGJ1Z3MgaW4gdGhlIGZvcm1hdHRp\r\n"
        "bmcgbG9naWMsDQphbmQgdGhlIHNhbWUgc2hvdWxkIGJlIGNoZWNrZWQgd2hlbiBwYXJzaW5nLg0K\r\n"
        "DQoNCg0KSGVyZSBpcyBhbHNvIGEgY2hlY2sgZm9yIGEgc2VxdWVuY2Ugb2YgYmxhbmsgbGluZXMu\r\n"
        "DQoNCg0K\r\n");
}


/**
Formatting long text ASCII charset Quoted Printable encoded to lines with the recommended length.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_long_text_ascii_qp)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format long text ascii quoted printable");
    msg.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    msg.content_type(message::media_type_t::TEXT, "plain", "us-ascii");
    msg.content("This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n\r\n\r\n"
        "Here is also a check for a sequence of blank lines.\r\n\r\n\r\n");
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "Subject: format long text ascii quoted printable\r\n"
        "\r\n"
        "This is a very long message that has blank lines and very long lines. It is =\r\n"
        "not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust m=\r\n"
        "essage formatting. Maybe there is no need, because libmailxx is not meant t=\r\n"
        "o\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and =\r\n"
        "see how wrapping behaves when characters are multi-byte. It should not matt=\r\n"
        "er whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines=\r\n"
        ". This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n");
}


/**
Formatting long text UTF-8 charset Base64 encoded to lines with the recommended length.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_long_text_utf8_base64)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format long text utf8 base64");
    msg.content_type(message::media_type_t::TEXT, "plain", "utf-8");
    msg.content_transfer_encoding(mime::content_transfer_encoding_t::BASE_64);
    msg.content("This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n\r\n\r\n"
        "Here is also a check for a sequence of blank lines.\r\n\r\n\r\n");
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Subject: format long text utf8 base64\r\n"
        "\r\n"
        "VGhpcyBpcyBhIHZlcnkgbG9uZyBtZXNzYWdlIHRoYXQgaGFzIGJsYW5rIGxpbmVzIGFuZCB2ZXJ5\r\n"
        "IGxvbmcgbGluZXMuIEl0IGlzIG5vdCBjbGVhciBob3cgdGhlIHRleHQgd2lsbCB3cmFwDQpzbyBJ\r\n"
        "IGhvcGUgdGhpcyB0ZXh0IHNob3dzIHRoYXQuDQoNCldlIHNob3VsZCBzZWUgaG93IGNvbW1vbiBt\r\n"
        "YWlsIGNsaWVudHMgd3JhcCB0ZXh0LCBhbmQgYmFzZWQgb24gdGhhdCBhZGp1c3QgbWVzc2FnZSBm\r\n"
        "b3JtYXR0aW5nLiBNYXliZSB0aGVyZSBpcyBubyBuZWVkLCBiZWNhdXNlIGxpYm1haWx4eCBpcyBu\r\n"
        "b3QgbWVhbnQgdG8NCmZvcm1hdCB0ZXh0Lg0KDQpJbiBhbnkgY2FzZSwgYWZ0ZXIgY2hlY2tpbmcg\r\n"
        "QVNDSUkgd2Ugc2hvdWxkIGFsc28gY2hlY2sgVVRGLTggY2hhcmFjdGVycyBhbmQgc2VlIGhvdyB3\r\n"
        "cmFwcGluZyBiZWhhdmVzIHdoZW4gY2hhcmFjdGVycyBhcmUgbXVsdGktYnl0ZS4gSXQgc2hvdWxk\r\n"
        "IG5vdCBtYXR0ZXIgd2hldGhlciB0aGUgZW5jb2RpbmcNCmlzIGJhc2U2NCBvciBxdW90ZWQgcHJp\r\n"
        "bnRhYmxlLCBiZWNhdXNlIEFTQ0lJIGNoYXJhY3RlcnMgd3JhcCBpbnRvIG5ldyBsaW5lcy4gVGhp\r\n"
        "cyB0ZXN0IHNob3VsZCBzaG93IHdoZXRoZXIgdGhlcmUgYXJlIGJ1Z3MgaW4gdGhlIGZvcm1hdHRp\r\n"
        "bmcgbG9naWMsDQphbmQgdGhlIHNhbWUgc2hvdWxkIGJlIGNoZWNrZWQgd2hlbiBwYXJzaW5nLg0K\r\n"
        "DQoNCg0KSGVyZSBpcyBhbHNvIGEgY2hlY2sgZm9yIGEgc2VxdWVuY2Ugb2YgYmxhbmsgbGluZXMu\r\n"
        "DQoNCg0K\r\n");
}


/**
Formatting long text UTF-8 cyrillic charset Quoted Printable encoded to lines with the recommended length.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_long_text_utf8_cyr_qp)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format long text utf8 cyrillic quoted printable");
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    msg.content_type(message::media_type_t::TEXT, "plain", "utf-8");
    msg.content("This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n\r\n\r\n"
        "Here is also a check for a sequence of blank lines.\r\n\r\n\r\n");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "Subject: format long text utf8 cyrillic quoted printable\r\n"
        "\r\n"
        "This is a very long message that has blank lines and very long lines. It is =\r\n"
        "not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust m=\r\n"
        "essage formatting. Maybe there is no need, because libmailxx is not meant t=\r\n"
        "o\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and =\r\n"
        "see how wrapping behaves when characters are multi-byte. It should not matt=\r\n"
        "er whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines=\r\n"
        ". This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n");
}


/**
Formatting long text UTF-8 latin charset Quoted Printable encoded to lines with the recommended length.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_long_text_utf8_lat_qp)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format long text utf8 latin quoted printable");
    msg.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    msg.content_type(message::media_type_t::TEXT, "plain", "utf-8");
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.content("This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n\r\n\r\n"
        "Here is also a check for a sequence of blank lines.\r\n\r\n\r\n");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "Subject: format long text utf8 latin quoted printable\r\n"
        "\r\n"
        "This is a very long message that has blank lines and very long lines. It is =\r\n"
        "not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust m=\r\n"
        "essage formatting. Maybe there is no need, because libmailxx is not meant t=\r\n"
        "o\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and =\r\n"
        "see how wrapping behaves when characters are multi-byte. It should not matt=\r\n"
        "er whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines=\r\n"
        ". This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n");
}

BOOST_AUTO_TEST_CASE(format_multipart_html_ascii_bit7_text_ascii_base64)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format multipart html ascii bit7 text ascii base64");
    msg.content_type(message::media_type_t::MULTIPART, "related");
    msg.content_type().boundary("my_bound");

    mime m1;
    m1.content_type(message::media_type_t::TEXT, "html", "us-ascii");
    m1.content_transfer_encoding(mime::content_transfer_encoding_t::BIT_7);
    m1.content("<html><head></head><body><h1>Hello, World!</h1></body></html>");

    mime m2;
    m2.content_type(message::media_type_t::TEXT, "plain", "us-ascii");
    m2.content_transfer_encoding(mime::content_transfer_encoding_t::BASE_64);
    m2.content("Hello, World!");

    msg.add_part(m1);
    msg.add_part(m2);

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/related; boundary=\"my_bound\"\r\n"
        "Subject: format multipart html ascii bit7 text ascii base64\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "\r\n"
        "<html><head></head><body><h1>Hello, World!</h1></body></html>\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "\r\n"
        "SGVsbG8sIFdvcmxkIQ==\r\n"
        "\r\n"
        "--my_bound--\r\n");
}


/**
Formatting an alternative multipart message with the first part HTML ASCII charset Quoted Printable encoded, the second part text ASCII charset Bit8 encoded.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_multipart_html_ascii_qp_text_ascii_bit8)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format multipart html ascii qp text ascii bit8");
    msg.content_type(message::media_type_t::MULTIPART, "alternative");
    msg.content_type().boundary("my_bound");

    mime m1;
    m1.content_type(message::media_type_t::TEXT, "html", "us-ascii");
    m1.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    m1.content("<html><head></head><body><h1>Hello, World!</h1></body></html>");

    mime m2;
    m2.content_type(message::media_type_t::TEXT, "plain", "us-ascii");
    m2.content_transfer_encoding(mime::content_transfer_encoding_t::BIT_8);
    m2.content("Hello, World!");

    msg.add_part(m1);
    msg.add_part(m2);

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/alternative; boundary=\"my_bound\"\r\n"
        "Subject: format multipart html ascii qp text ascii bit8\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "<html><head></head><body><h1>Hello, World!</h1></body></html>\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 8bit\r\n"
        "\r\n"
        "Hello, World!\r\n"
        "\r\n"
        "--my_bound--\r\n");
}


/**
Formatting a related multipart with the first part HTML default charset Base64 encoded, the second part text UTF-8 charset Quoted Printable encoded.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_related_html_default_base64_text_utf8_qp)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format related html default base64 text utf8 qp");
    msg.content_type(message::media_type_t::MULTIPART, "related");
    msg.content_type().boundary("my_bound");

    mime m1;
    m1.line_policy(codec::line_len_policy_t::RECOMMENDED);
    m1.content_type(message::media_type_t::TEXT, "html");
    m1.content_transfer_encoding(mime::content_transfer_encoding_t::BASE_64);
    m1.content("<html><head></head><body><h1>Hello, World!</h1></body></html>");

    mime m2;
    m2.line_policy(codec::line_len_policy_t::RECOMMENDED);
    m2.content_type(message::media_type_t::TEXT, "plain", "utf-8");
    m2.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    m2.content("Hello, World!");

    msg.add_part(m1);
    msg.add_part(m2);

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/related; boundary=\"my_bound\"\r\n"
        "Subject: format related html default base64 text utf8 qp\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "\r\n"
        "PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5PjxoMT5IZWxsbywgV29ybGQhPC9oMT48L2JvZHk+PC9o\r\n"
        "dG1sPg==\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "Hello, World!\r\n"
        "\r\n"
        "--my_bound--\r\n");
}


/**
Formatting an alternative multipart with the first part HTML ASCII charset Bit8 encoded, the second part text UTF-8 charset Base64 encoded.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_alternative_html_ascii_bit8_text_utf8_base64)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format alternative html ascii bit8 text utf8 base64");
    msg.content_type(message::media_type_t::MULTIPART, "alternative");
    msg.content_type().boundary("my_bound");

    mime m1;
    m1.content_type(message::media_type_t::TEXT, "html", "us-ascii");
    m1.content_transfer_encoding(mime::content_transfer_encoding_t::BIT_8);
    m1.content("<html><head></head><body><h1>Hello, World!</h1></body></html>");

    mime m2;
    m2.content_type(message::media_type_t::TEXT, "plain", "utf-8");
    m2.content_transfer_encoding(mime::content_transfer_encoding_t::BASE_64);
    m2.content("Hello, World!");

    msg.add_part(m1);
    msg.add_part(m2);

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/alternative; boundary=\"my_bound\"\r\n"
        "Subject: format alternative html ascii bit8 text utf8 base64\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 8bit\r\n"
        "\r\n"
        "<html><head></head><body><h1>Hello, World!</h1></body></html>\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "\r\n"
        "SGVsbG8sIFdvcmxkIQ==\r\n"
        "\r\n"
        "--my_bound--\r\n");
}


/**
Formatting a multipart message with leading dots and the escaping flag turned off and on.

The first part is HTML ASCII charset Seven Bit encoded, the second part is text UTF-8 charset Quoted Printable encoded, the third part is text UTF-8
charset Quoted Printable encoded, the fourth part is HTML ASCII charset Base64 encoded.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_dotted_multipart)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("Sylvain Guinebert", "qwerty@gmail.com"));
    msg.add_recipient(mail_address("Sylvain Guinebert", "asdfgh@zoho.com"));
    msg.add_recipient(mail_address("Sylvain Guinebert", "zxcvbn@hotmail.com"));
    auto ldt = make_zoned_time(2016, 3, 15, 13, 13, 32, 0, 0);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.date_time(ldt);
    msg.subject("format dotted multipart");
    msg.content_type(message::media_type_t::MULTIPART, "related");
    msg.content_type().boundary("my_bound");

    mime m1;
    m1.content_type(message::media_type_t::TEXT, "html", "us-ascii");
    m1.content_transfer_encoding(mime::content_transfer_encoding_t::BIT_7);
    m1.line_policy(codec::line_len_policy_t::RECOMMENDED);
    m1.content("<html>\r\n"
        "\t<head>\r\n"
        "\t\t<title>.title</title>\r\n"
        "\t</head>\r\n"
        "..\r\n"
        "\t<body>\r\n"
        "\t\t<h1>\r\n"
        "\t\t\t..Hello, Worldeeeee!\r\n"
        "\t\t</h1>\r\n"
        "\r\n"
        "\r\n"
        ".\r\n"
        "\r\n"
        "\r\n"
        "\t.<p>Anyone there?</p>\r\n"
        "\t</body>\r\n"
        "</html>");

    mime m2;
    m2.line_policy(codec::line_len_policy_t::RECOMMENDED);
    m2.content_type(message::media_type_t::TEXT, "plain", "utf-8");
    m2.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    m2.content(".Hello world!\r\n"
        "..\r\n"
        "Anyone there?\r\n"
        "\r\n"
        "\r\n"
        ".\r\n"
        "\r\n"
        "\r\n"
        "..yabadabadoo...\r\n");

    mime m3;
    m3.content_type(message::media_type_t::TEXT, "plain", "utf-8");
    m3.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    m3.line_policy(codec::line_len_policy_t::RECOMMENDED);
    m3.content(".Hello, World!\r\n"
        "..\r\n"
        "Is anyone there?\r\n"
        "\r\n\r\n"
        ".\r\n"
        "\r\n\r\n"
        "..yabba dabba doo...\r\n");

    mime m4;
    m4.content_type(message::media_type_t::TEXT, "html", "us-ascii");
    m4.content_transfer_encoding(mime::content_transfer_encoding_t::BASE_64);
    m4.content("<html>\r\n"
        "\t<head>\r\n"
        "\t\t<title>.title</title>\r\n"
        "\t</head>\r\n"
        "..\r\n"
        "\t<body>\r\n"
        "\t\t<h1>\r\n"
        "\t\t\t..Hello, Worldeeeee!\r\n"
        "\t\t</h1>\r\n"
        "\r\n"
        "\r\n"
        ".\r\n"
        "\r\n"
        "\r\n"
        "\t.<p>Anyone there?</p>\r\n"
        "\t</body>\r\n"
        "</html>");
    m4.line_policy(codec::line_len_policy_t::RECOMMENDED);

    msg.add_part(m1);
    msg.add_part(m2);
    msg.add_part(m3);
    msg.add_part(m4);

    {
        string msg_str;
        BOOST_REQUIRE(msg.format(msg_str, {false}));
        BOOST_CHECK(msg_str ==
            "From: mailxx <address@mailxx.dev>\r\n"
            "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
            "To: mailxx <address@mailxx.dev>,\r\n"
            "  Sylvain Guinebert <qwerty@gmail.com>,\r\n"
            "  Sylvain Guinebert <asdfgh@zoho.com>,\r\n"
            "  Sylvain Guinebert <zxcvbn@hotmail.com>\r\n"
            "Date: Tue, 15 Mar 2016 13:13:32 +0000\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/related; boundary=\"my_bound\"\r\n"
            "Subject: format dotted multipart\r\n"
            "\r\n"
            "--my_bound\r\n"
            "Content-Type: text/html; charset=us-ascii\r\n"
            "Content-Transfer-Encoding: 7bit\r\n"
            "\r\n"
            "<html>\r\n"
            "\t<head>\r\n"
            "\t\t<title>.title</title>\r\n"
            "\t</head>\r\n"
            "..\r\n"
            "\t<body>\r\n"
            "\t\t<h1>\r\n"
            "\t\t\t..Hello, Worldeeeee!\r\n"
            "\t\t</h1>\r\n"
            "\r\n"
            "\r\n"
            ".\r\n"
            "\r\n\r\n"
            "\t.<p>Anyone there?</p>\r\n"
            "\t</body>\r\n"
            "</html>\r\n"
            "\r\n"
            "--my_bound\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Transfer-Encoding: Quoted-Printable\r\n"
            "\r\n"
            ".Hello world!\r\n"
            "..\r\n"
            "Anyone there?\r\n"
            "\r\n"
            "\r\n"
            ".\r\n"
            "\r\n"
            "\r\n"
            "..yabadabadoo...\r\n"
            "\r\n"
            "--my_bound\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Transfer-Encoding: Quoted-Printable\r\n"
            "\r\n"
            ".Hello, World!\r\n"
            "..\r\n"
            "Is anyone there?\r\n"
            "\r\n\r\n"
            ".\r\n"
            "\r\n\r\n"
            "..yabba dabba doo...\r\n"
            "\r\n"
            "--my_bound\r\n"
            "Content-Type: text/html; charset=us-ascii\r\n"
            "Content-Transfer-Encoding: Base64\r\n"
            "\r\n"
            "PGh0bWw+DQoJPGhlYWQ+DQoJCTx0aXRsZT4udGl0bGU8L3RpdGxlPg0KCTwvaGVhZD4NCi4uDQoJ\r\n"
            "PGJvZHk+DQoJCTxoMT4NCgkJCS4uSGVsbG8sIFdvcmxkZWVlZWUhDQoJCTwvaDE+DQoNCg0KLg0K\r\n"
            "DQoNCgkuPHA+QW55b25lIHRoZXJlPzwvcD4NCgk8L2JvZHk+DQo8L2h0bWw+\r\n"
            "\r\n"
            "--my_bound--\r\n");
    }

    {
        string msg_str;
        BOOST_REQUIRE(msg.format(msg_str, {true}));
        BOOST_CHECK(msg_str ==
            "From: mailxx <address@mailxx.dev>\r\n"
            "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
            "To: mailxx <address@mailxx.dev>,\r\n"
            "  Sylvain Guinebert <qwerty@gmail.com>,\r\n"
            "  Sylvain Guinebert <asdfgh@zoho.com>,\r\n"
            "  Sylvain Guinebert <zxcvbn@hotmail.com>\r\n"
            "Date: Tue, 15 Mar 2016 13:13:32 +0000\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/related; boundary=\"my_bound\"\r\n"
            "Subject: format dotted multipart\r\n"
            "\r\n"
            "--my_bound\r\n"
            "Content-Type: text/html; charset=us-ascii\r\n"
            "Content-Transfer-Encoding: 7bit\r\n"
            "\r\n"
            "<html>\r\n"
            "\t<head>\r\n"
            "\t\t<title>.title</title>\r\n"
            "\t</head>\r\n"
            "...\r\n"
            "\t<body>\r\n"
            "\t\t<h1>\r\n"
            "\t\t\t..Hello, Worldeeeee!\r\n"
            "\t\t</h1>\r\n"
            "\r\n"
            "\r\n"
            "..\r\n"
            "\r\n"
            "\r\n"
            "\t.<p>Anyone there?</p>\r\n"
            "\t</body>\r\n"
            "</html>\r\n"
            "\r\n"
            "--my_bound\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Transfer-Encoding: Quoted-Printable\r\n"
            "\r\n"
            "..Hello world!\r\n"
            "...\r\n"
            "Anyone there?\r\n"
            "\r\n"
            "\r\n"
            "..\r\n"
            "\r\n"
            "\r\n"
            "...yabadabadoo...\r\n"
            "\r\n"
            "--my_bound\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Transfer-Encoding: Quoted-Printable\r\n"
            "\r\n"
            "..Hello, World!\r\n"
            "...\r\n"
            "Is anyone there?\r\n"
            "\r\n\r\n"
            "..\r\n"
            "\r\n\r\n"
            "...yabba dabba doo...\r\n"
            "\r\n"
            "--my_bound\r\n"
            "Content-Type: text/html; charset=us-ascii\r\n"
            "Content-Transfer-Encoding: Base64\r\n"
            "\r\n"
            "PGh0bWw+DQoJPGhlYWQ+DQoJCTx0aXRsZT4udGl0bGU8L3RpdGxlPg0KCTwvaGVhZD4NCi4uDQoJ\r\n"
            "PGJvZHk+DQoJCTxoMT4NCgkJCS4uSGVsbG8sIFdvcmxkZWVlZWUhDQoJCTwvaDE+DQoNCg0KLg0K\r\n"
            "DQoNCgkuPHA+QW55b25lIHRoZXJlPzwvcD4NCgk8L2JvZHk+DQo8L2h0bWw+\r\n"
            "\r\n"
            "--my_bound--\r\n");
    }
}


/**
Formatting multipart with a long content in various combinations.

The message has four parts: the first is long HTML ASCII charset Seven Bit encoded, the second is long text ASCII charset Base64 encoded, the third is long
text ASCII charset Quoted Printable encoded, the fourth is long text UTF-8 charset Quoted Printable encoded.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_long_multipart)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format long multipart");
    msg.content_type(message::media_type_t::MULTIPART, "related");
    msg.content_type().boundary("my_bound");

    mime m1;
    m1.content_type(message::media_type_t::TEXT, "html", "us-ascii");
    m1.content_transfer_encoding(mime::content_transfer_encoding_t::BIT_7);
    m1.content("<html><head></head><body><h1>Hello, World!</h1><p>Hello World!</p><p>Hello again!</p><p>Anyone there?</p><p>Yabba Dabba Doo!</p></body></html>");
    m1.line_policy(codec::line_len_policy_t::RECOMMENDED);

    mime m2;
    m2.line_policy(codec::line_len_policy_t::RECOMMENDED);
    m2.content_type(message::media_type_t::TEXT, "plain", "us-ascii");
    m2.content_transfer_encoding(mime::content_transfer_encoding_t::BASE_64);
    m2.content("This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n"
        "\r\n"
        "\r\n");

    mime m3;
    m3.content_type(message::media_type_t::TEXT, "plain", "us-ascii");
    m3.line_policy(codec::line_len_policy_t::RECOMMENDED);
    m3.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    m3.content("This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n"
        "\r\n"
        "\r\n");

    mime m4;
    m4.content_type(message::media_type_t::TEXT, "plain", "utf-8");
    m4.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    m4.content("This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n"
        "\r\n"
        "\r\n");
    m4.line_policy(codec::line_len_policy_t::RECOMMENDED);

    msg.add_part(m1);
    msg.add_part(m2);
    msg.add_part(m3);
    msg.add_part(m4);

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/related; boundary=\"my_bound\"\r\n"
        "Subject: format long multipart\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "\r\n"
        "<html><head></head><body><h1>Hello, World!</h1><p>Hello World!</p><p>Hello aga\r\n"
        "in!</p><p>Anyone there?</p><p>Yabba Dabba Doo!</p></body></html>\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "\r\n"
        "VGhpcyBpcyBhIHZlcnkgbG9uZyBtZXNzYWdlIHRoYXQgaGFzIGJsYW5rIGxpbmVzIGFuZCB2ZXJ5\r\n"
        "IGxvbmcgbGluZXMuIEl0IGlzIG5vdCBjbGVhciBob3cgdGhlIHRleHQgd2lsbCB3cmFwDQpzbyBJ\r\n"
        "IGhvcGUgdGhpcyB0ZXh0IHNob3dzIHRoYXQuDQoNCldlIHNob3VsZCBzZWUgaG93IGNvbW1vbiBt\r\n"
        "YWlsIGNsaWVudHMgd3JhcCB0ZXh0LCBhbmQgYmFzZWQgb24gdGhhdCBhZGp1c3QgbWVzc2FnZSBm\r\n"
        "b3JtYXR0aW5nLiBNYXliZSB0aGVyZSBpcyBubyBuZWVkLCBiZWNhdXNlIGxpYm1haWx4eCBpcyBu\r\n"
        "b3QgbWVhbnQgdG8NCmZvcm1hdCB0ZXh0Lg0KDQpJbiBhbnkgY2FzZSwgYWZ0ZXIgY2hlY2tpbmcg\r\n"
        "QVNDSUkgd2Ugc2hvdWxkIGFsc28gY2hlY2sgVVRGLTggY2hhcmFjdGVycyBhbmQgc2VlIGhvdyB3\r\n"
        "cmFwcGluZyBiZWhhdmVzIHdoZW4gY2hhcmFjdGVycyBhcmUgbXVsdGktYnl0ZS4gSXQgc2hvdWxk\r\n"
        "IG5vdCBtYXR0ZXIgd2hldGhlciB0aGUgZW5jb2RpbmcNCmlzIGJhc2U2NCBvciBxdW90ZWQgcHJp\r\n"
        "bnRhYmxlLCBiZWNhdXNlIEFTQ0lJIGNoYXJhY3RlcnMgd3JhcCBpbnRvIG5ldyBsaW5lcy4gVGhp\r\n"
        "cyB0ZXN0IHNob3VsZCBzaG93IHdoZXRoZXIgdGhlcmUgYXJlIGJ1Z3MgaW4gdGhlIGZvcm1hdHRp\r\n"
        "bmcgbG9naWMsDQphbmQgdGhlIHNhbWUgc2hvdWxkIGJlIGNoZWNrZWQgd2hlbiBwYXJzaW5nLg0K\r\n"
        "DQoNCg0KSGVyZSBpcyBhbHNvIGEgY2hlY2sgZm9yIGEgc2VxdWVuY2Ugb2YgYmxhbmsgbGluZXMu\r\n"
        "DQoNCg0K\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "This is a very long message that has blank lines and very long lines. It is =\r\n"
        "not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust m=\r\n"
        "essage formatting. Maybe there is no need, because libmailxx is not meant t=\r\n"
        "o\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and =\r\n"
        "see how wrapping behaves when characters are multi-byte. It should not matt=\r\n"
        "er whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines=\r\n"
        ". This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "This is a very long message that has blank lines and very long lines. It is =\r\n"
        "not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust m=\r\n"
        "essage formatting. Maybe there is no need, because libmailxx is not meant t=\r\n"
        "o\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and =\r\n"
        "see how wrapping behaves when characters are multi-byte. It should not matt=\r\n"
        "er whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines=\r\n"
        ". This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n"
        "\r\n"
        "--my_bound--\r\n");
}

BOOST_AUTO_TEST_CASE(format_parse_nested_multipart)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    msg.subject("format nested multipart");
    msg.content_type(message::media_type_t::MULTIPART, "related");
    msg.content_type().boundary("my_global_bound");
    msg.content("global content");

    mime m1;
    m1.content_type(message::media_type_t::MULTIPART, "related");
    m1.content_type().boundary("my_first_boundary");

    mime m11;
    m11.content_type(message::media_type_t::TEXT, "plain", "utf-8");
    m11.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    m11.content("mime part 1.1");

    mime m12;
    m12.content_type(message::media_type_t::TEXT, "plain", "us-ascii");
    m12.content_transfer_encoding(mime::content_transfer_encoding_t::BIT_8);
    m12.content("mime 1.2");

    mime m13;
    m13.content_type(message::media_type_t::TEXT, "plain", "us-ascii");
    m13.content_transfer_encoding(mime::content_transfer_encoding_t::BIT_7);
    m13.content("mime 1.3");

    m1.add_part(m11);
    m1.add_part(m12);
    m1.add_part(m13);

    mime m2;
    m2.content_type(message::media_type_t::MULTIPART, "related");
    m2.content_type().boundary("my_second_boundary");

    mime m21;
    m21.content_type(message::media_type_t::TEXT, "plain", "utf-8");
    m21.content_transfer_encoding(mime::content_transfer_encoding_t::BASE_64);
    m21.content("mime part 2.1");

    mime m22;
    m22.content_type(message::media_type_t::TEXT, "plain", "utf-8");
    m22.content_transfer_encoding(mime::content_transfer_encoding_t::BASE_64);
    m22.content("mime 2.2");

    m2.add_part(m21);
    m2.add_part(m22);

    msg.add_part(m1);
    msg.add_part(m2);
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    message msg_msg;
    BOOST_REQUIRE(msg_msg.parse(msg_str));
    string msg_msg_str;
    BOOST_REQUIRE(msg_msg.format(msg_msg_str));
    BOOST_CHECK(msg_str == msg_msg_str);
}


/**
Formatting multipart message with both content and parts.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_multipart_content)
{
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("format multipart content");
    BOOST_REQUIRE(msg.content_id("zero@mailxx.dev"));
    msg.content_type(message::media_type_t::MULTIPART, "related");
    msg.content_type().boundary("my_bound");
    msg.content("This is a multipart message.");

    mime m1;
    m1.content_type(message::media_type_t::TEXT, "html", "us-ascii");
    m1.content_transfer_encoding(mime::content_transfer_encoding_t::BIT_7);
    m1.content("<html><head></head><body><h1>Hello, World!</h1></body></html>");
    BOOST_REQUIRE(m1.content_id("first@mailxx.dev"));

    mime m2;
    m2.content_type(message::media_type_t::TEXT, "plain", "us-ascii");
    m2.content_transfer_encoding(mime::content_transfer_encoding_t::BIT_7);
    m2.content("Hello, World!");
    BOOST_REQUIRE(m2.content_id("second@mailxx.dev"));

    msg.add_part(m1);
    msg.add_part(m2);
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/related; boundary=\"my_bound\"\r\n"
        "Content-ID: <zero@mailxx.dev>\r\n"
        "Subject: format multipart content\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "This is a multipart message.\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "Content-ID: <first@mailxx.dev>\r\n"
        "\r\n"
        "<html><head></head><body><h1>Hello, World!</h1></body></html>\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "Content-ID: <second@mailxx.dev>\r\n"
        "\r\n"
        "Hello, World!\r\n"
        "\r\n"
        "--my_bound--\r\n");
}


/**
Attaching two files to a message.

@pre  Files `cv.txt` and `aleph0.png` in the current directory.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_attachment)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("format attachment");
    ifstream ifs1("cv.txt");
    message::content_type_t ct1{message::media_type_t::APPLICATION, "txt"};
    auto tp1 = make_tuple(std::ref(ifs1), "SylvainGuinebert_CV.txt", ct1);
    ifstream ifs2("aleph0.png", std::ios_base::binary);
    message::content_type_t ct2(message::media_type_t::IMAGE, "png");
    auto tp2 = make_tuple(std::ref(ifs2), "logo.png", ct2);
    list<tuple<std::istream&, string_t, message::content_type_t>> atts;
    atts.push_back(tp1);
    atts.push_back(tp2);
    BOOST_REQUIRE(msg.attach(atts));

    BOOST_CHECK(msg.content_type().media_type() == mime::media_type_t::MULTIPART && msg.content_type().media_subtype() == "mixed" && msg.attachments_size() == 2);
    BOOST_CHECK(msg.parts().at(0).content_type().media_type() == mime::media_type_t::APPLICATION && msg.parts().at(0).content_type().media_subtype() == "txt" &&
        msg.parts().at(0).content_transfer_encoding() == mime::content_transfer_encoding_t::BASE_64 && msg.parts().at(0).content_disposition() ==
        mime::content_disposition_t::ATTACHMENT);
    BOOST_CHECK(msg.parts().at(1).content_type().media_type() == mime::media_type_t::IMAGE && msg.parts().at(1).content_type().media_subtype() == "png" &&
        msg.parts().at(1).content_transfer_encoding() == mime::content_transfer_encoding_t::BASE_64 && msg.parts().at(1).content_disposition() ==
        mime::content_disposition_t::ATTACHMENT);
}


/**
Attaching a file with UTF-8 name in the base64 attribute codec.

@pre  File `cv.txt` in the current directory.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_utf8_attachment_b64)
{
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.date_time(ldt);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("format utf8 attachment base64");
    msg.content_type().boundary("mybnd");

    std::ifstream ifs("cv.txt");
    message::content_type_t ct(message::media_type_t::TEXT, "plain");
    auto tp = make_tuple(std::ref(ifs), string_t("SylvainGuinebert_CV.txt", "UTF-8", codec::codec_t::BASE64), ct);
    list<tuple<std::istream&, string_t, message::content_type_t>> atts;
    atts.push_back(tp);
    BOOST_REQUIRE(msg.attach(atts));

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"mybnd\"\r\n"
        "Subject: format utf8 attachment base64\r\n"
        "\r\n"
        "--mybnd\r\n"
        "Content-Type: text/plain; \r\n"
        "  name=\"=?UTF-8?B?VG9taXNsYXZLYXJhc3RvamtvdmljX0NWLnR4dA==?=\"\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename=\"=?UTF-8?B?VG9taXNsYXZLYXJhc3RvamtvdmljX0NWLnR4dA==?=\"\r\n"
        "\r\n"
        "SGVsbG8gV29ybGQgQ1YK\r\n"
        "\r\n"
        "--mybnd--\r\n");
}


/**
Attaching a file with UTF-8 name in the quoted printable attribute codec.

@pre  File `cv.txt` in the current directory.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_utf8_attachment_qp)
{
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.date_time(ldt);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("format utf8 attachment quoted printable");
    msg.content_type().boundary("mybnd");

    std::ifstream ifs("cv.txt");
    message::content_type_t ct(message::media_type_t::TEXT, "plain");
    auto tp = make_tuple(std::ref(ifs), string_t("SylvainGuinebert_CV.txt", "UTF-8", codec::codec_t::QUOTED_PRINTABLE), ct);
    list<tuple<std::istream&, string_t, message::content_type_t>> atts;
    atts.push_back(tp);
    BOOST_REQUIRE(msg.attach(atts));

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"mybnd\"\r\n"
        "Subject: format utf8 attachment quoted printable\r\n"
        "\r\n"
        "--mybnd\r\n"
        "Content-Type: text/plain; \r\n"
        "  name=\"=?UTF-8?Q?SylvainGuinebert_CV.txt?=\"\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename=\"=?UTF-8?Q?SylvainGuinebert_CV.txt?=\"\r\n"
        "\r\n"
        "SGVsbG8gV29ybGQgQ1YK\r\n"
        "\r\n"
        "--mybnd--\r\n");
}


/**
Attaching a file with long UTF-8 message content.

@pre  File `cv.txt` in the current directory.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_msg_att)
{
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("format message attachment");
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.content_type(message::media_type_t::TEXT, "plain", "utf-8");
    msg.content_type().boundary("mybnd");
    msg.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    msg.content("This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n"
        "\r\n"
        "\r\n");
    std::ifstream ifs("cv.txt");
    message::content_type_t ct(message::media_type_t::TEXT, "plain");
    auto tp = make_tuple(std::ref(ifs), "SylvainGuinebert_CV.txt", ct);
    list<tuple<std::istream&, string_t, message::content_type_t>> atts;
    atts.push_back(tp);
    BOOST_REQUIRE(msg.attach(atts));

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"mybnd\"\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "Subject: format message attachment\r\n"
        "\r\n"
        "--mybnd\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "This is a very long message that has blank lines and very long lines. It is =\r\n"
        "not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust m=\r\n"
        "essage formatting. Maybe there is no need, because libmailxx is not meant t=\r\n"
        "o\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and =\r\n"
        "see how wrapping behaves when characters are multi-byte. It should not matt=\r\n"
        "er whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines=\r\n"
        ". This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n"
        "\r\n"
        "--mybnd\r\n"
        "Content-Type: text/plain; \r\n"
        "  name=\"SylvainGuinebert_CV.txt\"\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename=\"SylvainGuinebert_CV.txt\"\r\n"
        "\r\n"
        "SGVsbG8gV29ybGQgQ1YK\r\n"
        "\r\n"
        "--mybnd--\r\n");
}

BOOST_AUTO_TEST_CASE(format_html_att)
{
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("format html attachment");
    msg.content_type(message::media_type_t::TEXT, "html", "utf-8");
    msg.content_type().boundary("mybnd");
    msg.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    msg.content("<h1>Title</h1><p>This is a message.</p>");

    ifstream ifs1("cv.txt");
    list<tuple<std::istream&, string_t, message::content_type_t>> atts;
    message::content_type_t ct(message::media_type_t::TEXT, "plain");
    auto tp = make_tuple(std::ref(ifs1), "SylvainGuinebert_CV.txt", ct);
    atts.push_back(tp);
    BOOST_REQUIRE(msg.attach(atts));
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg.parts().size() == 2);
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"mybnd\"\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "Subject: format html attachment\r\n"
        "\r\n"
        "--mybnd\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "<h1>Title</h1><p>This is a message.</p>\r\n"
        "\r\n"
        "--mybnd\r\n"
        "Content-Type: text/plain; \r\n"
        "  name=\"SylvainGuinebert_CV.txt\"\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename=\"SylvainGuinebert_CV.txt\"\r\n"
        "\r\n"
        "SGVsbG8gV29ybGQgQ1YK\r\n"
        "\r\n"
        "--mybnd--\r\n");
}


/**
Formatting a message without content type.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_mime_no_content_type)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("mime no content type");
    msg.content_type().boundary("my_bound");

    mime m1;
    m1.content_type(message::media_type_t::TEXT, "html", "us-ascii");
    m1.content_transfer_encoding(mime::content_transfer_encoding_t::BIT_7);
    m1.content("<html><head></head><body><h1>Hello, World!</h1></body></html>");

    mime m2;
    m2.content_type(message::media_type_t::TEXT, "plain", "us-ascii");
    m2.content_transfer_encoding(mime::content_transfer_encoding_t::BIT_7);
    m2.content("Hello, World!");

    msg.add_part(m1);
    msg.add_part(m2);
    string msg_str;
    BOOST_CHECK(!msg.format(msg_str));
}


/**
Formatting a message with the disposition notification.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_notification)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.disposition_notification(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.subject("format notification", codec::codec_t::BASE64);
    msg.content("Hello, World!");
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Disposition-Notification-To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?ASCII?B?Zm9ybWF0IG5vdGlmaWNhdGlvbg==?=\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting a message with UTF-8 addresses by using Base64 Q codec.

@pre  None.
@post None.
@todo The last line of the from header has the empty base64 name part.
**/
BOOST_AUTO_TEST_CASE(format_qb_sender)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.sender(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_from(mail_address(string_t("mailio library for working with emails in the C plus plus language", codec::CHARSET_UTF8, codec::codec_t::BASE64),
        "address@mailxx.dev"));
    msg.add_from(mail_address(string_t("Sylvain Guinebert", codec::CHARSET_UTF8, codec::codec_t::BASE64), "the_library@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx library for working with emails in the C plus plus language "
        "version 2017 but also compatible with C plus plus 2020 and 2023", "address@mailxx.dev"));
    msg.add_recipient(mail_address(string_t("Sylvain Guinebert", codec::CHARSET_UTF8, codec::codec_t::BASE64), "qwerty@gmail.com"));
    msg.add_recipient(mail_address(string_t("Sylvain Guinebert", codec::CHARSET_UTF8, codec::codec_t::BASE64), "asdfg@zoho.com"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.subject("format q base64 sender", codec::codec_t::BASE64);
    msg.content("test");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: =?UTF-8?B?bWFpbGlvIGxpYnJhcnkgZm9yIHdvcmtpbmcgd2l0aCBlbWFpbHMgaW4gdGhl?=\r\n"
        "  =?UTF-8?B?IEMgcGx1cyBwbHVzIGxhbmd1YWdl?= <address@mailxx.dev>,\r\n"
        "  =?UTF-8?B?VG9taXNsYXYgS2FyYXN0b2prb3ZpYw==?= <the_library@mailxx.dev>\r\n"
        "Sender: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx library for working with emails in the C plus plus language \r\n"
        "  version 2017 but also compatible with C plus plus 2020 and 2023\r\n"
        "  <address@mailxx.dev>,\r\n"
        "  =?UTF-8?B?VG9taXNsYXYgS2FyYXN0b2prb3ZpYw==?= <qwerty@gmail.com>,\r\n"
        "  =?UTF-8?B?VG9taXNsYXYgS2FyYXN0b2prb3ZpYw==?= <asdfg@zoho.com>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?ASCII?B?Zm9ybWF0IHEgYmFzZTY0IHNlbmRlcg==?=\r\n"
        "\r\n"
        "test\r\n");
}


/**
Formatting a message with UTF-8 addresses by using Quoted Printable Q codec.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_qq_sender)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address(string_t("mailio library for working with emails in the C plus plus language", codec::CHARSET_UTF8, codec::codec_t::QUOTED_PRINTABLE),
        "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx library for working with emails in the C plus plus language "
        "version 2017 but also compatible with C plus plus 2020 and 2023", "address@mailxx.dev"));
    msg.add_recipient(mail_address(string_t("Sylvain Guinebert", codec::CHARSET_UTF8, codec::codec_t::QUOTED_PRINTABLE), "qwerty@gmail.com"));
    msg.add_recipient(mail_address(string_t("Sylvain Guinebert", codec::CHARSET_UTF8, codec::codec_t::QUOTED_PRINTABLE), "asdfg@zoho.com"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.subject("format q quoted printable sender", codec::codec_t::QUOTED_PRINTABLE);
    msg.content("test");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: =?UTF-8?Q?mailio_library_for_working_with_emails_in_the_C_plus_plus_l?=\r\n"
        "  =?UTF-8?Q?anguage?= <address@mailxx.dev>\r\n"
        "To: mailxx library for working with emails in the C plus plus language \r\n"
        "  version 2017 but also compatible with C plus plus 2020 and 2023\r\n"
        "  <address@mailxx.dev>,\r\n"
        "  =?UTF-8?Q?Sylvain_Guinebert?= <qwerty@gmail.com>,\r\n"
        "  =?UTF-8?Q?Sylvain_Guinebert?= <asdfg@zoho.com>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?ASCII?Q?format_q_quoted_printable_sender?=\r\n"
        "\r\n"
        "test\r\n");
}


/**
Formatting a message with UTF-8 subject by using Base64 Q codec.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_qb_long_subject)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.subject_raw(string_t("Re: Hello, World! Request from Example Visitor - Sample Apartments", "utf-8", codec::codec_t::BASE64));
    msg.content("Hello, World!");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?UTF-8?B?UmU6IEhlbGxvLCBXb3JsZCEgUmVxdWVzdCBmcm9tIEV4YW1wbGUgVmlz?=\r\n"
        "  =?UTF-8?B?aXRvciAtIFNhbXBsZSBBcGFydG1lbnRz?=\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting a message with UTF-8 subject by using Quoted Printable Q codec.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_qq_long_subject)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.subject_raw(string_t("Re: Hello, World! Request from Example Visitor - Sample Apartments", "utf-8", codec::codec_t::QUOTED_PRINTABLE));
    msg.content("Hello, World!");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?UTF-8?Q?Re:_Hello,_World!_Request_from_Example_Visitor_-_Sample?=\r\n"
        "  =?UTF-8?Q?_Apartments?=\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting a message with UTF-8 subject containing the long dash character.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_qq_subject_dash)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
#if defined(__cpp_char8_t)
    msg.subject_raw(u8string_t(u8"C++ Annotated: Sep - Dec 2017", "utf-8", codec::codec_t::QUOTED_PRINTABLE));
#else
    msg.subject_raw(string_t(u8"C++ Annotated: Sep - Dec 2017", "utf-8", codec::codec_t::QUOTED_PRINTABLE));
#endif
    msg.content("test");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?UTF-8?Q?C++_Annotated:_Sep_-_Dec_2017?=\r\n"
        "\r\n"
        "test\r\n");
}


/**
Formatting a message with UTF-8 subject containing an emoji character.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_qq_subject_emoji)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
#if defined(__cpp_char8_t)
    msg.subject_raw(u8string_t(u8"Hello, World! One Year on Super Card", "utf-8", codec::codec_t::QUOTED_PRINTABLE));
#else
    msg.subject_raw(string_t(u8"Hello, World! One Year on Super Card", "utf-8", codec::codec_t::QUOTED_PRINTABLE));
#endif
    msg.content("test");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?UTF-8?Q?Hello,_World!_One_Year_on_Super_Card?=\r\n"
        "\r\n"
        "test\r\n");
}


/**
Attaching a file with the long ASCII name to show the attribute continuation with the default seven bit codec.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_continued_ascii_attachment_bit7)
{
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.strict_mode(false);
    // The default attribute codec is seven bit.
    msg.content_type().boundary("mybnd");
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.subject("format continued filename format continued filename format continued filename format continued filename");
    ifstream ifs1("cv.txt");
    message::content_type_t ct1(message::media_type_t::APPLICATION, "txt");
    auto tp1 = make_tuple(std::ref(ifs1), "C:\\Program Files\\AlephoLtd\\Email\\Libraries\\mailxx\\SylvainGuinebertResumeCurriculumVitae.txt", ct1);
    list<tuple<std::istream&, string_t, message::content_type_t>> atts;
    atts.push_back(tp1);
    BOOST_REQUIRE(msg.attach(atts));
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    // When the escape characters are removed from the long lines, they actually fit to the line policy, so everything is fine,
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"mybnd\"\r\n"
        "Subject: format continued filename format continued filename format continued \r\n"
        "  filename format continued filename\r\n"
        "\r\n"
        "--mybnd\r\n"
        "Content-Type: application/txt; \r\n"
        "  name*0=\"C:\\Program \"; \r\n"
        "  name*1=\"Files\\AlephoLtd\\Email\\Libraries\\mailxx\\SylvainGuinebertResume\"; \r\n"
        "  name*2=\"CurriculumVitae.txt\"\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename*0=\"C:\\Program \"; \r\n"
        "  filename*1=\"Files\\AlephoLtd\\Email\\Libraries\\mailxx\\SylvainGuinebertRe\"; \r\n"
        "  filename*2=\"sumeCurriculumVitae.txt\"\r\n"
        "\r\n"
        "SGVsbG8gV29ybGQgQ1YK\r\n"
        "\r\n"
        "--mybnd--\r\n"
   );
}



/**
Attaching a file with the long UTF-8 name to show the attribute continuation with the base64 codec.

@pre  File `cv.txt` in the current directory.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_continued_utf8_attachment_b64)
{
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("format long utf8 attachment base64");
    msg.content_type().boundary("mybnd");

    std::ifstream ifs("cv.txt");
    message::content_type_t ct(message::media_type_t::TEXT, "plain");
    auto tp = make_tuple(std::ref(ifs), string_t("Very_Long_File_Name_Sylvain_Guinebert_CV.txt", "UTF-8", codec::codec_t::BASE64), ct);
    list<tuple<std::istream&, string_t, message::content_type_t>> atts;
    atts.push_back(tp);
    BOOST_REQUIRE(msg.attach(atts));

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"mybnd\"\r\n"
        "Subject: format long utf8 attachment base64\r\n"
        "\r\n"
        "--mybnd\r\n"
        "Content-Type: text/plain; \r\n"
        "  name*0=\"=?UTF-8?B?VmVyeV9Mb25nX0ZpbGVfTmFtZV9Ub21pc2xhdl9LYXJhc3Rv?=\"; \r\n"
        "  name*1=\"=?UTF-8?B?amtvdmljX0NWLnR4dA==?=\"\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename*0=\"=?UTF-8?B?VmVyeV9Mb25nX0ZpbGVfTmFtZV9Ub21pc2xhdl9LYXJh?=\"; \r\n"
        "  filename*1=\"=?UTF-8?B?c3RvamtvdmljX0NWLnR4dA==?=\"\r\n"
        "\r\n"
        "SGVsbG8gV29ybGQgQ1YK\r\n"
        "\r\n"
        "--mybnd--\r\n");
}


/**
Attaching a file with the long UTF-8 name to show the attribute continuation with the quoted printable codec.

@pre  File `cv.txt` in the current directory.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_continued_utf8_attachment_qp)
{
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("format long utf8 attachment quoted printable");
    msg.content_type().boundary("mybnd");

    std::ifstream ifs("cv.txt");
    message::content_type_t ct(message::media_type_t::TEXT, "plain");
    auto tp = make_tuple(std::ref(ifs), string_t("Very_Long_File_Name_Sylvain_Guinebert_CV.txt", "UTF-8", codec::codec_t::QUOTED_PRINTABLE), ct);
    list<tuple<std::istream&, string_t, message::content_type_t>> atts;
    atts.push_back(tp);
    BOOST_REQUIRE(msg.attach(atts));

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"mybnd\"\r\n"
        "Subject: format long utf8 attachment quoted printable\r\n"
        "\r\n"
        "--mybnd\r\n"
        "Content-Type: text/plain; \r\n"
        "  name*0=\"=?UTF-8?Q?Very_Long_File_Name_Sylvain_Guinebert_CV.t?=\"; \r\n"
        "  name*1=\"=?UTF-8?Q?xt?=\"\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename*0=\"=?UTF-8?Q?Very_Long_File_Name_Sylvain_Guinebert_?=\"; \r\n"
        "  filename*1=\"=?UTF-8?Q?CV.txt?=\"\r\n"
        "\r\n"
        "SGVsbG8gV29ybGQgQ1YK\r\n"
        "\r\n"
        "--mybnd--\r\n");
}


/**
Attaching a file with the long UTF-8 name to show the attribute continuation with the percent codec.

@pre  File `cv.txt` in the current directory.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_continued_utf8_attachment_pct)
{
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("format long utf8 attachment percentage");
    msg.content_type().boundary("mybnd");

    std::ifstream ifs("cv.txt");
    message::content_type_t ct(message::media_type_t::TEXT, "plain");
    auto tp = make_tuple(std::ref(ifs), string_t("Very_Long_File_Name_Sylvain_Guinebert_CV.txt", "UTF-8", codec::codec_t::PERCENT), ct);
    list<tuple<std::istream&, string_t, message::content_type_t>> atts;
    atts.push_back(tp);
    BOOST_REQUIRE(msg.attach(atts));

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"mybnd\"\r\n"
        "Subject: format long utf8 attachment percentage\r\n"
        "\r\n"
        "--mybnd\r\n"
        "Content-Type: text/plain; \r\n"
        "  name*0*=UTF-8''Very%5FLong%5FFile%5FName%5FSylvain%5FGuinebert%5FCV%2E; \r\n"
        "  name*1*=txt\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename*0*=UTF-8''Very%5FLong%5FFile%5FName%5FSylvain%5FGuinebert%5F; \r\n"
        "  filename*1*=CV%2Etxt\r\n"
        "\r\n"
        "SGVsbG8gV29ybGQgQ1YK\r\n"
        "\r\n"
        "--mybnd--\r\n");
}


/**
Formatting UTF8 subject in 8bit encoding.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_utf8_subject)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.from(mail_address(string_t("Sylvain Guinebert", codec::CHARSET_UTF8, codec::codec_t::UTF8), "qwerty@hotmail.com"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("Hello, World!");
    msg.content("Hello, World!");
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: Sylvain Guinebert <qwerty@hotmail.com>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Hello, World!\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting ISO 8859-1 subject in combination with the UTF8 header.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_iso8859_subject_utf8_header)
{
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.from(mail_address(string_t("Hello World CV", "ISO-8859-1", codec::codec_t::UTF8), "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject_raw(string_t("Hello World CV", "ISO-8859-1"));
    msg.content("Hello, World!");
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: Hello World CV <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Hello World CV\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting a message with UTF-8 raw subject by using Base64 Q codec.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_qb_utf8_subject_raw)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.subject_raw(string_t("Re: Hello, World! Request from Example Visitor - Sample Apartments", "utf-8", codec::codec_t::BASE64));
    msg.content("Hello, World!");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?UTF-8?B?UmU6IEhlbGxvLCBXb3JsZCEgUmVxdWVzdCBmcm9tIEV4YW1wbGUgVmlz?=\r\n"
        "  =?UTF-8?B?aXRvciAtIFNhbXBsZSBBcGFydG1lbnRz?=\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting a message with several codecs in the header.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_many_codecs)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address(string_t("mailio", "UTF-8", codec::codec_t::QUOTED_PRINTABLE), "address@mailxx.dev"));
    msg.add_recipient(mail_address(string_t("Sylvain Guinebert", codec::CHARSET_UTF8, codec::codec_t::BASE64), "qwerty@gmail.com"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.subject_raw(string_t("Re: Hello, World! Request from Example Visitor - Sample Apartments", "utf-8", codec::codec_t::BASE64));
    msg.content("Hello, World!");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: =?UTF-8?Q?mailio?= <address@mailxx.dev>,\r\n"
        "  =?UTF-8?B?VG9taXNsYXYgS2FyYXN0b2prb3ZpYw==?= <qwerty@gmail.com>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?UTF-8?B?UmU6IEhlbGxvLCBXb3JsZCEgUmVxdWVzdCBmcm9tIEV4YW1wbGUgVmlz?=\r\n"
        "  =?UTF-8?B?aXRvciAtIFNhbXBsZSBBcGFydG1lbnRz?=\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting a message with the message ID in the strict mode.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_message_id)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.strict_mode(true);
    msg.date_time(ldt);
    msg.subject("format message id", codec::codec_t::QUOTED_PRINTABLE);
    msg.content("Hello, World!");
    BOOST_REQUIRE(msg.message_id("1234567890@mailxx.dev"));
    BOOST_REQUIRE(msg.content_id("987654321@mailxx.dev"));

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Message-ID: <1234567890@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Content-ID: <987654321@mailxx.dev>\r\n"
        "Subject: =?ASCII?Q?format_message_id?=\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting long nessage and content IDs.

Showing the bug of not applying the line policy for the message ID.

@pre  None.
@post None.
@todo Change the criteria once the bug is fixed.
**/
BOOST_AUTO_TEST_CASE(format_long_message_id)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.strict_mode(true);
    msg.date_time(ldt);
    msg.subject("format long message id", codec::codec_t::QUOTED_PRINTABLE);
    msg.content("Hello, World!");
    BOOST_REQUIRE(msg.message_id("1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890@mailxx.dev"));
    BOOST_REQUIRE(msg.content_id("987654321987654321987654321987654321987654321987654321987654321987654321987654321@mailxx.dev"));

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Message-ID: <12345678901234567890123456789012345678901234567890123456789012345\r\n"
        "  67890123456789012345678901234567890@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Content-ID: <98765432198765432198765432198765432198765432198765432198765432198\r\n"
        "  7654321987654321@mailxx.dev>\r\n"
        "Subject: =?ASCII?Q?format_long_message_id?=\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting the message ID without the monkey character in the strict mode.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_message_id_no_monkey_strict)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.strict_mode(true);
    msg.date_time(ldt);
    msg.subject("Test");
    msg.content("Hello, World!");
    BOOST_CHECK(!msg.message_id("1234567890mailxx.dev"));
}


/**
Formatting the message ID without the monkey character in the non-strict mode.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_message_id_no_monkey_non_strict)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.subject("format message id no monkey non strict", codec::codec_t::QUOTED_PRINTABLE);
    msg.content("Hello, World!");
    BOOST_REQUIRE(msg.message_id("1234567890mailxx.dev"));
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Message-ID: <1234567890mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?ASCII?Q?format_message_id_no_monkey_non_strict?=\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting the message ID with the space character in the strict mode.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_message_id_with_space_strict)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.strict_mode(true);
    msg.date_time(ldt);
    msg.subject("Test");
    msg.content("Hello, World!");
    BOOST_CHECK(!msg.message_id("1234567890@ mailxx.dev"));
}


/**
Formatting the message ID with the space character in the non-strict mode.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_message_id_with_space_non_strict)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.subject("format message id with space non strict", codec::codec_t::QUOTED_PRINTABLE);
    msg.content("Hello, World!");
    BOOST_REQUIRE(msg.message_id("1234567890@ mailxx.dev"));
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Message-ID: <1234567890@ mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?ASCII?Q?format_message_id_with_space_non_strict?=\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting a message with the in-reply-to and references IDs.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_in_reply_to)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.subject("format in reply to", codec::codec_t::QUOTED_PRINTABLE);
    msg.content("Hello, World!");
    BOOST_REQUIRE(msg.add_in_reply_to("1@mailxx.dev"));
    BOOST_REQUIRE(msg.add_in_reply_to("22@mailxx.dev"));
    BOOST_REQUIRE(msg.add_in_reply_to("333@mailxx.dev"));
    BOOST_REQUIRE(msg.add_references("4444@mailxx.dev"));
    BOOST_REQUIRE(msg.add_references("55555@mailxx.dev"));
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "In-Reply-To: <1@mailxx.dev> <22@mailxx.dev> <333@mailxx.dev>\r\n"
        "References: <4444@mailxx.dev> <55555@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?ASCII?Q?format_in_reply_to?=\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/*
Formatting long message IDs.

@pre  None.
@post None.
*/
BOOST_AUTO_TEST_CASE(format_in_reply_to_folding)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.subject("format in reply to folding", codec::codec_t::QUOTED_PRINTABLE);
    msg.content("Hello, World!");
    BOOST_REQUIRE(msg.add_in_reply_to("1@mailxx.dev"));
    BOOST_REQUIRE(msg.add_in_reply_to("22@mailxx.dev"));
    BOOST_REQUIRE(msg.add_in_reply_to("333@mailxx.dev"));
    BOOST_REQUIRE(msg.add_in_reply_to("44444444444444444444444444@mailxx.dev"));
    BOOST_REQUIRE(msg.add_in_reply_to("5555555555555555@mailxx.dev"));
    BOOST_REQUIRE(msg.add_in_reply_to("66666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666@mailxx.dev"));
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "In-Reply-To: <1@mailxx.dev> <22@mailxx.dev> <333@mailxx.dev> \r\n"
        "  <44444444444444444444444444@mailxx.dev> <5555555555555555@mailxx.dev> \r\n"
        "  <66666666666666666666666666666666666666666666666666666666666666666666666666666\r\n"
        "  666666666666666666666666666666@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?ASCII?Q?format_in_reply_to_folding?=\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting oversized recipient with the recommended line policy.

@pre  None.
@post None.
@todo Shows the bug with no delimiter between the name and the address.
**/
BOOST_AUTO_TEST_CASE(format_recommended_recipient)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address(string_t("mailio", codec::CHARSET_UTF8, codec::codec_t::BASE64), "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address(string_t("Sylvain Guinebert", codec::CHARSET_UTF8, codec::codec_t::BASE64), "qwerty@gmail.com"));
    msg.add_recipient(mail_address(string_t("Sylvain Guinebert", codec::CHARSET_UTF8, codec::codec_t::BASE64), "asdfg@zoho.com"));
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.subject("format recommended recipient", codec::codec_t::BASE64);
    msg.content("test");

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: =?UTF-8?B?bWFpbGlv?= <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>,\r\n"
        "  =?UTF-8?B?VG9taXNsYXYgS2FyYXN0b2prb3ZpYw==?= <qwerty@gmail.com>,\r\n"
        "  =?UTF-8?B?VG9taXNsYXYgS2FyYXN0b2prb3ZpYw==?= <asdfg@zoho.com>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?ASCII?B?Zm9ybWF0IHJlY29tbWVuZGVkIHJlY2lwaWVudA==?=\r\n"
        "\r\n"
        "test\r\n");
}


/*
Formatting long subject when there is a delimiter and when there is not.

@pre  None.
@post None.
*/
BOOST_AUTO_TEST_CASE(format_long_subject)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.from(mail_address(string_t("Sylvain Guinebert", codec::CHARSET_UTF8, codec::codec_t::UTF8), "qwerty@hotmail.com"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!"
        "Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!");
    msg.content("Hello, World!");
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: Sylvain Guinebert <qwerty@hotmail.com>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!Hello,\r\n"
        "  World!Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!Hello,\r\n"
        "  World!Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!Hello,World!\r\n"
        "\r\n"
        "Hello, World!\r\n");

    msg.subject("HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!Hello World!HelloWorld!HelloWorld!");
    msg_str.clear();
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "From: Sylvain Guinebert <qwerty@hotmail.com>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!Hel\r\n"
        "  lo World!HelloWorld!HelloWorld!\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Formatting a message with a long header to be folded.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_long_header)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "contact@mailxx.dev"));
    msg.add_recipient(mail_address("contact", "contact@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_group("all", {mail_address("Sylvain", "qwerty@hotmail.com")}));
    msg.subject("Hello, World!");
    msg.content("Hello, World!");
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg.date_time(ldt);
    BOOST_REQUIRE(msg.add_header("Test", "12345678901234567890 1234567890123456789012345678901234567890123456789012345678901234567890 12345678901234567890@mailxx.dev"));
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "Test: 12345678901234567890 \r\n"
        "  1234567890123456789012345678901234567890123456789012345678901234567890 \r\n"
        "  12345678901234567890@mailxx.dev\r\n"
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <contact@mailxx.dev>\r\n"
        "To: contact <contact@mailxx.dev>,\r\n"
        "  mailxx <address@mailxx.dev>,\r\n"
        "  all: Sylvain <qwerty@hotmail.com>;\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: Hello, World!\r\n"
        "\r\n"
        "Hello, World!\r\n");

    msg.remove_header("Test");
    BOOST_REQUIRE(msg.add_header("Test", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890 12345678901234567890@mailxx.dev"));
    msg_str.clear();
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str == "Test: 12345678901234567890123456789012345678901234567890123456789012345678901\r\n"
        "  2345678901234567890 12345678901234567890@mailxx.dev\r\n"
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <contact@mailxx.dev>\r\n"
        "To: contact <contact@mailxx.dev>,\r\n"
        "  mailxx <address@mailxx.dev>,\r\n"
        "  all: Sylvain <qwerty@hotmail.com>;\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: Hello, World!\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Showing a bug with the line folding for the long sender header.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(format_long_from)
{
    {
        message msg;
        msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
        auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
        msg.date_time(ldt);
        msg.from(mail_address(string_t("Sylvain      Guinebert", codec::CHARSET_UTF8, codec::codec_t::BASE64), "SylvainGuinebert@hotmail.com"));
        msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
        msg.subject("Hello,World!", codec::codec_t::BASE64);
        msg.content("Hello, World!");
        string msg_str;
        BOOST_REQUIRE(msg.format(msg_str));
        BOOST_CHECK(msg_str ==
            "From: =?UTF-8?B?VG9taXNsYXYgICAgICBLYXJhc3Rvamtvdmlj?= <SylvainGuinebert@hotmail.com>\r\n"
            "To: mailxx <address@mailxx.dev>\r\n"
            "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
            "Subject: =?ASCII?B?SGVsbG8sV29ybGQh?=\r\n"
            "\r\n"
            "Hello, World!\r\n");
    }
    {
        message msg;
        msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
        auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
        msg.date_time(ldt);
        msg.from(mail_address(string_t("Hello,World! Hello,World! Hello,World! Hello,World! Hello,World! Hello,World!"), "helloworld@hotmail.com"));
        msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
        msg.subject("Hello,World!", codec::codec_t::BASE64);
        msg.content("Hello, World!");
        string msg_str;
        BOOST_REQUIRE(msg.format(msg_str));
        BOOST_CHECK(msg_str ==
            "From: \"Hello,World! Hello,World! Hello,World! Hello,World! Hello,World! Hello,\r\n"
            "  World!\" <helloworld@hotmail.com>\r\n"
            "To: mailxx <address@mailxx.dev>\r\n"
            "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
            "Subject: =?ASCII?B?SGVsbG8sV29ybGQh?=\r\n"
            "\r\n"
           "Hello, World!\r\n");
    }
    {
        message msg;
        msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
        auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
        msg.date_time(ldt);
        msg.from(mail_address(string_t("HelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHello"), "helloworld@hotmail.com"));
        msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
        msg.subject("Hello,World!", codec::codec_t::BASE64);
        msg.content("Hello, World!");
        string msg_str;
        BOOST_REQUIRE(msg.format(msg_str));
        BOOST_CHECK(msg_str ==
            "From: HelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHe\r\n"
            "  llo <helloworld@hotmail.com>\r\n"
            "To: mailxx <address@mailxx.dev>\r\n"
            "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
            "Subject: =?ASCII?B?SGVsbG8sV29ybGQh?=\r\n"
            "\r\n"
            "Hello, World!\r\n");
    }
}


/**
Formatting content type attributes.

@pre  None.
@post None.
@todo Bug that shows that the content type is not formatted according to the line policy.
**/
BOOST_AUTO_TEST_CASE(format_content_type_attributes)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.from(mail_address(string_t("mailxx", codec::CHARSET_UTF8, codec::codec_t::UTF8), "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    message::attributes_t attrs;
    attrs["method"] = "request";
    attrs["format"] = "flowed";
    attrs["name"] = "PersoalBoardingCard.pdf";
    msg.content_type(message::media_type_t::TEXT, "calendar", attrs, "utf-8");

    msg.subject("Hello,World!");
    msg.content("Hello, World!");
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    BOOST_CHECK(msg_str ==
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Content-Type: text/calendar; charset=utf-8; format=flowed; method=request; name=PersoalBoardingCard.pdf\r\n"
        "Subject: Hello,World!\r\n"
        "\r\n"
        "Hello, World!\r\n");
}


/**
Parsing simple message.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_simple)
{
    string msg_str = "From: mail io <adre.sa@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: parse simple\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "\r\n"
        "hello\r\n"
        "\r\n"
        "world\r\n"
        "\r\n"
        "\r\n"
        "hello again\r\n";
    message msg;

    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    BOOST_REQUIRE(msg.parse(msg_str));
    auto recipients_res = msg.recipients_to_string();
    BOOST_REQUIRE(recipients_res);
    BOOST_CHECK(msg.from().addresses.at(0).name == "mail io" &&
        msg.from().addresses.at(0).name.charset == "ASCII" &&
        msg.from().addresses.at(0).name.codec_type == codec::codec_t::ASCII &&
        msg.from().addresses.at(0).address == "adre.sa@mailxx.dev" &&
        msg.date_time() == ldt &&
        msg.recipients().addresses.at(0).name.charset == "ASCII" &&
        msg.recipients().addresses.at(0).name.codec_type == codec::codec_t::ASCII &&
        *recipients_res == "mailxx <address@mailxx.dev>" &&
        msg.subject() == "parse simple" &&
        msg.subject_raw().charset == "ASCII" &&
        msg.subject_raw().codec_type == codec::codec_t::ASCII &&
        msg.content() == "hello\r\n\r\nworld\r\n\r\n\r\nhello again");
}


/**
Parsing custom headers.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_custom_header)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    string msg_str = "From: mail io <adre.sa@mailxx.dev>\r\n"
        "To: mailxx <adre.sa@mailxx.dev>\r\n"
        "Subject: parse custom header\r\n"
        "User-Agent: mailxx\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Content-Language: en-US\r\n"
        "\r\n"
        "Hello, world!\r\n";
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.headers().size() == 2 && msg.headers().find("User-Agent")->second == "mailxx");
    msg.remove_header("User-Agent");
    BOOST_CHECK(msg.headers().size() == 1);
}


/**
Parsing a header with a non-allowed character in it's name.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_bad_header_name)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    string msg_str = "From: mail io <adre.sa@mailxx.dev>\r\n"
        "To: mailxx <adre.sa@mailxx.dev>\r\n"
        "Subject: parse bad header name\r\n"
        "User-Agent: mailxx\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Content-Language: en-US\r\n"
        "\r\n"
        "Hello, world!\r\n";
    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing simple message with lines matching the recommended length.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_line_len)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    string msg_str = "From: adre.sa@mailxx.dev\r\n"
        "To: adre.sa@mailxx.dev\r\n"
        "Subject: parse line len\r\n"
        "\r\n"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n";

    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.from().addresses.at(0).address == "adre.sa@mailxx.dev" && msg.content().size() == 244);
}


/**
Parsing a message with lines violating the recommended length.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_wrong_line_len)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    string msg_str = "From: adre.sa@mailxx.dev\r\n"
        "To: adre.sa@mailxx.dev\r\n"
        "Subject: parse wrong line len\r\n"
        "\r\n"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n";

    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing by lines an oversized line.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_by_line_oversized)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse_by_line("From: mailxx <address@mailxx.dev>"));
    BOOST_REQUIRE(msg.parse_by_line("To: mailxx"));
    BOOST_REQUIRE(msg.parse_by_line("Subject: parse by line oversized"));
    BOOST_REQUIRE(msg.parse_by_line(""));
    BOOST_CHECK(!msg.parse_by_line("01234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n"));
}


/**
Parsing by lines an oversized line Base64 encoded.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_base64_line_oversized)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse_by_line("From: mailxx <address@mailxx.dev>"));
    BOOST_REQUIRE(msg.parse_by_line("To: mailxx <address@mailxx.dev>"));
    BOOST_REQUIRE(msg.parse_by_line("Date: Fri, 17 Jan 2014 05:39:22 -0730"));
    BOOST_REQUIRE(msg.parse_by_line("Content-Type: text/plain"));
    BOOST_REQUIRE(msg.parse_by_line("Content-Transfer-Encoding: Base64"));
    BOOST_REQUIRE(msg.parse_by_line("Subject: parse base64 line oversized"));
    BOOST_REQUIRE(msg.parse_by_line(""));
    BOOST_CHECK(!msg.parse_by_line("T3ZvIGplIGpha28gZHVnYWNoa2EgcG9ydWthIGtvamEgaW1hIGkgcHJhem5paCBsaW5pamEgaSBwcmVkdWdhY2hraWggbGluaWphLg==\r\n"));
}


/**
Parsing addresses and groups from the header.

Multiple addresses in a header are in separated lines, some of them are contain additional spaces.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_addresses)
{
    string msg_str = "From: mail io <address@mailxx.dev>\r\n"
        "To: info,\r\n"
        "  contact@mailxx.dev,\r\n"
        "  all, \r\n"
        "  mail io <address@mailxx.dev>\r\n"
        "Cc: all: Sylvain <qwerty@mailxx.dev>, \r\n"
        "  \"Sylvain Guinebert\" <asdfgh@mailxx.dev>; \r\n"
        "  address@mailxx.dev,\r\n"
        "  undisclosed-recipients:;\r\n"
        "  qwerty@gmail.com,\r\n"
        "  \"Sylvain\" <qwerty@hotmail.com>,\r\n"
        "  <qwerty@zoho.com>, \r\n"
        "  mailxx: qwerty@outlook.com;\r\n"
        "Subject: parse addresses\r\n"
        "\r\n"
        "Hello, World!\r\n";
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    auto recipients_res = msg.recipients_to_string();
    BOOST_REQUIRE(recipients_res);
    BOOST_CHECK(msg.from().addresses.at(0).name == "mail io" && msg.from().addresses.at(0).address == "address@mailxx.dev" &&
        msg.recipients().addresses.size() == 4 &&
        *recipients_res == "info,\r\n  <contact@mailxx.dev>,\r\n  all,\r\n  mail io <address@mailxx.dev>" &&
        msg.recipients().addresses.at(0).name == "info" && msg.recipients().addresses.at(1).address == "contact@mailxx.dev" &&
        msg.recipients().addresses.at(2).name == "all" &&
        msg.recipients().addresses.at(3).name == "mail io" && msg.recipients().addresses.at(3).address == "address@mailxx.dev" &&
        msg.cc_recipients().addresses.size() == 4 && msg.cc_recipients().groups.size() == 3 &&
        msg.cc_recipients().groups.at(0).name == "all" && msg.cc_recipients().addresses.at(0).address == "address@mailxx.dev" &&
        msg.cc_recipients().groups.at(1).name == "undisclosed-recipients" &&
        msg.cc_recipients().addresses.at(2).name == "Sylvain" && msg.cc_recipients().addresses.at(2).address == "qwerty@hotmail.com" &&
        msg.cc_recipients().groups.at(2).name == "mailxx" && msg.cc_recipients().groups.at(2).members.size() == 1 &&
        msg.subject() == "parse addresses" && msg.content() == "Hello, World!");
}


/**
Parsing address not separated by space from name.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_address_no_space)
{
    string msg_str = "From: mail io<address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: test\r\n"
        "\r\n"
        "test\r\n";

    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.from().addresses.at(0).name == "mail io" && msg.from().addresses.at(0).address == "address@mailxx.dev");
}


/**
Parsing the name and address without brackets.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_bad_author_address)
{
    string msg_str = "From: mailxx address@mailxx.dev\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: parse bad author address\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "\r\n"
        "hello\r\n";
    message msg;

    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing a message without the author address.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_no_author_address)
{
    string msg_str = "Sender: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: parse no author address\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "\r\n"
        "hello\r\n";
    message msg;

    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing a message with a wrong recipient mail group.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_bad_mail_group)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: all: karas@mailxx.dev\r\n"
        "Subject: parse bad mail group\r\n"
        "\r\n"
        "hello\r\n";
    message msg;

    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing a wrong recipient address.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_bad_recipient_address)
{
    string msg_str = "From: maill.io@mailxx.dev\r\n"
        "To: <mailxx>\r\n"
        "Subject: parse bad recipient address\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "\r\n"
        "hello\r\n";
    message msg;

    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing oversized recipients with the recommended line policy.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_recommended_address)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <contact@mailxx.dev>\r\n"
        "To: contact <contact@mailxx.dev>, Sylvain Guinebert <karas@mailxx.dev>, Sylvain Guinebert <qwerty@gmail.com>, "
        "  Sylvain Guinebert <asdfg@zoho.com>\r\n"
        "Cc: mail.io <address@mailxx.dev>, Sylvain Guinebert <zxcvb@yahoo.com>\r\n"
        "Date: Wed, 23 Aug 2017 22:16:45 +0000\r\n"
        "Subject: parse recommended address\r\n"
        "\r\n"
        "Hello, World!\r\n";

    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing quoted address not separated by space from name.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_quoted_address_no_space)
{
    string msg_str = "From: \"mail io\"<address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: test\r\n"
        "\r\n"
        "test\r\n";

    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.from().addresses.at(0).name == "mail io" && msg.from().addresses.at(0).address == "address@mailxx.dev");
}


/**
Parsing addresses in a single line which contains trailing comment.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_address_comment)
{
    string msg_str = "From: mailxx <address@mailxx.dev> (Mail Delivery System)\r\n"
        "To: address@mailxx.dev, all: qwerty@gmail.com, Karas <asdfgh@mailxx.dev>; Sylvain <qwerty@hotmail.com> (The comment)\r\n"
        "Subject: parse address comment\r\n"
        "\r\n"
        "Hello, World!";
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.from().addresses.at(0).name == "mailxx" && msg.from().addresses.at(0).address == "address@mailxx.dev" &&
        msg.recipients().addresses.size() == 2 && msg.recipients().groups.size() == 1 && msg.recipients().groups.at(0).members.size() == 2);
}


/**
Parsing address as name in the strict mode.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_double_address_strict)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: aaa@mailxx.dev <bbb@mailxx.dev>\r\n"
        "Subject: parse double address strict\r\n"
        "\r\n"
        "Hello, World!";

    message msg;
    msg.strict_mode(true);
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing address as name in the non-strict mode.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_double_address_non_strict)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: aaa@mailxx.dev <bbb@mailxx.dev>\r\n"
        "Subject: parse double address non strict\r\n"
        "\r\n"
        "Hello, World!";

    message msg;
    msg.strict_mode(false);
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.recipients().addresses.at(0).name == "aaa@mailxx.dev" && msg.recipients().addresses.at(0).address == "bbb@mailxx.dev");
}


/**
Parsing the address without the monkey.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_address_without_monkey)
{
    string msg_str =
        "From: recipients \"undisclosed recipients: ;\"\r\n"
        "To: recipients \"undisclosed recipients: ;\"\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: parse address without monkey\r\n"
        "\r\n"
        "test\r\n";
    message msg;
    msg.strict_mode(false);
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    auto from = msg.from().addresses.at(0);
    auto rcpt = msg.recipients().addresses.at(0);
    BOOST_CHECK(from.name == "recipients undisclosed recipients: ;" && rcpt.name == "recipients undisclosed recipients: ;");
}


/**
Parsing the content type which follows the specification.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_content_type)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Content-Type: text/plain; charset=\"UTF-8\"; method=request\r\n"
        "To: address@mailxx.dev\r\n"
        "Subject: parse content type\r\n"
        "\r\n"
        "Hello, World!";

    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.content_type().media_type() == mailxx::mime::media_type_t::TEXT && msg.content_type().media_subtype() == "plain" &&
        msg.content_type().charset() == "utf-8" && msg.content_type().attributes().size() == 2 && msg.content_type().attributes().at("method") == "request");

}


/**
Parsing the content type which does not follow the specification, in both strict and non-strict modes.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_malformed_content_type)
{
    const string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Content-Type: text/plain; charset       =   \"UTF-8\"\r\n"
        "To: address@mailxx.dev\r\n"
        "Subject: parse strict content type\r\n"
        "\r\n"
        "Hello, World!";

    {
        message msg;
        msg.line_policy(codec::line_len_policy_t::MANDATORY);
        msg.strict_mode(true);
        BOOST_CHECK(!msg.parse(msg_str));
    }

    {
        message msg;
        msg.line_policy(codec::line_len_policy_t::MANDATORY);
        msg.strict_mode(false);
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.content_type().media_type() == mailxx::mime::media_type_t::TEXT && msg.content_type().media_subtype() == "plain" && msg.content_type().charset() == "utf-8");
    }
}


/**
Parsing the content type with an attribute containing the backslash in the non-strict mode.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_attribute_backslash_non_strict)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Content-Type: application/octet-stream; name=217093469\\container_0_LOGO\r\n"
        "To: address@mailxx.dev\r\n"
        "Subject: parse attribute backslash non strict\r\n"
        "\r\n"
        "Hello, World!";

    message msg;
    msg.strict_mode(false);
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.content_type().media_type() == mailxx::mime::media_type_t::APPLICATION && msg.content_type().media_subtype() == "octet-stream");
}


/**
Parsing the content type with an attribute containing the backslash in the strict mode.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_attribute_backslash_strict)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Content-Type: application/octet-stream; name=217093469\\container_0_LOGO\r\n"
        "To: address@mailxx.dev\r\n"
        "Subject: parse attribute backslash strict\r\n"
        "\r\n"
        "Hello, World!";

    message msg;
    msg.strict_mode(true);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing the content disposition with an attribute with the quoted value containing the backslash.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_quoted_attribute_backslash)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename=\"C:\\Windows\\mailxx.ini\"\r\n"
        "To: address@mailxx.dev\r\n"
        "Subject: parse quoted attribute backslash\r\n"
        "\r\n"
        "Hello, World!";

    message msg;
    msg.strict_mode(false);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.content_type().media_type() == mailxx::mime::media_type_t::TEXT && msg.content_type().media_subtype() == "plain");
}


/**
Parsing continued ascii filename encoded in seven bit.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_continued_ascii_filename_bit7)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename*0=\"C:\\Program Files\\AlephoLtd\"; \r\n"
        "  filename*1=\"\\mailxx\\configuration.ini\"\r\n"
        "To: address@mailxx.dev\r\n"
        "Subject: parse continued ascii filename bit7\r\n"
        "\r\n"
        "Hello, World!";

    message msg;
    msg.strict_mode(false);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.name().charset == codec::CHARSET_ASCII && msg.name().buffer == "C:\\Program Files\\AlephoLtd\\mailxx\\configuration.ini" &&
        msg.name().charset == "ASCII" && msg.name().codec_type == codec::codec_t::ASCII);
}


/**
Parsing UTF8 filename encoded in percent.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_utf8_filename_pct)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename*0=UTF-8'en-us'C%3A\\%E8.xlsx; \r\n"
        "To: address@mailxx.dev\r\n"
        "Subject: parse utf8 filename percent\r\n"
        "\r\n"
        "Hello, World!";

    message msg;
    msg.strict_mode(false);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.name().buffer == "C:\\\xE8.xlsx" && msg.name().charset == codec::CHARSET_UTF8 && msg.name().codec_type == codec::codec_t::PERCENT);
}


/**
Parsing continued filename with the charset and language encoded in percent.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_continued_utf8_filename_pct_rec)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename*0=UTF-8'en-us'C%3A\\Program%20Files\\; \r\n"
        "  filename*1=%E8.xlsx; \r\n"
        "To: address@mailxx.dev\r\n"
        "Subject: parse continued utf8 filename percent recommended policy\r\n"
        "\r\n"
        "Hello, World!";

    message msg;
    msg.strict_mode(false);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.name().buffer == "C:\\Program Files\\\xE8.xlsx" && msg.name().charset == codec::CHARSET_UTF8 && msg.name().codec_type ==
        codec::codec_t::PERCENT);
}


/**
Parsing continued filename with the charset and language encoded in percent.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_continued_utf8_filename_pct_man)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Content-Type: text/plain; name*0*=UTF-8''%D0%A2%D0%BE%D0%BC%D0%B8%D1%81%D0%BB%D0%B0%D0%B2%20; \r\n"
        "  name*1*=%D0%9A%D0%B0%D1%80%D0%B0%D1%81%D1%82%D0%BE%D1%98%D0%BA%D0%BE%D0%B2%D0%B8%D1%9B\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename*0*=UTF-8''%D0%A2%D0%BE%D0%BC%D0%B8%D1%81%D0%BB%D0%B0%D0%B2%20; \r\n"
        "  filename*1*=%D0%9A%D0%B0%D1%80%D0%B0%D1%81%D1%82%D0%BE%D1%98%D0%BA%D0%BE%D0%B2%D0%B8%D1%9B\r\n"
        "To: address@mailxx.dev\r\n"
        "Subject: parse continued utf8 filename percent mandatory policy\r\n"
        "\r\n"
        "Hello, World!";

    {
        message msg;
        msg.strict_mode(false);
        msg.line_policy(codec::line_len_policy_t::MANDATORY);
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.name() == "Sylvain Guinebert" && msg.name().charset == codec::CHARSET_UTF8 && msg.name().codec_type == codec::codec_t::PERCENT);
    }
    {
        message msg;
        msg.strict_mode(false);
        msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
        BOOST_CHECK(!msg.parse(msg_str));
    }
}


/**
Parsing content type attributes.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_continued_content_type_attributes)
{
    const string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Content-Type: text/calendar; charset=utf-8; format=flowed; method=request; name=PersoalBoardingCard.pdf\r\n"
        "Subject: Hello,World!\r\n"
        "\r\n"
        "Hello, World!\r\n";
    {
        message msg;
        msg.strict_mode(false);
        msg.line_policy(codec::line_len_policy_t::MANDATORY);
        BOOST_REQUIRE(msg.parse(msg_str));
        auto attrs = msg.content_type().attributes();
        BOOST_CHECK(attrs.at("charset") == "utf-8" && attrs.at("format") == "flowed" && attrs.at("method") == "request" &&
            attrs.at("name") == "PersoalBoardingCard.pdf");
    }
    {
        message msg;
        msg.strict_mode(false);
        msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
        BOOST_CHECK(!msg.parse(msg_str));
    }
}


/**
Parsing the content type as a continued attribute.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_continued_content_type)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Content-Type: multipart/related; boundary*0=\"my_boundary_which_is_\"; \r\n"
        "  boundary*1=\"very_long_id_and_should_test_the_continuation\";\r\n"
        "  boundary*2=\"_of_the_attribute_in_headers\"; \r\n"
        "  name*1=\"veoma_dugachko_ime_za_zaglavlje_content_type_koje_ide_\"; \r\n"
        "  name*2=\"u_dva_reda\"\r\n"
        "To: address@mailxx.dev\r\n"
        "Subject: parse continued content type\r\n"
        "\r\n"
        "Hello, World!";

    message msg;
    msg.strict_mode(false);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.content_type().boundary() == "my_boundary_which_is_very_long_id_and_should_test_the_continuation_of_the_attribute_in_headers");
    BOOST_CHECK(msg.name() == "veoma_dugachko_ime_za_zaglavlje_content_type_koje_ide_u_dva_reda" && msg.name().charset == "ASCII" &&
        msg.name().codec_type == codec::codec_t::ASCII);
}


/**
Parsing the filename as a continued attribute without the language.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_invalid_continued_filename)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename*0=\"C:\\Program Files\\\"; \r\n"
        "  filename*1=UTF-8'%E8.xlsx; \r\n"
        "To: address@mailxx.dev\r\n"
        "Subject: parse invalid continued filename\r\n"
        "\r\n"
        "Hello, World!";

    message msg;
    msg.strict_mode(false);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing a header split into two lines.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_multiline_header)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Message-ID: <1234567890123456789012345678901234567890\r\n"
        " 12345678901234567890@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: parse multiline header\r\n"
        "\r\n"
        "Hello, World!\r\n";
    message msg;
    msg.strict_mode(false);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.message_id() == "<123456789012345678901234567890123456789012345678901234567890@mailxx.dev>");
}


/**
Parsing a header exceeding the line policy.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_long_header)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Message-ID: <123456789012345678901234567890123456789012345678901234567890@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: parse long header\r\n"
        "\r\n"
        "Hello, World!\r\n";
    message msg;
    msg.strict_mode(false);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing multiline content with lines containing leading dots, with the escaping dot flag on.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_dotted_esc)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: parse dotted escape\r\n"
        "\r\n"
        "..Hello, World!\r\n"
        "hello again\r\n"
        "...test\r\n"
        "\r\n"
        "..\r\n"
        "\r\n"
        "yaba.daba.doo.\r\n"
        "\r\n"
        "...\r\n"
        "\r\n";

    message msg;
    BOOST_REQUIRE(msg.parse(msg_str, true));
    BOOST_CHECK(msg.content() == ".Hello, World!\r\n"
        "hello again\r\n"
        "..test\r\n"
        "\r\n"
        ".\r\n"
        "\r\n"
        "yaba.daba.doo.\r\n"
        "\r\n"
        "..");
}


/**
Parsing long plain text with default charset (ASCII) default encoded (Seven Bit) with the recommended length.

Except the trailing ones, CRLF characters are preserved.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_long_text_default_default)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>, <qwerty@gmail.com>\r\n"
        "Date: Fri, 12 Feb 2016 13:22:22 +0100\r\n"
        "Content-Type: text/plain\r\n"
        "Subject: parse long text default default\r\n"
        "\r\n"
        "This is a very long message that has blank lines and very long lines. It is no\r\n"
        "t clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust mess\r\n"
        "age formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and se\r\n"
        "e how wrapping behaves when characters are multi-byte. It should not matter wh\r\n"
        "ether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. T\r\n"
        "his test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n";

    message msg;
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.subject() == "parse long text default default" && msg.content_type().media_type() == mime::media_type_t::TEXT &&
        msg.content_type().media_subtype() == "plain" && msg.content_type().charset().empty() &&
        msg.content_transfer_encoding() == mime::content_transfer_encoding_t::NONE);
    BOOST_CHECK(msg.content() ==
        "This is a very long message that has blank lines and very long lines. It is no\r\n"
        "t clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust mess\r\n"
        "age formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and se\r\n"
        "e how wrapping behaves when characters are multi-byte. It should not matter wh\r\n"
        "ether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. T\r\n"
        "his test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n");
}

BOOST_AUTO_TEST_CASE(parse_long_text_default_base64)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: parse long text default base64\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "\r\n"
        "VGhpcyBpcyBhIHZlcnkgbG9uZyBtZXNzYWdlIHRoYXQgaGFzIGJsYW5rIGxpbmVzIGFuZCB2ZXJ5\r\n"
        "IGxvbmcgbGluZXMuIEl0IGlzIG5vdCBjbGVhciBob3cgdGhlIHRleHQgd2lsbCB3cmFwDQpzbyBJ\r\n"
        "IGhvcGUgdGhpcyB0ZXh0IHNob3dzIHRoYXQuDQoNCldlIHNob3VsZCBzZWUgaG93IGNvbW1vbiBt\r\n"
        "YWlsIGNsaWVudHMgd3JhcCB0ZXh0LCBhbmQgYmFzZWQgb24gdGhhdCBhZGp1c3QgbWVzc2FnZSBm\r\n"
        "b3JtYXR0aW5nLiBNYXliZSB0aGVyZSBpcyBubyBuZWVkLCBiZWNhdXNlIGxpYm1haWx4eCBpcyBu\r\n"
        "b3QgbWVhbnQgdG8NCmZvcm1hdCB0ZXh0Lg0KDQpJbiBhbnkgY2FzZSwgYWZ0ZXIgY2hlY2tpbmcg\r\n"
        "QVNDSUkgd2Ugc2hvdWxkIGFsc28gY2hlY2sgVVRGLTggY2hhcmFjdGVycyBhbmQgc2VlIGhvdyB3\r\n"
        "cmFwcGluZyBiZWhhdmVzIHdoZW4gY2hhcmFjdGVycyBhcmUgbXVsdGktYnl0ZS4gSXQgc2hvdWxk\r\n"
        "IG5vdCBtYXR0ZXIgd2hldGhlciB0aGUgZW5jb2RpbmcNCmlzIGJhc2U2NCBvciBxdW90ZWQgcHJp\r\n"
        "bnRhYmxlLCBiZWNhdXNlIEFTQ0lJIGNoYXJhY3RlcnMgd3JhcCBpbnRvIG5ldyBsaW5lcy4gVGhp\r\n"
        "cyB0ZXN0IHNob3VsZCBzaG93IHdoZXRoZXIgdGhlcmUgYXJlIGJ1Z3MgaW4gdGhlIGZvcm1hdHRp\r\n"
        "bmcgbG9naWMsDQphbmQgdGhlIHNhbWUgc2hvdWxkIGJlIGNoZWNrZWQgd2hlbiBwYXJzaW5nLg0K\r\n"
        "DQoNCg0KSGVyZSBpcyBhbHNvIGEgY2hlY2sgZm9yIGEgc2VxdWVuY2Ugb2YgYmxhbmsgbGluZXMu\r\n"
        "DQoNCg0K\r\n";

    message msg;
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.subject() == "parse long text default base64" && msg.content_type().media_type() == mime::media_type_t::NONE &&
        msg.content_type().media_subtype().empty() && msg.content_type().charset().empty() &&
        msg.content_transfer_encoding() == mime::content_transfer_encoding_t::BASE_64);
    BOOST_CHECK(msg.content() ==
        "This is a very long message that has blank lines and very long lines. It is no\r\n"
        "t clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust mess\r\n"
        "age formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and se\r\n"
        "e how wrapping behaves when characters are multi-byte. It should not matter wh\r\n"
        "ether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. T\r\n"
        "his test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n");
}

BOOST_AUTO_TEST_CASE(parse_long_text_default_qp)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: parse long text default quoted printable\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "This is a very long message that has blank lines and very long lines. It is =\r\n"
        "not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust m=\r\n"
        "essage formatting. Maybe there is no need, because libmailxx is not meant t=\r\n"
        "o\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and =\r\n"
        "see how wrapping behaves when characters are multi-byte. It should not matt=\r\n"
        "er whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines=\r\n"
        ". This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n";

    message msg;
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.subject() == "parse long text default quoted printable" && msg.content_type().media_type() == mime::media_type_t::NONE &&
        msg.content_type().media_subtype().empty() && msg.content_type().charset().empty() &&
        msg.content_transfer_encoding() == mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    BOOST_CHECK(msg.content() ==
        "This is a very long message that has blank lines and very long lines. It is no\r\n"
        "t clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust mess\r\n"
        "age formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and se\r\n"
        "e how wrapping behaves when characters are multi-byte. It should not matter wh\r\n"
        "ether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. T\r\n"
        "his test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n");
}

BOOST_AUTO_TEST_CASE(parse_long_text_utf8_base64)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: parse long text utf8 base64\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "VGhpcyBpcyBhIHZlcnkgbG9uZyBtZXNzYWdlIHRoYXQgaGFzIGJsYW5rIGxpbmVzIGFuZCB2ZXJ5\r\n"
        "IGxvbmcgbGluZXMuIEl0IGlzIG5vdCBjbGVhciBob3cgdGhlIHRleHQgd2lsbCB3cmFwDQpzbyBJ\r\n"
        "IGhvcGUgdGhpcyB0ZXh0IHNob3dzIHRoYXQuDQoNCldlIHNob3VsZCBzZWUgaG93IGNvbW1vbiBt\r\n"
        "YWlsIGNsaWVudHMgd3JhcCB0ZXh0LCBhbmQgYmFzZWQgb24gdGhhdCBhZGp1c3QgbWVzc2FnZSBm\r\n"
        "b3JtYXR0aW5nLiBNYXliZSB0aGVyZSBpcyBubyBuZWVkLCBiZWNhdXNlIGxpYm1haWx4eCBpcyBu\r\n"
        "b3QgbWVhbnQgdG8NCmZvcm1hdCB0ZXh0Lg0KDQpJbiBhbnkgY2FzZSwgYWZ0ZXIgY2hlY2tpbmcg\r\n"
        "QVNDSUkgd2Ugc2hvdWxkIGFsc28gY2hlY2sgVVRGLTggY2hhcmFjdGVycyBhbmQgc2VlIGhvdyB3\r\n"
        "cmFwcGluZyBiZWhhdmVzIHdoZW4gY2hhcmFjdGVycyBhcmUgbXVsdGktYnl0ZS4gSXQgc2hvdWxk\r\n"
        "IG5vdCBtYXR0ZXIgd2hldGhlciB0aGUgZW5jb2RpbmcNCmlzIGJhc2U2NCBvciBxdW90ZWQgcHJp\r\n"
        "bnRhYmxlLCBiZWNhdXNlIEFTQ0lJIGNoYXJhY3RlcnMgd3JhcCBpbnRvIG5ldyBsaW5lcy4gVGhp\r\n"
        "cyB0ZXN0IHNob3VsZCBzaG93IHdoZXRoZXIgdGhlcmUgYXJlIGJ1Z3MgaW4gdGhlIGZvcm1hdHRp\r\n"
        "bmcgbG9naWMsDQphbmQgdGhlIHNhbWUgc2hvdWxkIGJlIGNoZWNrZWQgd2hlbiBwYXJzaW5nLg0K\r\n"
        "DQoNCg0KSGVyZSBpcyBhbHNvIGEgY2hlY2sgZm9yIGEgc2VxdWVuY2Ugb2YgYmxhbmsgbGluZXMu\r\n"
        "DQoNCg0K\r\n";

    message msg;
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.subject() == "parse long text utf8 base64" && msg.content_type().media_type() == mime::media_type_t::TEXT &&
        msg.content_type().media_subtype() == "plain" && msg.content_type().charset() == "utf-8" &&
        msg.content_transfer_encoding() == mime::content_transfer_encoding_t::BASE_64);
    BOOST_CHECK(msg.content() ==
        "This is a very long message that has blank lines and very long lines. It is no\r\n"
        "t clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust mess\r\n"
        "age formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and se\r\n"
        "e how wrapping behaves when characters are multi-byte. It should not matter wh\r\n"
        "ether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. T\r\n"
        "his test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n");
}

BOOST_AUTO_TEST_CASE(parse_long_text_utf8_qp)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "Subject: parse long text utf8 quoted printable\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "This is a very long message that has blank lines and very long lines. It is =\r\n"
        "not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust m=\r\n"
        "essage formatting. Maybe there is no need, because libmailxx is not meant t=\r\n"
        "o\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and =\r\n"
        "see how wrapping behaves when characters are multi-byte. It should not matt=\r\n"
        "er whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines=\r\n"
        ". This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n";

    message msg;
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.subject() == "parse long text utf8 quoted printable" && msg.content_type().media_type() == mime::media_type_t::TEXT &&
        msg.content_type().media_subtype() == "plain" && msg.content_type().charset() == "utf-8" &&
        msg.content_transfer_encoding() == mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    BOOST_CHECK(msg.content() ==
        "This is a very long message that has blank lines and very long lines. It is no\r\n"
        "t clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust mess\r\n"
        "age formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and se\r\n"
        "e how wrapping behaves when characters are multi-byte. It should not matter wh\r\n"
        "ether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. T\r\n"
        "his test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n");
}

BOOST_AUTO_TEST_CASE(parse_multipart_html_ascii_bit7_plain_utf8_base64)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/alternative; boundary=\"my_bound\"\r\n"
        "Subject: parse multipart html ascii bit7 plain utf8 base64\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "\r\n"
        "<html><head></head><body><h1>Hello, World!</h1></body></html>\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "SGVsbG8sIFdvcmxkIQ==\r\n"
        "\r\n"
        "--my_bound--\r\n";
    BOOST_REQUIRE(msg.parse(msg_str));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    auto from_res = msg.from_to_string();
    BOOST_REQUIRE(from_res);
    BOOST_CHECK(msg.content_type().boundary() == "my_bound" && msg.subject() == "parse multipart html ascii bit7 plain utf8 base64" && msg.date_time() == ldt &&
        *from_res == "mailxx <address@mailxx.dev>" && msg.recipients().addresses.size() == 1 &&
        msg.content_type().media_type() == mime::media_type_t::MULTIPART && msg.content_type().media_subtype() == "alternative" && msg.parts().size() == 2);
    BOOST_CHECK(msg.parts().at(0).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(0).content_type().media_subtype() == "html" &&
        msg.parts().at(0).content_transfer_encoding() == mime::content_transfer_encoding_t::BIT_7 &&
        msg.parts().at(0).content_type().charset() == "us-ascii" &&
        msg.parts().at(0).content() == "<html><head></head><body><h1>Hello, World!</h1></body></html>");
    BOOST_CHECK(msg.parts().at(1).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(1).content_type().media_subtype() == "plain" &&
        msg.parts().at(1).content_transfer_encoding() == mime::content_transfer_encoding_t::BASE_64 &&
        msg.parts().at(1).content_type().charset() == "utf-8" && msg.parts().at(1).content() == "Hello, World!");
}


/**
Parsing alternative multipart with the first part HTML with ASCII charset Quoted Printable encoded, the second part text with ASCII charset Bit8
encoded.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_multipart_html_ascii_qp_plain_ascii_bit8)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);

    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/alternative; boundary=\"my_bound\"\r\n"
        "Subject: parse multipart html ascii qp plain ascii bit8\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "<html><head></head><body><h1>Hello, World!</h1></body></html>\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 8bit\r\n"
        "\r\n"
        "Hello, World!\r\n"
        "\r\n"
        "--my_bound--\r\n";
    BOOST_REQUIRE(msg.parse(msg_str));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    auto from_res = msg.from_to_string();
    BOOST_REQUIRE(from_res);
    BOOST_CHECK(msg.subject() == "parse multipart html ascii qp plain ascii bit8" &&  msg.content_type().boundary() == "my_bound" && msg.date_time() == ldt &&
        *from_res == "mailxx <address@mailxx.dev>" && msg.recipients().addresses.size() == 1 &&
        msg.content_type().media_type() == mime::media_type_t::MULTIPART && msg.content_type().media_subtype() == "alternative" && msg.parts().size() == 2);
    BOOST_CHECK(msg.parts().at(0).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(0).content_type().media_subtype() == "html" &&
        msg.parts().at(0).content_transfer_encoding() == mime::content_transfer_encoding_t::QUOTED_PRINTABLE &&
        msg.parts().at(0).content_type().charset() == "us-ascii" && msg.parts().at(0).content() ==
        "<html><head></head><body><h1>Hello, World!</h1></body></html>");
    BOOST_CHECK(msg.parts().at(1).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(1).content_type().media_subtype() == "plain" &&
        msg.parts().at(1).content_transfer_encoding() == mime::content_transfer_encoding_t::BIT_8 &&
        msg.parts().at(1).content_type().charset() == "us-ascii" && msg.parts().at(1).content() == "Hello, World!");
}


/**
Parsing related multipart with the first part HTML default charset Base64 encoded, the second part text UTF-8 charset Quoted Printable encoded.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_multipart_html_default_base64_text_utf8_qp)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);

    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/related; boundary=\"my_bound\"\r\n"
        "Subject: parse multipart html default base64 text utf8 qp\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "\r\n"
        "PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5PjxoMT5IZWxsbywgV29ybGQhPC9oMT48L2JvZHk+PC9o\r\n"
        "dG1sPg==\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "Hello, World!\r\n"
        "\r\n"
        "--my_bound--\r\n";
    BOOST_REQUIRE(msg.parse(msg_str));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    auto from_res = msg.from_to_string();
    BOOST_REQUIRE(from_res);
    BOOST_CHECK(msg.subject() == "parse multipart html default base64 text utf8 qp" &&  msg.content_type().boundary() == "my_bound" && msg.date_time() == ldt &&
        *from_res == "mailxx <address@mailxx.dev>" && msg.recipients().addresses.size() == 1 &&
        msg.content_type().media_type() == mime::media_type_t::MULTIPART && msg.content_type().media_subtype() == "related" && msg.parts().size() == 2);
    BOOST_CHECK(msg.parts().at(0).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(0).content_type().media_subtype() == "html" &&
        msg.parts().at(0).content_transfer_encoding() == mime::content_transfer_encoding_t::BASE_64 &&
        msg.parts().at(0).content_type().charset().empty() && msg.parts().at(0).content() == "<html><head></head><body><h1>Hello, World!</h1></body></html>");
    BOOST_CHECK(msg.parts().at(1).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(1).content_type().media_subtype() == "plain" &&
        msg.parts().at(1).content_transfer_encoding() == mime::content_transfer_encoding_t::QUOTED_PRINTABLE &&
        msg.parts().at(1).content_type().charset() == "utf-8" && msg.parts().at(1).content() == "Hello, World!");
}


/**
Parsing alternative multipart with the first part HTML with ASCII charset Base64 encoded, the second part plain text with ASCII charset Bit7 encoded.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_multipart_html_ascii_base64_plain_ascii_bit7)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);

    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>, <qwerty@gmail.com>\r\n"
        "Date: Fri, 12 Feb 2016 13:22:22 +0100\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/related; boundary=\"my_bound\"\r\n"
        "Subject: parse multipart html ascii base64 plain ascii bit7\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5PkhlbGxvLCBXb3JsZCE8L2JvZHk+PC9odG1sPg==\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "\r\n"
        "Hello, World!\r\n"
        "\r\n"
        "--my_bound--\r\n";
    BOOST_REQUIRE(msg.parse(msg_str));
    auto ldt = make_zoned_time(2016, 2, 12, 12, 22, 22, 1, 0);
    auto from_res = msg.from_to_string();
    BOOST_REQUIRE(from_res);
    BOOST_CHECK(msg.subject() == "parse multipart html ascii base64 plain ascii bit7" &&  msg.content_type().boundary() == "my_bound" && msg.date_time() == ldt &&
        *from_res == "mailxx <address@mailxx.dev>" && msg.recipients().addresses.size() == 2 &&
        msg.content_type().media_type() == mime::media_type_t::MULTIPART && msg.content_type().media_subtype() == "related" && msg.parts().size() == 2);
    BOOST_CHECK(msg.parts().at(0).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(0).content_type().media_subtype() == "html" &&
        msg.parts().at(0).content_transfer_encoding() == mime::content_transfer_encoding_t::BASE_64 &&
        msg.parts().at(0).content_type().charset() == "us-ascii" && msg.parts().at(0).content() == "<html><head></head><body>Hello, World!</body></html>");
    BOOST_CHECK(msg.parts().at(1).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(1).content_type().media_subtype() == "plain" &&
        msg.parts().at(1).content_transfer_encoding() == mime::content_transfer_encoding_t::BIT_7 &&
        msg.parts().at(1).content_type().charset() == "us-ascii" && msg.parts().at(1).content() == "Hello, World!");
}


/**
Parsing multipart with leading dots and escaping flag turned off.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_dotted_multipart_no_esc)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    string msg_str =
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>, Sylvain Guinebert <qwerty@gmail.com>, Sylvain Guinebert <asdfgh@zoho.com>, Sylvain Guinebert <zxcvbn@hotmail.com>\r\n"
        "Date: Tue, 15 Mar 2016 13:13:32 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/related; boundary=\"my_bound\"\r\n"
        "Subject: parse dotted multipart no esc\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "\r\n"
        "<html>\r\n"
        "\t<head>\r\n"
        "\t\t<title>.title</title>\r\n"
        "\t</head>\r\n"
        "..\r\n"
        "\t<body>\r\n"
        "\t\t<h1>\r\n"
        "\t\t\t..Hello, Worldeeeee!\r\n"
        "\t\t</h1>\r\n"
        "\r\n"
        "\r\n"
        ".\r\n"
        "\r\n\r\n"
        "\t.<p>Anyone there?</p>\r\n"
        "\t</body>\r\n"
        "</html>\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        ".Hello world!\r\n"
        "..\r\n"
        "Anyone there?\r\n"
        "\r\n"
        "\r\n"
        ".\r\n"
        "\r\n"
        "\r\n"
        "..yabadabadoo...\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        ".Hello, World!\r\n"
        "..\r\n"
        "Is anyone there?\r\n"
        "\r\n\r\n"
        ".\r\n"
        "\r\n\r\n"
        "..yabba dabba doo...\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "\r\n"
        "PGh0bWw+DQoJPGhlYWQ+DQoJCTx0aXRsZT4udGl0bGU8L3RpdGxlPg0KCTwvaGVhZD4NCi4uDQoJ\r\n"
        "PGJvZHk+DQoJCTxoMT4NCgkJCS4uSGVsbG8sIFdvcmxkZWVlZWUhDQoJCTwvaDE+DQoNCg0KLg0K\r\n"
        "DQoNCgkuPHA+QW55b25lIHRoZXJlPzwvcD4NCgk8L2JvZHk+DQo8L2h0bWw+\r\n"
        "\r\n"
        "--my_bound--\r\n";
    BOOST_REQUIRE(msg.parse(msg_str, false));
    auto ldt = make_zoned_time(2016, 3, 15, 13, 13, 32, 0, 0);
    auto from_res = msg.from_to_string();
    BOOST_REQUIRE(from_res);
    BOOST_CHECK(msg.subject() == "parse dotted multipart no esc" && msg.content_type().boundary() == "my_bound" &&
        msg.date_time() == ldt && *from_res == "mailxx <address@mailxx.dev>" && msg.recipients().addresses.size() == 4 &&
        msg.content_type().media_type() == mime::media_type_t::MULTIPART && msg.content_type().media_subtype() == "related" && msg.parts().size() == 4);
    BOOST_CHECK(msg.parts().at(0).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(0).content_type().media_subtype() == "html" &&
        msg.parts().at(0).content_transfer_encoding() == mime::content_transfer_encoding_t::BIT_7 &&
        msg.parts().at(0).content_type().charset() == "us-ascii" && msg.parts().at(0).content() == "<html>\r\n"
        "\t<head>\r\n"
        "\t\t<title>.title</title>\r\n"
        "\t</head>\r\n"
        "..\r\n"
        "\t<body>\r\n"
        "\t\t<h1>\r\n"
        "\t\t\t..Hello, Worldeeeee!\r\n"
        "\t\t</h1>\r\n"
        "\r\n"
        "\r\n"
        ".\r\n"
        "\r\n\r\n"
        "\t.<p>Anyone there?</p>\r\n"
        "\t</body>\r\n"
        "</html>");
    BOOST_CHECK(msg.parts().at(1).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(1).content_type().media_subtype() == "plain" &&
        msg.parts().at(1).content_transfer_encoding() == mime::content_transfer_encoding_t::QUOTED_PRINTABLE &&
        msg.parts().at(1).content_type().charset() == "utf-8" && msg.parts().at(1).content() == ".Hello world!\r\n"
        "..\r\n"
        "Anyone there?\r\n"
        "\r\n"
        "\r\n"
        ".\r\n"
        "\r\n"
        "\r\n"
        "..yabadabadoo...");
    BOOST_CHECK(msg.parts().at(2).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(2).content_type().media_subtype() == "plain" &&
        msg.parts().at(2).content_transfer_encoding() == mime::content_transfer_encoding_t::QUOTED_PRINTABLE &&
        msg.parts().at(2).content_type().charset() == "utf-8" && msg.parts().at(2).content() == ".Hello, World!\r\n"
        "..\r\n"
        "Is anyone there?\r\n"
        "\r\n\r\n"
        ".\r\n"
        "\r\n\r\n"
        "..yabba dabba doo...");
    BOOST_CHECK(msg.parts().at(3).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(3).content_type().media_subtype() == "html" &&
        msg.parts().at(3).content_transfer_encoding() == mime::content_transfer_encoding_t::BASE_64 &&
        msg.parts().at(3).content_type().charset() == "us-ascii" && msg.parts().at(3).content() == "<html>\r\n"
        "\t<head>\r\n"
        "\t\t<title>.title</title>\r\n"
        "\t</head>\r\n"
        "..\r\n"
        "\t<body>\r\n"
        "\t\t<h1>\r\n"
        "\t\t\t..Hello, Worldeeeee!\r\n"
        "\t\t</h1>\r\n"
        "\r\n"
        "\r\n"
        ".\r\n"
        "\r\n"
        "\r\n"
        "\t.<p>Anyone there?</p>\r\n"
        "\t</body>\r\n"
        "</html>");
}


/**
Parsing multipart with leading dots and escaping flag turned on.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_dotted_multipart_esc)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    string msg_str =
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>, Sylvain Guinebert <qwerty@gmail.com>, Sylvain Guinebert <asdfgh@zoho.com>, Sylvain Guinebert <zxcvbn@hotmail.com>\r\n"
        "Date: Tue, 15 Mar 2016 13:13:32 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/related; boundary=\"my_bound\"\r\n"
        "Subject: parse dotted multipart esc\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "\r\n"
        "<html>\r\n"
        "\t<head>\r\n"
        "\t\t<title>.title</title>\r\n"
        "\t</head>\r\n"
        "...\r\n"
        "\t<body>\r\n"
        "\t\t<h1>\r\n"
        "\t\t\t..Hello, Worldeeeee!\r\n"
        "\t\t</h1>\r\n"
        "\r\n"
        "\r\n"
        "..\r\n"
        "\r\n"
        "\r\n"
        "\t.<p>Anyone there?</p>\r\n"
        "\t</body>\r\n"
        "</html>\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "..Hello world!\r\n"
        "...\r\n"
        "Anyone there?\r\n"
        "\r\n"
        "\r\n"
        "..\r\n"
        "\r\n"
        "\r\n"
        "...yabadabadoo...\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "..Hello, World!\r\n"
        "...\r\n"
        "Is anyone there?\r\n"
        "\r\n\r\n"
        "..\r\n"
        "\r\n\r\n"
        "...yabba dabba doo...\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "\r\n"
        "PGh0bWw+DQoJPGhlYWQ+DQoJCTx0aXRsZT4udGl0bGU8L3RpdGxlPg0KCTwvaGVhZD4NCi4uDQoJ\r\n"
        "PGJvZHk+DQoJCTxoMT4NCgkJCS4uSGVsbG8sIFdvcmxkZWVlZWUhDQoJCTwvaDE+DQoNCg0KLg0K\r\n"
        "DQoNCgkuPHA+QW55b25lIHRoZXJlPzwvcD4NCgk8L2JvZHk+DQo8L2h0bWw+\r\n"
        "\r\n"
        "--my_bound--\r\n";
    BOOST_REQUIRE(msg.parse(msg_str, true));
    auto ldt = make_zoned_time(2016, 3, 15, 13, 13, 32, 0, 0);
    auto from_res = msg.from_to_string();
    BOOST_REQUIRE(from_res);
    BOOST_CHECK(msg.subject() == "parse dotted multipart esc" && msg.content_type().boundary() == "my_bound" &&
        msg.date_time() == ldt && *from_res == "mailxx <address@mailxx.dev>" && msg.recipients().addresses.size() == 4 &&
        msg.content_type().media_type() == mime::media_type_t::MULTIPART && msg.content_type().media_subtype() == "related" && msg.parts().size() == 4);
    BOOST_CHECK(msg.parts().at(0).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(0).content_type().media_subtype() == "html" &&
        msg.parts().at(0).content_transfer_encoding() == mime::content_transfer_encoding_t::BIT_7 &&
        msg.parts().at(0).content_type().charset() == "us-ascii" && msg.parts().at(0).content() == "<html>\r\n"
        "\t<head>\r\n"
        "\t\t<title>.title</title>\r\n"
        "\t</head>\r\n"
        "..\r\n"
        "\t<body>\r\n"
        "\t\t<h1>\r\n"
        "\t\t\t..Hello, Worldeeeee!\r\n"
        "\t\t</h1>\r\n"
        "\r\n"
        "\r\n"
        ".\r\n"
        "\r\n\r\n"
        "\t.<p>Anyone there?</p>\r\n"
        "\t</body>\r\n"
        "</html>");
    BOOST_CHECK(msg.parts().at(1).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(1).content_type().media_subtype() == "plain" &&
        msg.parts().at(1).content_transfer_encoding() == mime::content_transfer_encoding_t::QUOTED_PRINTABLE &&
        msg.parts().at(1).content_type().charset() == "utf-8" && msg.parts().at(1).content() == ".Hello world!\r\n"
        "..\r\n"
        "Anyone there?\r\n"
        "\r\n"
        "\r\n"
        ".\r\n"
        "\r\n"
        "\r\n"
        "..yabadabadoo...");
    BOOST_CHECK(msg.parts().at(2).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(2).content_type().media_subtype() == "plain" &&
        msg.parts().at(2).content_transfer_encoding() == mime::content_transfer_encoding_t::QUOTED_PRINTABLE &&
        msg.parts().at(2).content_type().charset() == "utf-8" && msg.parts().at(2).content() == ".Hello, World!\r\n"
        "..\r\n"
        "Is anyone there?\r\n"
        "\r\n\r\n"
        ".\r\n"
        "\r\n\r\n"
        "..yabba dabba doo...");
    BOOST_CHECK(msg.parts().at(3).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(3).content_type().media_subtype() == "html" &&
        msg.parts().at(3).content_transfer_encoding() == mime::content_transfer_encoding_t::BASE_64 &&
        msg.parts().at(3).content_type().charset() == "us-ascii" && msg.parts().at(3).content() == "<html>\r\n"
        "\t<head>\r\n"
        "\t\t<title>.title</title>\r\n"
        "\t</head>\r\n"
        "..\r\n"
        "\t<body>\r\n"
        "\t\t<h1>\r\n"
        "\t\t\t..Hello, Worldeeeee!\r\n"
        "\t\t</h1>\r\n"
        "\r\n"
        "\r\n"
        ".\r\n"
        "\r\n"
        "\r\n"
        "\t.<p>Anyone there?</p>\r\n"
        "\t</body>\r\n"
        "</html>");
}


/**
Parsing multipart with long content in various combinations.

The message has four parts: the first is long HTML ASCII charset Seven Bit encoded, the second is long text ASCII charset Base64 encoded, the third is
long text ASCII charset Quoted Printable encoded, the fourth is long text UTF-8 charset Quoted printable encoded.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_long_multipart)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    string msg_str =
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/related; boundary=\"my_bound\"\r\n"
        "Subject: parse long multipart\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "\r\n"
        "<html><head></head><body><h1>Hello, World!</h1><p>Hello World!</p><p>Hello aga\r\n"
        "in!</p><p>Anyone there?</p><p>Yabba Dabba Doo!</p></body></html>\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "\r\n"
        "VGhpcyBpcyBhIHZlcnkgbG9uZyBtZXNzYWdlIHRoYXQgaGFzIGJsYW5rIGxpbmVzIGFuZCB2ZXJ5\r\n"
        "IGxvbmcgbGluZXMuIEl0IGlzIG5vdCBjbGVhciBob3cgdGhlIHRleHQgd2lsbCB3cmFwDQpzbyBJ\r\n"
        "IGhvcGUgdGhpcyB0ZXh0IHNob3dzIHRoYXQuDQoNCldlIHNob3VsZCBzZWUgaG93IGNvbW1vbiBt\r\n"
        "YWlsIGNsaWVudHMgd3JhcCB0ZXh0LCBhbmQgYmFzZWQgb24gdGhhdCBhZGp1c3QgbWVzc2FnZSBm\r\n"
        "b3JtYXR0aW5nLiBNYXliZSB0aGVyZSBpcyBubyBuZWVkLCBiZWNhdXNlIGxpYm1haWx4eCBpcyBu\r\n"
        "b3QgbWVhbnQgdG8NCmZvcm1hdCB0ZXh0Lg0KDQpJbiBhbnkgY2FzZSwgYWZ0ZXIgY2hlY2tpbmcg\r\n"
        "QVNDSUkgd2Ugc2hvdWxkIGFsc28gY2hlY2sgVVRGLTggY2hhcmFjdGVycyBhbmQgc2VlIGhvdyB3\r\n"
        "cmFwcGluZyBiZWhhdmVzIHdoZW4gY2hhcmFjdGVycyBhcmUgbXVsdGktYnl0ZS4gSXQgc2hvdWxk\r\n"
        "IG5vdCBtYXR0ZXIgd2hldGhlciB0aGUgZW5jb2RpbmcNCmlzIGJhc2U2NCBvciBxdW90ZWQgcHJp\r\n"
        "bnRhYmxlLCBiZWNhdXNlIEFTQ0lJIGNoYXJhY3RlcnMgd3JhcCBpbnRvIG5ldyBsaW5lcy4gVGhp\r\n"
        "cyB0ZXN0IHNob3VsZCBzaG93IHdoZXRoZXIgdGhlcmUgYXJlIGJ1Z3MgaW4gdGhlIGZvcm1hdHRp\r\n"
        "bmcgbG9naWMsDQphbmQgdGhlIHNhbWUgc2hvdWxkIGJlIGNoZWNrZWQgd2hlbiBwYXJzaW5nLg0K\r\n"
        "DQoNCg0KSGVyZSBpcyBhbHNvIGEgY2hlY2sgZm9yIGEgc2VxdWVuY2Ugb2YgYmxhbmsgbGluZXMu\r\n"
        "DQoNCg0K\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "This is a very long message that has blank lines and very long lines. It is =\r\n"
        "not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust m=\r\n"
        "essage formatting. Maybe there is no need, because libmailxx is not meant t=\r\n"
        "o\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and =\r\n"
        "see how wrapping behaves when characters are multi-byte. It should not matt=\r\n"
        "er whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines=\r\n"
        ". This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "\r\n"
        "This is a very long message that has blank lines and very long lines. It is =\r\n"
        "not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust m=\r\n"
        "essage formatting. Maybe there is no need, because libmailxx is not meant t=\r\n"
        "o\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and =\r\n"
        "see how wrapping behaves when characters are multi-byte. It should not matt=\r\n"
        "er whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines=\r\n"
        ". This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n"
        "\r\n"
        "--my_bound--\r\n";
    BOOST_REQUIRE(msg.parse(msg_str));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    auto from_res = msg.from_to_string();
    BOOST_REQUIRE(from_res);
    BOOST_CHECK(msg.subject() == "parse long multipart" &&  msg.content_type().boundary() == "my_bound" && msg.date_time() == ldt &&
        *from_res == "mailxx <address@mailxx.dev>" && msg.recipients().addresses.size() == 1 &&
        msg.content_type().media_type() == mime::media_type_t::MULTIPART && msg.content_type().media_subtype() == "related" && msg.parts().size() == 4);
    BOOST_CHECK(msg.parts().at(0).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(0).content_type().media_subtype() == "html" &&
        msg.parts().at(0).content_transfer_encoding() == mime::content_transfer_encoding_t::BIT_7 && msg.parts().at(0).content_type().charset() == "us-ascii" && msg.parts().at(0).content() ==
        "<html><head></head><body><h1>Hello, World!</h1><p>Hello World!</p><p>Hello aga\r\n"
        "in!</p><p>Anyone there?</p><p>Yabba Dabba Doo!</p></body></html>");
    BOOST_CHECK(msg.parts().at(1).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(1).content_type().media_subtype() == "plain" &&
        msg.parts().at(1).content_transfer_encoding() == mime::content_transfer_encoding_t::BASE_64 && msg.parts().at(1).content_type().charset() == "us-ascii"
        && msg.parts().at(1).content() ==
        "This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.\r\n"
        "\r\n"
        "\r\n");
    BOOST_CHECK(msg.parts().at(2).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(2).content_type().media_subtype() == "plain" &&
        msg.parts().at(2).content_transfer_encoding() == mime::content_transfer_encoding_t::QUOTED_PRINTABLE &&
        msg.parts().at(2).content_type().charset() == "us-ascii" && msg.parts().at(2).content() ==
        "This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.");
    BOOST_CHECK(msg.parts().at(3).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(3).content_type().media_subtype() == "plain" &&
        msg.parts().at(3).content_transfer_encoding() == mime::content_transfer_encoding_t::QUOTED_PRINTABLE &&
        msg.parts().at(3).content_type().charset() == "utf-8" && msg.parts().at(3).content() ==
        "This is a very long message that has blank lines and very long lines. It is not clear how the text will wrap\r\n"
        "so I hope this text shows that.\r\n"
        "\r\n"
        "We should see how common mail clients wrap text, and based on that adjust message formatting. Maybe there is no need, because libmailxx is not meant to\r\n"
        "format text.\r\n"
        "\r\n"
        "In any case, after checking ASCII we should also check UTF-8 characters and see how wrapping behaves when characters are multi-byte. It should not matter whether the encoding\r\n"
        "is base64 or quoted printable, because ASCII characters wrap into new lines. This test should show whether there are bugs in the formatting logic,\r\n"
        "and the same should be checked when parsing.\r\n"
        "\r\n"
        "\r\n"
        "\r\n"
        "Here is also a check for a sequence of blank lines.");
}

BOOST_AUTO_TEST_CASE(parse_multipart_content)
{
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>, <qwerty@gmail.com>, Sylvain Guinebert <asdfgh@outlook.com>\r\n"
        "Date: Fri, 17 Jan 2014 05:39:22 -0730\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/alternative; boundary=\"my_bound\"\r\n"
        "Content-ID: <zero@mailxx.dev>\r\n"
        "Subject: parse multipart content\r\n"
        "\r\n"
        "This is a multipart message.\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Content-ID: <first@mailxx.dev>\r\n"
        "\r\n"
        "PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5PjxoMT5IZWxsbywgV29ybGQhPC9oMT48L2JvZHk+PC9odG1sPg==\r\n"
        "\r\n"
        "--my_bound\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: Quoted-Printable\r\n"
        "Content-ID: <second@mailxx.dev>\r\n"
        "\r\n"
        "Hello, World!\r\n"
        "--my_bound--\r\n";
    BOOST_REQUIRE(msg.parse(msg_str));
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    auto from_res = msg.from_to_string();
    BOOST_REQUIRE(from_res);
    BOOST_CHECK(msg.subject() == "parse multipart content" && msg.content() == "This is a multipart message." && msg.content_type().boundary() == "my_bound" &&
        msg.date_time() == ldt && *from_res == "mailxx <address@mailxx.dev>" && msg.recipients().addresses.size() == 3 &&
        msg.content_type().media_type() == mime::media_type_t::MULTIPART && msg.content_type().media_subtype() == "alternative" && msg.parts().size() == 2 &&
        msg.content_id() == "<zero@mailxx.dev>");
    BOOST_CHECK(msg.parts().at(0).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(0).content_type().media_subtype() == "html" &&
        msg.parts().at(0).content_transfer_encoding() == mime::content_transfer_encoding_t::BASE_64 &&
        msg.parts().at(0).content_type().charset() == "utf-8" && msg.parts().at(0).content_id() == "<first@mailxx.dev>" &&
        msg.parts().at(0).content() == "<html><head></head><body><h1>Hello, World!</h1></body></html>");
    BOOST_CHECK(msg.parts().at(1).content_type().media_type() == mime::media_type_t::TEXT && msg.parts().at(1).content_type().media_subtype() == "plain" &&
        msg.parts().at(1).content_transfer_encoding() == mime::content_transfer_encoding_t::QUOTED_PRINTABLE &&
        msg.parts().at(1).content_type().charset() == "utf-8" && msg.parts().at(1).content_id() == "<second@mailxx.dev>" &&
        msg.parts().at(1).content() == "Hello, World!");
}


/**
Parsing attachments of a message.

The message is formatted by the library itself.

@pre  Files `cv.txt` and `aleph0.png` used for attaching files.
@post Created files `tkcv.txt` and `a0.png` as copies of `cv.txt` and `aleph0.png`.
**/
BOOST_AUTO_TEST_CASE(parse_attachment)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("parse attachment");
    ifstream ifs1("cv.txt");
    message::content_type_t ct1(message::media_type_t::APPLICATION, "txt");
    auto tp1 = make_tuple(std::ref(ifs1), "tkcv.txt", ct1);
    ifstream ifs2("aleph0.png", std::ios_base::binary);
    message::content_type_t ct2(message::media_type_t::IMAGE, "png");
    auto tp2 = make_tuple(std::ref(ifs1), "a0.png", ct2);
    list<tuple<std::istream&, string_t, message::content_type_t>> atts;
    atts.push_back(tp1);
    atts.push_back(tp2);
    BOOST_REQUIRE(msg.attach(atts));

    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    message msg_msg;
    BOOST_REQUIRE(msg_msg.parse(msg_str));
    BOOST_CHECK(msg_msg.content_type().media_type() == mime::media_type_t::MULTIPART && msg_msg.content_type().media_subtype() == "mixed" &&
        msg_msg.attachments_size() == 2);
    BOOST_CHECK(msg_msg.parts().at(0).name() == "tkcv.txt" && msg_msg.parts().at(0).name().charset == "ASCII" &&
        msg_msg.parts().at(0).name().codec_type == codec::codec_t::ASCII && msg_msg.parts().at(0).content_type().media_type() == message::media_type_t::APPLICATION &&
        msg_msg.parts().at(0).content_type().media_subtype() == "txt");
    BOOST_CHECK(msg_msg.parts().at(1).name() == "a0.png" && msg_msg.parts().at(1).content_type().media_type() == message::media_type_t::IMAGE &&
        msg_msg.parts().at(1).content_type().media_subtype() == "png");

    const char* CV_FILE = "tkcv.txt";
    ofstream ofs1(CV_FILE);
    string_t ofs1_name;
    BOOST_REQUIRE(msg_msg.attachment(1, ofs1, ofs1_name));
    ofs1.close();
    BOOST_CHECK(ofs1_name == "tkcv.txt");

    const char* A0_FILE = "a0.png";
    ofstream ofs2(A0_FILE, std::ios_base::binary);
    string_t ofs2_name;
    BOOST_REQUIRE(msg_msg.attachment(2, ofs2, ofs2_name));
    ofs2.close();
    BOOST_CHECK(ofs2_name == "a0.png");

    std::remove(CV_FILE);
    std::remove(A0_FILE);
}


/**
Parsing attachments and an HTML content of a message.

@pre  Files `cv.txt` and `aleph0.png` used for attaching files.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_html_attachment)
{
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.date_time(ldt);
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.reply_address(mail_address("Sylvain Guinebert", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("parse html attachment");
    msg.content_type(message::media_type_t::TEXT, "html", "utf-8");
    msg.content_type().boundary("mybnd");
    msg.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
    msg.content("<h1>Title</h1><p>This is a message.</p>");

    ifstream ifs1("cv.txt");
    message::content_type_t ct1(message::media_type_t::APPLICATION, "txt");
    auto tp1 = std::make_tuple(std::ref(ifs1), "tkcv.txt", ct1);
    ifstream ifs2("aleph0.png", std::ios_base::binary);
    message::content_type_t ct2(message::media_type_t::IMAGE, "png");
    auto tp2 = std::make_tuple(std::ref(ifs2), "a0.png", ct2);
    list<tuple<std::istream&, string_t, message::content_type_t>> atts;
    atts.push_back(tp1);
    atts.push_back(tp2);

    BOOST_REQUIRE(msg.attach(atts));
    string msg_str;
    BOOST_REQUIRE(msg.format(msg_str));
    message msg_msg;
    BOOST_REQUIRE(msg_msg.parse(msg_str));
    BOOST_CHECK(msg_msg.content_type().media_type() == mime::media_type_t::MULTIPART && msg_msg.content_type().media_subtype() == "mixed" && msg_msg.attachments_size() == 2);
    BOOST_CHECK(msg_msg.parts().at(0).content() == "<h1>Title</h1><p>This is a message.</p>" && msg_msg.parts().at(0).content_type().media_type() ==
        mime::media_type_t::TEXT && msg_msg.parts().at(0).content_type().media_subtype() == "html");
    BOOST_CHECK(msg_msg.parts().at(1).name() == "tkcv.txt" && msg_msg.parts().at(1).content_type().media_type() ==
        message::media_type_t::APPLICATION && msg_msg.parts().at(1).content_type().media_subtype() == "txt");
    BOOST_CHECK(msg_msg.parts().at(2).name() == "a0.png" && msg_msg.parts().at(2).content_type().media_type() ==
        message::media_type_t::IMAGE && msg_msg.parts().at(2).content_type().media_subtype() == "png");
}


/**
Parsing attachments with UTF-8 names.

@pre  None.
@post None.
@todo Shows that the attachment name charset is not properly set.
**/
BOOST_AUTO_TEST_CASE(parse_attachment_utf8)
{
    string msg_str =
        "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"mybnd\"\r\n"
        "Subject: parse attachment utf8\r\n"
        "\r\n"
        "--mybnd\r\n"
        "Content-Type: text/plain; \r\n"
        "  name=\"=?UTF-8?B?VG9taXNsYXZLYXJhc3RvamtvdmnEh19DVi50eHQ=?=\"\r\n"
        "Content-Transfer-Encoding: Base64\r\n"
        "Content-Disposition: attachment; \r\n"
        "  filename=\"=?UTF-8?B?VG9taXNsYXZLYXJhc3RvamtvdmnEh19DVi50eHQ=?=\"\r\n"
        "\r\n"
        "VGhpcyBpcyBteSByZXN1bWUuIAo=\r\n"
        "\r\n"
        "--mybnd--\r\n";
    message msg;
    BOOST_REQUIRE(msg.parse(msg_str));
    const char* CV_FILE = "tkcv.txt";
    ofstream att_file(CV_FILE);
    string_t att_name;
    BOOST_REQUIRE(msg.attachment(1, att_file, att_name));
    att_file.close();
    BOOST_CHECK(att_name == msg.parts()[0].name() && att_name == "SylvainGuinebert_CV.txt" && att_name.charset == codec::CHARSET_UTF8 &&
        att_name.codec_type == codec::codec_t::BASE64);

    ofstream ofs(CV_FILE);
    BOOST_CHECK_EQUAL(!ofs, false);
    ofs.close();
    std::remove(CV_FILE);
}


/**
Parsing a message with the recipents and CC recipients in several lines.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_multilined_addresses)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <contact@mailxx.dev>\r\n"
        "To: contact <contact@mailxx.dev>,\r\n"
        "  Sylvain Guinebert <address@mailxx.dev>,\r\n"
        "  Sylvain Guinebert <qwerty@gmail.com>,\r\n"
        "  Sylvain Guinebert <asdfg@zoho.com>,\r\n"
        "Cc: mail.io <address@mailxx.dev>,\r\n"
        "  Sylvain Guinebert <zxcvb@yahoo.com>\r\n"
        "Date: Wed, 23 Aug 2017 22:16:45 +0000\r\n"
        "Subject: Hello, World!\r\n"
        "\r\n"
        "Hello, World!\r\n";

    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.from().addresses.at(0).name == "mailxx" && msg.from().addresses.at(0).address == "address@mailxx.dev" &&
        msg.recipients().addresses.at(0).name == "contact" && msg.recipients().addresses.at(0).address == "contact@mailxx.dev" &&
        msg.recipients().addresses.at(1).name == "Sylvain Guinebert" && msg.recipients().addresses.at(1).address == "address@mailxx.dev" &&
        msg.recipients().addresses.at(2).name == "Sylvain Guinebert" && msg.recipients().addresses.at(2).address == "qwerty@gmail.com" &&
        msg.recipients().addresses.at(3).name == "Sylvain Guinebert" && msg.recipients().addresses.at(3).address == "asdfg@zoho.com" &&
        msg.cc_recipients().addresses.at(0).name == "mail.io" && msg.cc_recipients().addresses.at(0).address == "address@mailxx.dev" &&
        msg.cc_recipients().addresses.at(1).name == "Sylvain Guinebert" && msg.cc_recipients().addresses.at(1).address == "zxcvb@yahoo.com");
}


/**
Parsing a message with the recipients in a long line.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_long_addresses)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "Reply-To: Sylvain Guinebert <contact@mailxx.dev>\r\n"
        "To: contact <contact@mailxx.dev>, Sylvain Guinebert <address@mailxx.dev>, Sylvain Guinebert <qwerty@gmail.com>, "
        "  Sylvain Guinebert <asdfg@zoho.com>\r\n"
        "Cc: mail.io <address@mailxx.dev>, Sylvain Guinebert <zxcvb@yahoo.com>\r\n"
        "Date: Wed, 23 Aug 2017 22:16:45 +0000\r\n"
        "Subject: Hello, World!\r\n"
        "\r\n"
        "Hello, World!\r\n";

    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.from().addresses.at(0).name == "mailxx" && msg.from().addresses.at(0).address == "address@mailxx.dev" &&
        msg.recipients().addresses.at(0).name == "contact" && msg.recipients().addresses.at(0).address == "contact@mailxx.dev" &&
        msg.recipients().addresses.at(1).name == "Sylvain Guinebert" && msg.recipients().addresses.at(1).address == "address@mailxx.dev" &&
        msg.recipients().addresses.at(2).name == "Sylvain Guinebert" && msg.recipients().addresses.at(2).address == "qwerty@gmail.com" &&
        msg.recipients().addresses.at(3).name == "Sylvain Guinebert" && msg.recipients().addresses.at(3).address == "asdfg@zoho.com" &&
        msg.cc_recipients().addresses.at(0).name == "mail.io" && msg.cc_recipients().addresses.at(0).address == "address@mailxx.dev" &&
        msg.cc_recipients().addresses.at(1).name == "Sylvain Guinebert" && msg.cc_recipients().addresses.at(1).address == "zxcvb@yahoo.com");
}


/**
Parsing a message with the disposition notification.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_notification)
{
    string msg_str = "From: karastojko <qwerty@gmail.com>\r\n"
        "To: karastojko <asdfg@hotmail.com>\r\n"
        "Disposition-Notification-To: karastojko <zxcvb@zoho.com>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: parse notification\r\n"
        "\r\n"
        "Hello, World!\r\n";
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    auto disp_res = msg.disposition_notification_to_string();
    BOOST_REQUIRE(disp_res);
    BOOST_CHECK(*disp_res == "karastojko <zxcvb@zoho.com>" && msg.subject() == "parse notification");
}


/**
Parsing a message with Q/Quoted Printable encoded sender.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_qq_sender)
{
    string msg_str = "From: =?UTF-8?Q?mailio?= <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>, \r\n"
        "    =?UTF-8?Q?Sylvain_Guinebert?= <qwerty@gmail.com>, \r\n"
        "    =?UTF-8?Q?Sylvain_Guinebert?= <asdfg@zoho.com>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: test\r\n"
        "\r\n"
        "test\r\n";

    {
        message msg;
        msg.line_policy(codec::line_len_policy_t::MANDATORY);
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.from().addresses.at(0).name == "mailio" &&
            msg.from().addresses.at(0).name.charset == "UTF-8" &&
            msg.from().addresses.at(0).name.codec_type == codec::codec_t::QUOTED_PRINTABLE &&
            msg.from().addresses.at(0).address == "address@mailxx.dev" &&
            msg.recipients().addresses.at(0).name.buffer == "mailxx" &&
            msg.recipients().addresses.at(0).address == "address@mailxx.dev" &&
            msg.recipients().addresses.at(1).name == "Sylvain Guinebert" &&
            msg.recipients().addresses.at(1).name.charset == "UTF-8" &&
            msg.recipients().addresses.at(1).name.codec_type == codec::codec_t::QUOTED_PRINTABLE &&
            msg.recipients().addresses.at(1).address == "qwerty@gmail.com"&&
            msg.recipients().addresses.at(2).name == "Sylvain Guinebert" &&
            msg.recipients().addresses.at(2).name.charset == "UTF-8" &&
            msg.recipients().addresses.at(2).name.codec_type == codec::codec_t::QUOTED_PRINTABLE &&
            msg.recipients().addresses.at(2).address == "asdfg@zoho.com");
    }
    {
        message msg;
        msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
        BOOST_CHECK(!msg.parse(msg_str));
    }
}


/**
Parsing a message with Q/Base64 encoded sender.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_qb_sender)
{
    string msg_str = "From: =?UTF-8?B?bWFpbGlv?= <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: test\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "\r\n"
        "test\r\n";
    message msg;
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.from().addresses.at(0).name == "mailio" &&
        msg.from().addresses.at(0).name.charset == "UTF-8" &&
        msg.from().addresses.at(0).name.codec_type == codec::codec_t::BASE64);
}


/**
Parsing a message with sender's name Q encoded not separated by space from the address.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_qq_from_no_space)
{
    string msg_str = "From: =?windows-1252?Q?Action_English?=<address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: exam\r\n"
        "\r\n"
        "test\r\n";

    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.from().addresses.at(0).name == "Action English" &&
        msg.from().addresses.at(0).name.charset == "WINDOWS-1252" &&
        msg.from().addresses.at(0).name.codec_type == codec::codec_t::QUOTED_PRINTABLE &&
        msg.from().addresses.at(0).address == "address@mailxx.dev");
}


/**
Parsing a message with Q/Base64 encoded subject with the UTF-8 charset.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_qb_utf8_subject)
{
    string msg_str = "From: mail io <adre.sa@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: =?UTF-8?B?UmU6IEhlbGxvLCBXb3JsZCEgU3VtbWVyIDIwMTc=?=\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "\r\n"
        "hello world\r\n";
    message msg;

    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    BOOST_REQUIRE(msg.parse(msg_str));
    auto recipients_res = msg.recipients_to_string();
    BOOST_REQUIRE(recipients_res);
    BOOST_CHECK(msg.from().addresses.at(0).name == "mail io" && msg.from().addresses.at(0).address == "adre.sa@mailxx.dev" && msg.date_time() == ldt &&
        *recipients_res == "mailxx <address@mailxx.dev>" && msg.subject_raw().buffer == "Re: Hello, World! Summer 2017" &&
        msg.subject_raw().charset == "UTF-8" && msg.subject_raw().codec_type == codec::codec_t::BASE64 && msg.content() == "hello world");
}


/**
Parsing a message with Q/Base64 encoded subject in the ISO-8859-1 charset by using the mailxx string type.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_qq_latin1_subject_raw)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: =?iso-8859-1?Q?Hello_World_CV?=\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "\r\n"
        "hello world\r\n";
    message msg;

    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    BOOST_REQUIRE(msg.parse(msg_str));
    auto recipients_res = msg.recipients_to_string();
    BOOST_REQUIRE(recipients_res);
    BOOST_CHECK(msg.from().addresses.at(0).name == "mailxx" && msg.from().addresses.at(0).address == "address@mailxx.dev" && msg.date_time() == ldt &&
        *recipients_res == "mailxx <address@mailxx.dev>" && msg.subject_raw().buffer == "Hello World CV" &&
        msg.subject_raw().charset == "ISO-8859-1" && msg.subject_raw().codec_type == codec::codec_t::QUOTED_PRINTABLE && msg.content() == "hello world");
}


/**
Parsing a subject and checking the result against `string_t`.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_qq_utf8_emoji_subject_raw)
{
    string msg_str = "From: \"Sylvain Guinebert\" <qwerty@gmail.com>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: =?utf-8?Q?Hello,_World!_One_Year_on_Super_Card?=\r\n"
        "Date: Fri, 24 Dec 2021 15:15:38 +0000\r\n"
        "Content-Type: text/plain; charset=\"UTF-8\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "SGVsbG8sIFdvcmxkIQ0K";

    {
        message msg;
        msg.line_policy(codec::line_len_policy_t::MANDATORY);
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.subject_raw() == string_t("Hello, World! One Year on Super Card", "utf-8", codec::codec_t::QUOTED_PRINTABLE));
    }
    {
        message msg;
        msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
        BOOST_CHECK(!msg.parse(msg_str));
    }
}


/**
Parsing a message with Q/Quoted Printable encoded long subject.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_qq_long_subject)
{
    string msg_str = "From: mail io <adre.sa@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: =?UTF-8?Q?HELLO_WORLD_COMPUTER_PROGRAMMING_ALEPHO_BELGRADE_TRAINI?=\r\n"
        "    =?UTF-8?Q?NG_COURSE?=\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "\r\n"
        "hello\r\n"
        "\r\n"
        "world\r\n"
        "\r\n"
        "\r\n"
        "hello again\r\n";
    message msg;

    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    auto recipients_res = msg.recipients_to_string();
    BOOST_REQUIRE(recipients_res);
    BOOST_CHECK(msg.from().addresses.at(0).name == "mail io" && msg.from().addresses.at(0).address == "adre.sa@mailxx.dev" && msg.date_time() == ldt &&
        *recipients_res == "mailxx <address@mailxx.dev>" &&
        msg.subject_raw() == string_t("HELLO WORLD COMPUTER PROGRAMMING ALEPHO BELGRADE TRAINING COURSE", "utf-8", codec::codec_t::QUOTED_PRINTABLE) &&
        msg.content() == "hello\r\n\r\nworld\r\n\r\n\r\nhello again");
}


/**
Parsing a message with Q/Base64 encoded long subject.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_qb_long_subject)
{
    string msg_str = "From: mail io <adre.sa@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: =?UTF-8?B?UmU6IEhlbGxvLCBXb3JsZCEgUmVxdWVzdCBmcm9tIEV4YW1wbGUgVmlz?=\r\n"
        "  =?UTF-8?B?aXRvciAtIFNhbXBsZSBBcGFydG1lbnRz?=\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "\r\n"
        "hello\r\n"
        "\r\n"
        "world\r\n"
        "\r\n"
        "\r\n"
        "hello again\r\n";

    {
        message msg;
        auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
        msg.line_policy(codec::line_len_policy_t::MANDATORY);
        BOOST_REQUIRE(msg.parse(msg_str));
        auto recipients_res = msg.recipients_to_string();
        BOOST_REQUIRE(recipients_res);
        BOOST_CHECK(msg.from().addresses.at(0).name == "mail io" && msg.from().addresses.at(0).address == "adre.sa@mailxx.dev" && msg.date_time() == ldt &&
            *recipients_res == "mailxx <address@mailxx.dev>" &&
            msg.subject_raw() == string_t("Re: Hello, World! Request from Example Visitor - Sample Apartments", "utf-8", codec::codec_t::BASE64) &&
            msg.content() == "hello\r\n\r\nworld\r\n\r\n\r\nhello again");
    }
    {
        message msg;
        msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
        BOOST_CHECK(!msg.parse(msg_str));
    }
}


/**
Parsing a message with mixed Q/Quoted Printable and Q/Base64 long subject.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_qbq_long_subject)
{
    string msg_str = "From: mail io <adre.sa@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: =?UTF-8?B?UmU6IEhlbGxvLCBXb3JsZCEgUmVxdWVzdCBmcm9tIEV4YW1wbGUgVmlz?=\r\n"
        " =?UTF-8?Q?itor_-_Sample_Apartments?=\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "\r\n"
        "hello\r\n"
        "\r\n"
        "world\r\n"
        "\r\n"
        "\r\n"
        "hello again\r\n";
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    auto recipients_res = msg.recipients_to_string();
    BOOST_REQUIRE(recipients_res);
    BOOST_CHECK(msg.from().addresses.at(0).name == "mail io" && msg.from().addresses.at(0).address == "adre.sa@mailxx.dev" && msg.date_time() == ldt &&
        *recipients_res == "mailxx <address@mailxx.dev>" &&
        msg.subject_raw() == string_t("Re: Hello, World! Request from Example Visitor - Sample Apartments", "UTF-8", codec::codec_t::QUOTED_PRINTABLE) &&
        msg.content() == "hello\r\n\r\nworld\r\n\r\n\r\nhello again");
}


/**
Parsing a message with UTF-8 subject containing the long dash character.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_qq_subject_dash)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?UTF-8?Q?C++_Annotated:_Sep_-_Dec_2017?=\r\n"
        "\r\n"
        "test\r\n";
    message msg;
    auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.subject() == "C++ Annotated: Sep - Dec 2017");
}


/**
Parsing a message with UTF-8 subject containing an emoji character.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_qq_subject_emoji)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?utf-8?Q?Hello,_World!_One_Year_on_Super_Card?=\r\n"
        "\r\n"
        "test\r\n";
    {
        message msg;
        auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
        msg.line_policy(codec::line_len_policy_t::MANDATORY);
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.subject_raw().buffer == "Hello, World! One Year on Super Card" && msg.subject_raw().charset == "UTF-8" &&
            msg.subject_raw().codec_type == codec::codec_t::QUOTED_PRINTABLE);
    }
    {
        message msg;
        msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
        BOOST_CHECK(!msg.parse(msg_str));
    }
}


/**
Parsing a long subject.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_qq_subject_long)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?utf-8?Q?Hello,_World!_Happy_holidays_and_best_wishes_to_everyone?=\r\n"
        "\r\n"
        "test\r\n";
    {
        message msg;
        auto ldt = make_zoned_time(2016, 2, 11, 22, 56, 22, 0, 0);
        msg.line_policy(codec::line_len_policy_t::MANDATORY);
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.subject() == "Hello, World! Happy holidays and best wishes to everyone");
    }
    {
        message msg;
        msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
        BOOST_CHECK(!msg.parse(msg_str));
    }
}


/**
Parsing a UTF8 subject in the eight bit encoding.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_utf8_subject)
{
    string msg_str = "From: \"Sylvain Guinebert\" <qwerty@gmail.com>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: Hello, World!\r\n"
        "Date: Fri, 24 Dec 2021 15:15:38 +0000\r\n"
        "Content-Type: text/plain; charset=\"UTF-8\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "SGVsbG8sIFdvcmxkIQ0K";

    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.subject() == "Hello, World!");
}


/**
Parsing a UTF8 sender with the quoted name in the eight bit encoding.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_utf8_quoted_name)
{
    string msg_str = "From: \"Sylvain Guinebert\" <qwerty@gmail.com>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: Test for UTF8\r\n"
        "Date: Fri, 24 Dec 2021 15:15:38 +0000\r\n"
        "Content-Type: text/plain; charset=\"UTF-8\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "SGVsbG8sIFdvcmxkIQ0K";

    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.from().addresses.at(0).name == "Sylvain Guinebert" && msg.from().addresses.at(0).address == "qwerty@gmail.com");
}


/**
Parsing a UTF8 recipient with the quoted name in the eight bit encoding.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_utf8_name)
{
    string msg_str = "From: Sylvain Guinebert <qwerty@gmail.com>\r\n"
        "To: \"Sylvain Guinebert\" <qwerty@gmail.com>\r\n"
        "Subject: Hello, World!\r\n"
        "Date: Fri, 24 Dec 2021 15:15:38 +0000\r\n"
        "Content-Type: text/plain; charset=\"UTF-8\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "SGVsbG8sIFdvcmxkIQ0K";

    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.recipients().addresses.at(0).name == "Sylvain Guinebert" && msg.recipients().addresses.at(0).address == "qwerty@gmail.com");
    BOOST_CHECK(msg.subject() == "Hello, World!");
}


/**
Parsing UTF8 sender with the address in the eight bit encoding.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_utf8_address)
{
    string msg_str = "From: Sylvain Guinebert <Guinebert@gmail.com>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: Test for UTF8\r\n"
        "Date: Fri, 24 Dec 2021 15:15:38 +0000\r\n"
        "Content-Type: text/plain; charset=\"UTF-8\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "SGVsbG8sIFdvcmxkIQ0K";

    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.from().addresses.at(0).name == "Sylvain Guinebert" && msg.from().addresses.at(0).address == "Guinebert@gmail.com");
    auto from_res = msg.from_to_string();
    BOOST_REQUIRE(from_res);
    BOOST_CHECK(*from_res == "Sylvain Guinebert <Guinebert@gmail.com>" && msg.content() == "Hello, World!\r\n");
}


/**
Parsing Q encoded recipient with the missing charset.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_q_subject_missing_charset)
{
    string msg_str = "From: =??Q?mailio?= <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: test\r\n"
        "\r\n"
        "test\r\n";

    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing Q encoded recipient with the missing codec type.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_q_subject_missing_codec)
{
    string msg_str = "From: =?UTF-8\?\?mailio?= <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: test\r\n"
        "\r\n"
        "test\r\n";

    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing a message with several codecs in the header.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_many_codecs)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: =?UTF-8?Q?mailio?= <address@mailxx.dev>,\r\n"
        "  =?UTF-8?B?VG9taXNsYXYgS2FyYXN0b2prb3ZpYw==?=\r\n"
        "  <qwertyuiop@zoho.com>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: =?UTF-8?B?UmU6IEhlbGxvLCBXb3JsZCEgUmVxdWVzdCBmcm9tIEV4YW1wbGUgVmlz?=\r\n"
        " =?UTF-8?B?aXRvciAtIFNhbXBsZSBBcGFydG1lbnRz?=\r\n"
        "\r\n"
        "Hello, World!\r\n";
    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.from().addresses.at(0).name == "mailxx" && msg.from().addresses.at(0).address == "address@mailxx.dev");
    BOOST_CHECK(msg.recipients().addresses.at(0).name == "mailio" && msg.recipients().addresses.at(0).address == "address@mailxx.dev");
    BOOST_CHECK(msg.recipients().addresses.at(1).name == "Sylvain Guinebert" && msg.recipients().addresses.at(1).address == "qwertyuiop@zoho.com");
    BOOST_CHECK(msg.subject() == "Re: Hello, World! Request from Example Visitor - Sample Apartments");
}


/**
Parsing the message ID.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_message_id)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Message-ID: <1234567890@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Content-ID: <987654321@mailxx.dev>\r\n"
        "Subject: Test\r\n"
        "\r\n"
        "Hello, World!\r\n";

    {
        // strict mode
        message msg;
        msg.strict_mode(true);
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.message_id() == "1234567890@mailxx.dev" && msg.content_id() == "987654321@mailxx.dev");
    }
    {
        // non-strict mode
        message msg;
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.message_id() == "<1234567890@mailxx.dev>" && msg.content_id() == "<987654321@mailxx.dev>");
    }
}


/**
Parsing the message ID consisting only of spaces.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_whitespace_message_id)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Message-ID:    \r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Test\r\n"
        "\r\n"
        "Hello, World!\r\n";
    message msg;
    BOOST_REQUIRE(msg.parse(msg_str));
    BOOST_CHECK(msg.message_id().empty() == true);
}


/**
Parsing the empty message ID.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_empty_message_id)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Message-ID:\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Test\r\n"
        "\r\n"
        "Hello, World!\r\n";
    message msg;
    BOOST_REQUIRE(msg.parse(msg_str));
}


/**
Parsing few message IDs.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_few_message_ids)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Message-ID: <1@mailxx.dev><2@mailxx.dev>   <3@mailxx.dev>    <4@mailxx.dev>   \r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Test\r\n"
        "\r\n"
        "Hello, World!\r\n";
    {
        message msg;
        msg.strict_mode(true);
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.message_id() == "1@mailxx.dev");
    }
    {
        message msg;
        msg.strict_mode(false);
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.message_id() == "<1@mailxx.dev><2@mailxx.dev>   <3@mailxx.dev>    <4@mailxx.dev>");
    }
}


/**
Parsing a message with the in-reply-to IDs.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_in_reply_to)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "In-Reply-To: <1@mailxx.dev> <22@mailxx.dev> <333@mailxx.dev>\r\n"
        "References: <4444@mailxx.dev> <55555@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Test\r\n"
        "\r\n"
        "Hello, World!\r\n";
    {
        message msg;
        msg.strict_mode(true);
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.in_reply_to().size() == 3 && msg.in_reply_to().at(0) == "1@mailxx.dev" && msg.in_reply_to().at(1) == "22@mailxx.dev" &&
            msg.in_reply_to().at(2) == "333@mailxx.dev" && msg.references().at(0) == "4444@mailxx.dev" && msg.references().at(1) == "55555@mailxx.dev");
    }
    {
        message msg;
        msg.strict_mode(false);
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.in_reply_to().size() == 1 && msg.in_reply_to().at(0) == "<1@mailxx.dev> <22@mailxx.dev> <333@mailxx.dev>" &&
            msg.references().size() == 1 && msg.references().at(0) == "<4444@mailxx.dev> <55555@mailxx.dev>");
    }
}


/**
Parsing the message ID without the monkey character.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_in_reply_without_monkey)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "In-reply-To: <1@mailxx.dev> <2 mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Test\r\n"
        "\r\n"
        "Hello, World!\r\n";
    {
        message msg;
        msg.strict_mode(true);
        BOOST_CHECK(!msg.parse(msg_str));
    }
    {
        message msg;
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.in_reply_to().size() == 1 && msg.in_reply_to().at(0) == "<1@mailxx.dev> <2 mailxx.dev>");
    }
}


/**
Parsing the message ID without the angle brackets.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_references_without_brackets)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "References: <1@mailxx.dev> 2@mailxx.dev\r\n"
        "In-reply-To: <3@mailxx.dev> <4@mailxx.dev>\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Test\r\n"
        "\r\n"
        "Hello, World!\r\n";
    {
        message msg;
        msg.strict_mode(true);
        BOOST_CHECK(!msg.parse(msg_str));
    }
    {
        message msg;
        msg.strict_mode(false);
        BOOST_REQUIRE(msg.parse(msg_str));
        BOOST_CHECK(msg.references().size() == 1);
    }
}


/**
Parsing an empty header in the strict mode.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_empty_header_strict)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "User-Agent:\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Test\r\n"
        "\r\n"
        "Hello, World!\r\n";
    message msg;
    msg.strict_mode(true);
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing the empty header in the non-strict mode.

@pre  None.
@post None.
@todo MSVC is not working well if headers are not copied, see below.
**/
BOOST_AUTO_TEST_CASE(parse_empty_header_relaxed)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "User-Agent:\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Test\r\n"
        "Hello: World\r\n"
        "\r\n"
        "Hello, World!\r\n";
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    // If the headers in tests are accessed without copying, then for some reason the multimap often does not read the individual headers
    // properly. Not sure what is the reason for this behavior, Gcc works fine.
    auto headers = msg.headers();
    BOOST_CHECK(headers.size() == 2);
    BOOST_CHECK(msg.subject() == "Test");
    BOOST_CHECK(headers.count("User-Agent") == 1 && headers.count("Hello") == 1);
    auto user_agent = headers.find("User-Agent");
    BOOST_CHECK(user_agent->first == "User-Agent" && user_agent->second.empty());
    auto hello = headers.find("Hello");
    BOOST_CHECK(hello->first == "Hello" && hello->second == "World");
}


/**
Parsing an empty header with a wrong header name.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_wrong_empty_header)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "User Agent:\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Test\r\n"
        "\r\n"
        "Hello, World!\r\n";
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_CHECK(!msg.parse(msg_str));
}


/**
Parsing a header with horizontal tabs.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_headers_htab)
{
    string msg_str = "From: mail io <test@sender.com>\r\n"
        "To: \tmail io <test@sender.com>\r\n"
        "Date: Sat, 18 Jun 2022 05:56:34 +0000\r\n"
        "Received: from SRV2 - test@sender.com\r\n"
        " (srv2 - test@sender.com[192.168.245.16])\tby\r\n"
        " smtp - 01.test@sender.com(Postfix) with ESMTP id 8D16C3CE\tfor\r\n"
        " <test@receiver.com>; Sat, 20 Aug 2022 11:01 : 35 + 0200\r\n"
        " (CEST)\r\n"
        "Subject: Hello, World!\r\n"
        "\r\n"
        "Hello, World!\r\n";
    message msg;
    msg.line_policy(mailxx::codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    auto hdrs = msg.headers();
    auto rcv = hdrs.find("Received");
    BOOST_CHECK(rcv != hdrs.end());
}


/**
Parsing a header by ignoring the letter case.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(parse_icase_header)
{
    string msg_str = "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "User-Agent: mailxx\r\n"
        "Date: Thu, 11 Feb 2016 22:56:22 +0000\r\n"
        "Subject: Test\r\n"
        "Hello: World\r\n"
        "\r\n"
        "Hello, World!\r\n";
    message msg;
    msg.line_policy(codec::line_len_policy_t::MANDATORY);
    BOOST_REQUIRE(msg.parse(msg_str));
    auto headers = msg.headers();
    auto user_agent = headers.find("User-Agent");
    BOOST_CHECK(user_agent->first == "USER-AGENT" && user_agent->second == "mailxx");
    auto hello_world = headers.find("HELLO");
    BOOST_CHECK(hello_world->first == "Hello" && hello_world->second == "World");
}


/**
Copying the message by using the constructor and the assignment operator.

@pre  None.
@post None.
**/
BOOST_AUTO_TEST_CASE(object_copying)
{
    message msg1;
    msg1.from(mail_address("mailxx", "address@mailxx.dev"));
    msg1.reply_address(mail_address("Sylvain Guinebert", "contact@mailxx.dev"));
    msg1.add_recipient(mail_address("contact", "contact@mailxx.dev"));
    msg1.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg1.add_recipient(mail_group("all", {mail_address("Sylvain", "qwerty@hotmail.com")}));
    msg1.add_cc_recipient(mail_group("mailxx", {mail_address("", "karas@mailxx.dev"), mail_address("Sylvain Guinebert", "contact@mailxx.dev")}));
    msg1.add_cc_recipient(mail_address("Sylvain Guinebert", "contact@mailxx.dev"));
    msg1.add_cc_recipient(mail_address("Sylvain @ Guinebert", "asdfg@gmail.com"));
    msg1.add_cc_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg1.add_cc_recipient(mail_group("all", {mail_address("", "qwerty@hotmail.com"), mail_address("Sylvain", "asdfg@gmail.com"),
        mail_address("Sylvain @ Guinebert", "zxcvb@zoho.com")}));
    msg1.add_bcc_recipient(mail_address("Sylvain Guinebert", "contact@mailxx.dev"));
    msg1.add_bcc_recipient(mail_address("Sylvain @ Guinebert", "asdfg@gmail.com"));
    msg1.add_bcc_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg1.subject("Hello, World!");
    msg1.content("Hello, World!");
    auto ldt = make_zoned_time(2014, 1, 17, 13, 9, 22, -7, -30);
    msg1.date_time(ldt);

    string msg1_str;
    BOOST_REQUIRE(msg1.format(msg1_str));
    {
        // Test the copy constructor.

        message msg2(msg1);
        string msg2_str;
        BOOST_REQUIRE(msg2.format(msg2_str));
        BOOST_CHECK(msg1_str == msg2_str);
    }

    {
        // Test for the assignment operator.

        message msg3;
        msg3 = msg1;
        string msg3_str;
        BOOST_REQUIRE(msg3.format(msg3_str));
        BOOST_CHECK(msg1_str == msg3_str);
    }
}


#define BOOST_TEST_MODULE message_stream_format_test

#include <boost/test/included/unit_test.hpp>

#include <string>

#include <mailxx/detail/output_sink.hpp>
#include <mailxx/mime/mailboxes.hpp>
#include <mailxx/mime/message.hpp>

using mailxx::mail_address;
using mailxx::message;

BOOST_AUTO_TEST_CASE(message_format_to_inserts_header_body_separator)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("stream format separator");
    msg.content("Hello, World!");

    std::string out;
    mailxx::detail::string_sink sink(out);
    BOOST_REQUIRE(msg.format_to(sink));

    BOOST_CHECK_NE(out.find("\r\n\r\nHello, World!\r\n"), std::string::npos);

    message parsed;
    BOOST_REQUIRE(parsed.parse(out));
    BOOST_CHECK_EQUAL(parsed.subject(), "stream format separator");
    BOOST_CHECK_EQUAL(parsed.content(), "Hello, World!");
}

BOOST_AUTO_TEST_CASE(message_format_to_inserts_multipart_part_separators)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("stream multipart separator");
    msg.content("Multipart body");

    BOOST_REQUIRE(msg.attach_file(
        "aleph0.png",
        mailxx::string_t("aleph0.png"),
        message::content_type_t(message::media_type_t::IMAGE, "png")));

    std::string out;
    mailxx::detail::string_sink sink(out);
    BOOST_REQUIRE(msg.format_to(sink));

    BOOST_CHECK_NE(out.find("Content-Type: text/plain\r\n\r\nMultipart body\r\n"), std::string::npos);
    BOOST_CHECK_NE(out.find("filename=\"aleph0.png\"\r\n\r\n"), std::string::npos);

    message parsed;
    BOOST_REQUIRE(parsed.parse(out));
    BOOST_CHECK_EQUAL(parsed.subject(), "stream multipart separator");
    BOOST_CHECK_EQUAL(parsed.parts().size(), 2U);
}

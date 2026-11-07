#define BOOST_TEST_MODULE codec_headers_test

#include <string>
#include <boost/test/unit_test.hpp>
#include <mailxx/codec/bit7.hpp>
#include <mailxx/codec/bit8.hpp>
#include <mailxx/codec/base64.hpp>
#include <mailxx/codec/percent.hpp>
#include <mailxx/codec/q_codec.hpp>
#include <mailxx/mime/message.hpp>

using mailxx::bit7;
using mailxx::bit8;
using mailxx::base64;
using mailxx::codec;
using mailxx::mail_address;
using mailxx::message;
using mailxx::percent;
using mailxx::q_codec;

BOOST_AUTO_TEST_CASE(percent_does_not_split_inside_escape)
{
    percent pct(8, 8);
    const auto parts = pct.encode("a b", "utf-8");
    BOOST_REQUIRE(!parts.empty());
    std::string joined;
    for (const auto& part : parts)
    {
        BOOST_CHECK(part.find("%2") == std::string::npos || part.find("%20") != std::string::npos || part.size() < 3);
        for (std::size_t i = 0; i < part.size(); ++i)
        {
            if (part[i] != '%')
                continue;
            BOOST_REQUIRE(i + 2 < part.size());
        }
        joined += part;
    }
    percent decoder(78, 78);
    const auto language = joined.find('\'', joined.find('\'') + 1);
    BOOST_REQUIRE(language != std::string::npos);
    const auto decoded = decoder.decode(joined.substr(language + 1));
    BOOST_REQUIRE(decoded);
    BOOST_CHECK(*decoded == "a b");

    const auto bad = decoder.decode("a%");
    BOOST_CHECK(!bad);
    const auto bad_hex = decoder.decode("%ZZ");
    BOOST_CHECK(!bad_hex);
}

BOOST_AUTO_TEST_CASE(q_codec_uses_header_prefix)
{
    q_codec qc(30, 30);
    const auto words = qc.encode("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "UTF-8", codec::codec_t::BASE64, std::string("Subject: ").size());
    BOOST_REQUIRE(words);
    BOOST_REQUIRE(!words->empty());
    BOOST_CHECK(words->front().size() + std::string("Subject: ").size() <= 30);
    for (std::size_t i = 1; i < words->size(); ++i)
        BOOST_CHECK(2 + words->at(i).size() <= 30);
}

BOOST_AUTO_TEST_CASE(attribute_continuations_round_trip_and_reject_gaps)
{
    const std::string ok_msg =
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: cont\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Disposition: attachment;\r\n"
        "  filename*0*=UTF-8''Hello;\r\n"
        "  filename*1*=%20World\r\n"
        "\r\n"
        "Hi\r\n";
    message parsed;
    BOOST_REQUIRE(parsed.parse(ok_msg));
    BOOST_CHECK(parsed.name().buffer == "Hello World");
    BOOST_CHECK(parsed.name().charset == "UTF-8");

    const std::string gap_msg =
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: gap\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Disposition: attachment;\r\n"
        "  filename*0*=UTF-8''Hello;\r\n"
        "  filename*2*=%20World\r\n"
        "\r\n"
        "Hi\r\n";
    message gapped;
    BOOST_CHECK(!gapped.parse(gap_msg));
}

BOOST_AUTO_TEST_CASE(unquoted_token_and_quoted_space)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("attrs");
    msg.content("Hi");
    BOOST_REQUIRE(msg.content_type(message::media_type_t::TEXT, "plain"));
    msg.content_type().add_attribute("format", mailxx::string_t("flowed"));
    msg.content_type().add_attribute("title", mailxx::string_t("a file"));

    std::string out;
    BOOST_REQUIRE(msg.format(out));
    BOOST_CHECK(out.find("format=flowed") != std::string::npos);
    BOOST_CHECK(out.find("title=\"a file\"") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(reserved_header_is_rejected)
{
    message msg;
    BOOST_CHECK(!msg.add_header("From", "other <a@b.c>"));
    BOOST_CHECK(!msg.add_header("content-type", "text/plain"));
    BOOST_REQUIRE(msg.add_header("X-Trace", "1"));
    BOOST_CHECK(msg.headers().count("X-Trace") == 1);
}

BOOST_AUTO_TEST_CASE(strict_seven_bit_rejects_high_and_nul)
{
    bit7 strict7(78, 78);
    strict7.strict_mode(true);
    BOOST_CHECK(!strict7.encode(std::string("caf\xC3\xA9", 5)));
    BOOST_CHECK(!strict7.encode(std::string("a\0b", 3)));

    bit8 eight(78, 78);
    const auto high = eight.encode(std::string("caf\xC3\xA9", 5));
    BOOST_REQUIRE(high);
    BOOST_CHECK(!eight.encode(std::string("a\0b", 3)));

    base64 loose(20, 20);
    std::vector<std::string> long_line{"ABCDEFGHIJKLMNOPQRSTUVWXYZ"};
    BOOST_CHECK(static_cast<bool>(loose.decode(long_line)));
    base64 strict64(20, 20);
    strict64.strict_mode(true);
    BOOST_CHECK(!strict64.decode(long_line));
}

BOOST_AUTO_TEST_CASE(strict_header_rejects_raw_high_byte)
{
    const std::string raw =
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: caf\xC3\xA9\r\n"
        "\r\n"
        "Hi\r\n";
    message relaxed;
    BOOST_CHECK(relaxed.parse(raw));
    message strict;
    strict.strict_mode(true);
    BOOST_CHECK(!strict.parse(raw));

    const std::string bad_q =
        "From: mailxx <address@mailxx.dev>\r\n"
        "To: mailxx <address@mailxx.dev>\r\n"
        "Subject: =??B?QQ==?=\r\n"
        "\r\n"
        "Hi\r\n";
    message qmsg;
    BOOST_CHECK(!qmsg.parse(bad_q));
}

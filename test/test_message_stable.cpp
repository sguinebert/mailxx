#define BOOST_TEST_MODULE message_stable_test

#include <chrono>
#include <list>
#include <sstream>
#include <string>
#include <tuple>
#include <boost/test/unit_test.hpp>
#include <mailxx/mime/message.hpp>

using mailxx::codec;
using mailxx::mail_address;
using mailxx::message;
using mailxx::message_format_options_t;
using mailxx::string_t;

namespace
{

std::chrono::zoned_time<std::chrono::seconds> fixed_date()
{
    std::chrono::year_month_day ymd{std::chrono::year{2016}, std::chrono::month{2}, std::chrono::day{11}};
    auto local_tp = std::chrono::local_days{ymd} + std::chrono::hours{22} + std::chrono::minutes{56} + std::chrono::seconds{22};
    auto sys_tp = std::chrono::sys_time<std::chrono::seconds>{local_tp.time_since_epoch()};
    return std::chrono::zoned_time<std::chrono::seconds>{std::chrono::current_zone(), sys_tp};
}

std::string bytes_with_nul(std::string prefix, std::string suffix)
{
    prefix.push_back('\0');
    prefix += suffix;
    return prefix;
}

}

BOOST_AUTO_TEST_CASE(stable_format_requires_date_and_boundary)
{
    message msg;
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("stable");
    msg.content("Hello");

    message_format_options_t opts;
    opts.stable = true;
    std::string out;
    BOOST_CHECK(!msg.format(out, opts));

    msg.date_time(fixed_date());
    BOOST_REQUIRE(msg.format(out, opts));

    message multipart;
    multipart.date_time(fixed_date());
    multipart.from(mail_address("mailxx", "address@mailxx.dev"));
    multipart.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    multipart.subject("stable multipart");
    BOOST_REQUIRE(multipart.content_type(message::media_type_t::MULTIPART, "mixed"));
    std::string multipart_out;
    BOOST_CHECK(!multipart.format(multipart_out, opts));
}

BOOST_AUTO_TEST_CASE(stable_format_is_repeatable)
{
    message msg;
    msg.date_time(fixed_date());
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("stable repeat");
    msg.content("Hello, World!");

    message_format_options_t opts;
    opts.stable = true;
    std::string first;
    std::string second;
    BOOST_REQUIRE(msg.format(first, opts));
    BOOST_REQUIRE(msg.format(second, opts));
    BOOST_CHECK(first == second);
    BOOST_CHECK(first.find("\r\nDate: ") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(stable_binary_parts_round_trip)
{
    const std::string pdf = bytes_with_nul("%PDF-1.4", "trailer");
    const std::string zip = bytes_with_nul("PK\x03\x04", "entry");

    std::stringstream pdf_stream(std::ios::in | std::ios::out | std::ios::binary);
    std::stringstream zip_stream(std::ios::in | std::ios::out | std::ios::binary);
    pdf_stream.write(pdf.data(), static_cast<std::streamsize>(pdf.size()));
    zip_stream.write(zip.data(), static_cast<std::streamsize>(zip.size()));
    pdf_stream.seekg(0);
    zip_stream.seekg(0);

    message msg;
    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
    msg.date_time(fixed_date());
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("stable parts");
    msg.content("body");
    msg.content_type().boundary("stable-boundary");

    message::content_type_t pdf_type(message::media_type_t::APPLICATION, "pdf");
    message::content_type_t zip_type(message::media_type_t::APPLICATION, "zip");
    std::list<std::tuple<std::istream&, string_t, message::content_type_t>> parts;
    parts.emplace_back(std::ref(pdf_stream), string_t("note.pdf"), pdf_type);
    parts.emplace_back(std::ref(zip_stream), string_t("pack.zip"), zip_type);
    BOOST_REQUIRE(msg.attach(parts));
    BOOST_CHECK(msg.content_type().boundary() == "stable-boundary");

    message_format_options_t opts;
    opts.stable = true;
    std::string first;
    std::string second;
    BOOST_REQUIRE(msg.format(first, opts));
    BOOST_REQUIRE(msg.format(second, opts));
    BOOST_CHECK(first == second);
    BOOST_CHECK(first.find('\0') == std::string::npos);
    BOOST_CHECK(first.find("boundary=\"stable-boundary\"") != std::string::npos);
    BOOST_CHECK(first.find("Content-Type: application/pdf") != std::string::npos);
    BOOST_CHECK(first.find("Content-Type: application/zip") != std::string::npos);
    BOOST_CHECK(first.find("Content-Transfer-Encoding: Base64\r\n") != std::string::npos);

    message parsed;
    BOOST_REQUIRE(parsed.parse(first));
    BOOST_REQUIRE(parsed.parts().size() == 3);

    std::stringstream pdf_out(std::ios::in | std::ios::out | std::ios::binary);
    std::stringstream zip_out(std::ios::in | std::ios::out | std::ios::binary);
    string_t pdf_name;
    string_t zip_name;
    BOOST_REQUIRE(parsed.attachment(1, pdf_out, pdf_name));
    BOOST_REQUIRE(parsed.attachment(2, zip_out, zip_name));
    BOOST_CHECK(pdf_out.str() == pdf);
    BOOST_CHECK(zip_out.str() == zip);
    BOOST_CHECK(parsed.parts().at(1).content_transfer_encoding() == message::content_transfer_encoding_t::BASE_64);
    BOOST_CHECK(parsed.parts().at(2).content_transfer_encoding() == message::content_transfer_encoding_t::BASE_64);
    BOOST_CHECK(parsed.parts().at(1).content_type().media_subtype() == "pdf");
    BOOST_CHECK(parsed.parts().at(2).content_type().media_subtype() == "zip");
}

BOOST_AUTO_TEST_CASE(string_concat_keeps_left_codec)
{
    string_t left("left", codec::CHARSET_UTF8, codec::codec_t::BASE64);
    string_t right("right", codec::CHARSET_ASCII, codec::codec_t::QUOTED_PRINTABLE);
    const string_t sum = left + right;
    BOOST_CHECK(sum.buffer == "leftright");
    BOOST_CHECK(sum.charset == codec::CHARSET_UTF8);
    BOOST_CHECK(sum.codec_type == codec::codec_t::BASE64);

    left += right;
    BOOST_CHECK(left.buffer == "leftright");
    BOOST_CHECK(left.codec_type == codec::codec_t::BASE64);
}

BOOST_AUTO_TEST_CASE(binary_octet_stream_round_trip_keeps_nul)
{
    const std::string payload = bytes_with_nul("OCT", "ET\r\nMORE");

    message msg;
    msg.date_time(fixed_date());
    msg.from(mail_address("mailxx", "address@mailxx.dev"));
    msg.add_recipient(mail_address("mailxx", "address@mailxx.dev"));
    msg.subject("binary");
    BOOST_REQUIRE(msg.content_type(message::media_type_t::APPLICATION, "octet-stream"));
    msg.content_transfer_encoding(message::content_transfer_encoding_t::BINARY);
    msg.content(payload);

    std::u8string u8_subject;
    u8_subject.push_back(u8'n');
    u8_subject.push_back(u8'\0');
    u8_subject.push_back(u8'b');
    message subject_msg;
    subject_msg.subject(u8_subject);
    BOOST_CHECK(subject_msg.subject() == std::string("n\0b", 3));

    std::string formatted;
    BOOST_REQUIRE(msg.format(formatted));
    BOOST_CHECK(formatted.find(payload) != std::string::npos);
    BOOST_CHECK(formatted.find("Content-Transfer-Encoding: Binary\r\n") != std::string::npos);

    message parsed;
    BOOST_REQUIRE(parsed.parse(formatted));
    BOOST_CHECK(parsed.content() == payload);
    BOOST_CHECK(parsed.content_transfer_encoding() == message::content_transfer_encoding_t::BINARY);

    std::u8string as_u8(reinterpret_cast<const char8_t*>(formatted.data()), formatted.size());
    message parsed_u8;
    BOOST_REQUIRE(parsed_u8.parse(as_u8));
    BOOST_CHECK(parsed_u8.content() == payload);

    std::u8string u8_body(reinterpret_cast<const char8_t*>(payload.data()), payload.size());
    message from_u8;
    from_u8.content(u8_body);
    BOOST_CHECK(from_u8.content() == payload);
}

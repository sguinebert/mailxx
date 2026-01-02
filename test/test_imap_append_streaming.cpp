/*

test_imap_append_streaming.cpp
-----------------------------

Validates IMAP APPEND streaming without buffering the payload.

*/

#define BOOST_TEST_MODULE imap_append_streaming_test

#include <string>
#include <thread>
#include <array>
#include <boost/test/unit_test.hpp>
#include <mailxx/imap/client.hpp>
#include <mailxx/mime/message.hpp>
#include <mailxx/mime/mailboxes.hpp>

using mailxx::mail_address;
using mailxx::message;
using mailxx::imap::client;
using mailxx::imap::response;

namespace asio = mailxx::asio;
using tcp = asio::ip::tcp;

static std::string read_line(tcp::socket& socket)
{
    asio::streambuf buf;
    asio::read_until(socket, buf, "\r\n");
    std::istream is(&buf);
    std::string line;
    std::getline(is, line);
    if (!line.empty() && line.back() == '\r')
        line.pop_back();
    return line;
}

static std::size_t parse_literal_size(const std::string& cmd_line)
{
    auto l = cmd_line.rfind('{');
    auto r = cmd_line.rfind('}');
    BOOST_REQUIRE(l != std::string::npos && r != std::string::npos && r > l);
    std::string num = cmd_line.substr(l + 1, r - l - 1);
    if (!num.empty() && num.back() == '+')
        num.pop_back();
    return static_cast<std::size_t>(std::stoul(num));
}

BOOST_AUTO_TEST_CASE(append_streaming_literal_plus)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(tcp::v4(), 0));
    const unsigned short port = acc.local_endpoint().port();
    std::string received;
    message msg;
    msg.from(mail_address("sender", "s@example.com"));
    msg.add_recipient(mail_address("rcpt", "r@example.com"));
    msg.subject("append");
    msg.content("hello\r\nworld\r\n");

    std::thread server_thread([&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
        asio::write(sock, asio::buffer(std::string("* OK [CAPABILITY IMAP4rev1 LITERAL+] ready\r\n")));

        auto line = read_line(sock); // APPEND command with {N+}
        std::size_t size = parse_literal_size(line);

        std::string data(size, '\0');
        asio::read(sock, asio::buffer(data.data(), data.size()));
        received = data;

        asio::write(sock, asio::buffer(std::string("1 OK append completed\r\n")));
    });

    asio::io_context client_ctx;
    auto fut = asio::co_spawn(client_ctx,
        [port, msg]() -> asio::awaitable<void>
        {
            client cli(co_await asio::this_coro::executor);
            auto conn_res = co_await cli.connect("127.0.0.1", port);
            BOOST_REQUIRE(conn_res);
            auto greet_res = co_await cli.read_greeting();
            BOOST_REQUIRE(greet_res);

            auto resp = co_await cli.append_streaming("INBOX", msg);
            BOOST_REQUIRE(resp);
            BOOST_CHECK(resp->st == mailxx::imap::status::ok);
        }, asio::use_future);

    client_ctx.run();
    fut.get();

    server_ctx.stop();
    if (server_thread.joinable())
        server_thread.join();

    std::string expected;
    BOOST_REQUIRE(msg.format(expected));
    BOOST_CHECK_EQUAL(received, expected);
}

BOOST_AUTO_TEST_CASE(append_streaming_wait_continuation)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(tcp::v4(), 0));
    const unsigned short port = acc.local_endpoint().port();
    std::string received;
    message msg;
    msg.from(mail_address("sender", "s@example.com"));
    msg.add_recipient(mail_address("rcpt", "r@example.com"));
    msg.subject("append");
    msg.content("hello\r\nworld\r\n");

    std::thread server_thread([&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
        asio::write(sock, asio::buffer(std::string("* OK [CAPABILITY IMAP4rev1] ready\r\n")));

        auto line = read_line(sock); // APPEND command with {N}
        std::size_t size = parse_literal_size(line);
        asio::write(sock, asio::buffer(std::string("+ go\r\n")));

        std::string data(size, '\0');
        asio::read(sock, asio::buffer(data.data(), data.size()));
        received = data;

        asio::write(sock, asio::buffer(std::string("1 OK append completed\r\n")));
    });

    asio::io_context client_ctx;
    auto fut = asio::co_spawn(client_ctx,
        [port, msg]() -> asio::awaitable<void>
        {
            client cli(co_await asio::this_coro::executor);
            auto conn_res = co_await cli.connect("127.0.0.1", port);
            BOOST_REQUIRE(conn_res);
            auto greet_res = co_await cli.read_greeting();
            BOOST_REQUIRE(greet_res);

            auto resp = co_await cli.append_streaming("INBOX", msg);
            BOOST_REQUIRE(resp);
            BOOST_CHECK(resp->st == mailxx::imap::status::ok);
        }, asio::use_future);

    client_ctx.run();
    fut.get();

    server_ctx.stop();
    if (server_thread.joinable())
        server_thread.join();

    std::string expected;
    BOOST_REQUIRE(msg.format(expected));
    BOOST_CHECK_EQUAL(received, expected);
}

/*

test_smtp_streaming.cpp
-----------------------

Verifies that smtp::client can stream DATA without buffering the entire payload and
that dot-stuffing/termination is correct.

*/

#define BOOST_TEST_MODULE smtp_streaming_test

#include <string>
#include <thread>
#include <array>
#include <future>
#include <boost/test/unit_test.hpp>
#include <mailxx/mime/message.hpp>
#include <mailxx/mime/mailboxes.hpp>
#include <mailxx/smtp/client.hpp>

using mailxx::mail_address;
using mailxx::message;
using mailxx::smtp::client;
using mailxx::smtp::envelope;

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

BOOST_AUTO_TEST_CASE(send_streaming_dot_stuffed)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(tcp::v4(), 0));
    const unsigned short port = acc.local_endpoint().port();
    std::string received;

    std::thread server_thread([&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
        asio::write(sock, asio::buffer(std::string("220 localhost\r\n")));

        auto line = read_line(sock); // EHLO
        BOOST_CHECK(line.rfind("EHLO", 0) == 0);
        asio::write(sock, asio::buffer(std::string("250-localhost\r\n250 OK\r\n")));

        line = read_line(sock); // MAIL FROM
        BOOST_CHECK(line.rfind("MAIL FROM:", 0) == 0);
        asio::write(sock, asio::buffer(std::string("250 OK\r\n")));

        line = read_line(sock); // RCPT TO
        BOOST_CHECK(line.rfind("RCPT TO:", 0) == 0);
        asio::write(sock, asio::buffer(std::string("250 OK\r\n")));

        line = read_line(sock); // DATA
        BOOST_CHECK_EQUAL(line, "DATA");
        asio::write(sock, asio::buffer(std::string("354 Go ahead\r\n")));

        std::string data;
        std::array<char, 1024> buf{};
        for (;;)
        {
            std::size_t n = sock.read_some(asio::buffer(buf));
            data.append(buf.data(), n);
            auto pos = data.find("\r\n.\r\n");
            if (pos != std::string::npos)
            {
                received = data.substr(0, pos);
                break;
            }
        }

        asio::write(sock, asio::buffer(std::string("250 Accepted\r\n")));
    });

    asio::io_context client_ctx;
    auto fut = asio::co_spawn(client_ctx,
        [port]() -> asio::awaitable<void>
        {
            client cli(co_await asio::this_coro::executor);
            auto conn_res = co_await cli.connect("127.0.0.1", port);
            BOOST_REQUIRE(conn_res);
            auto greet_res = co_await cli.read_greeting();
            BOOST_REQUIRE(greet_res);
            auto ehlo_res = co_await cli.ehlo("localhost");
            BOOST_REQUIRE(ehlo_res);

            message msg;
            msg.from(mail_address("sender", "sender@example.com"));
            msg.add_recipient(mail_address("rcpt", "rcpt@example.com"));
            msg.subject("stream");
            msg.content("Hello\r\n.Line starting with dot\r\nBye\r\n");

            envelope env;
            env.mail_from = "sender@example.com";
            env.rcpt_to = {"rcpt@example.com"};

            auto send_res = co_await cli.send_streaming(env, msg);
            BOOST_REQUIRE(send_res);
            BOOST_CHECK_EQUAL(send_res->status, 250);
        }, asio::use_future);

    client_ctx.run();
    fut.get();

    server_ctx.stop();
    if (server_thread.joinable())
        server_thread.join();

    BOOST_CHECK(received.find("\r\n..Line starting with dot") != std::string::npos);
    BOOST_CHECK(received.size() > 0);
}

/*

test_smtp_frozen.cpp
---------------------

Frozen MIME submission: exact bytes, four outcomes, and no second DATA.

*/

#define BOOST_TEST_MODULE smtp_frozen_test

#include <array>
#include <chrono>
#include <cstddef>
#include <future>
#include <span>
#include <string>
#include <thread>
#include <boost/test/unit_test.hpp>
#include <mailxx/smtp/client.hpp>

using mailxx::smtp::client;
using mailxx::smtp::envelope;
using mailxx::smtp::options;
using mailxx::smtp::queued_id;
using mailxx::smtp::reply;
using mailxx::smtp::submission_state;

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

static std::string stuff(std::string_view mime)
{
    std::string out;
    bool at_bol = true;
    char prev = 0;
    for (char c : mime)
    {
        if (at_bol && c == '.')
            out.push_back('.');
        out.push_back(c);
        at_bol = (prev == '\r' && c == '\n');
        prev = c;
    }
    return out;
}

static std::span<const std::byte> bytes_of(const std::string& mime)
{
    return std::as_bytes(std::span<const char>(mime.data(), mime.size()));
}

static options with_timeout()
{
    options opt;
    opt.timeout = std::chrono::milliseconds(400);
    return opt;
}

BOOST_AUTO_TEST_CASE(queued_id_accepts_only_the_postfix_line)
{
    reply ok;
    ok.status = 250;
    ok.lines = {"2.0.0 Ok: queued as ABC123"};
    auto id = queued_id(ok);
    BOOST_REQUIRE(id);
    BOOST_CHECK_EQUAL(*id, "ABC123");

    reply extra = ok;
    extra.lines = {"2.0.0 Ok: queued as ABC123 extra"};
    BOOST_CHECK(!queued_id(extra));

    reply other;
    other.status = 250;
    other.lines = {"Accepted"};
    BOOST_CHECK(!queued_id(other));

    reply hyphen = ok;
    hyphen.lines = {"2.0.0 Ok: queued as AB-12"};
    BOOST_CHECK(!queued_id(hyphen));

    reply counted = ok;
    counted.lines = {"2.0.0 Ok: 277 bytes queued as B0BD4A60000000900D0"};
    auto counted_id = queued_id(counted);
    BOOST_REQUIRE(counted_id);
    BOOST_CHECK_EQUAL(*counted_id, "B0BD4A60000000900D0");
}

BOOST_AUTO_TEST_CASE(local_refusals_submit_nothing)
{
    asio::io_context ctx;
    auto fut = asio::co_spawn(ctx,
        []() -> asio::awaitable<void>
        {
            client bare(co_await asio::this_coro::executor);
            envelope env;
            env.mail_from = "a@b";
            env.rcpt_to = {"c@d"};
            const std::string mime = "Subject: x\r\n\r\nHi\r\n";
            auto missing_timeout = co_await bare.send_frozen(bytes_of(mime), mime.size(), env);
            BOOST_CHECK(missing_timeout.state == submission_state::not_submitted);
            BOOST_CHECK(!missing_timeout);

            client cli(co_await asio::this_coro::executor, with_timeout());
            auto mismatch = co_await cli.send_frozen(bytes_of(mime), mime.size() + 1, env);
            BOOST_CHECK(mismatch.state == submission_state::not_submitted);

            std::string no_crlf = "Subject: x\r\n\r\nHi\n";
            auto crlf = co_await cli.send_frozen(bytes_of(no_crlf), no_crlf.size(), env);
            BOOST_CHECK(crlf.state == submission_state::not_submitted);

            std::string with_nul = "Subject: x\r\n\r\nH";
            with_nul.push_back('\0');
            with_nul += "i\r\n";
            auto nul = co_await cli.send_frozen(bytes_of(with_nul), with_nul.size(), env);
            BOOST_CHECK(nul.state == submission_state::not_submitted);

            envelope empty;
            auto no_rcpt = co_await cli.send_frozen(bytes_of(mime), mime.size(), empty);
            BOOST_CHECK(no_rcpt.state == submission_state::not_submitted);
        }, asio::use_future);
    ctx.run();
    fut.get();
}

BOOST_AUTO_TEST_CASE(send_frozen_preserves_bytes_and_queues)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(tcp::v4(), 0));
    const unsigned short port = acc.local_endpoint().port();

    std::string mime = "From: a@b\r\nSubject: frozen\r\n\r\nHello\r\n.dot\r\n----=_Boundary.1\r\n";
    mime.append(9000, 'A');
    mime += "\r\n";
    const std::string original = mime;
    const std::string expected = stuff(mime);
    std::string received;
    std::string mail_from;

    std::thread server([&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
        asio::write(sock, asio::buffer(std::string("220 localhost\r\n")));
        BOOST_CHECK(read_line(sock).rfind("EHLO", 0) == 0);
        asio::write(sock, asio::buffer(std::string("250-localhost\r\n250-SIZE 1000000\r\n250 OK\r\n")));
        mail_from = read_line(sock);
        asio::write(sock, asio::buffer(std::string("250 OK\r\n")));
        BOOST_CHECK(read_line(sock).rfind("RCPT TO:", 0) == 0);
        asio::write(sock, asio::buffer(std::string("250 OK\r\n")));
        BOOST_CHECK_EQUAL(read_line(sock), "DATA");
        asio::write(sock, asio::buffer(std::string("354 Go ahead\r\n")));

        std::array<char, 1024> buf{};
        std::string data;
        for (;;)
        {
            const std::size_t n = sock.read_some(asio::buffer(buf));
            data.append(buf.data(), n);
            const auto pos = data.rfind("\r\n.\r\n");
            if (pos != std::string::npos)
            {
                received = data.substr(0, pos + 2);
                break;
            }
        }
        asio::write(sock, asio::buffer(std::string("250 2.0.0 Ok: queued as ABC123\r\n")));
    });

    asio::io_context client_ctx;
    auto fut = asio::co_spawn(client_ctx,
        [port, &mime]() -> asio::awaitable<void>
        {
            client cli(co_await asio::this_coro::executor, with_timeout());
            BOOST_REQUIRE(co_await cli.connect("127.0.0.1", port));
            BOOST_REQUIRE(co_await cli.read_greeting());
            BOOST_REQUIRE(co_await cli.ehlo("localhost"));
            envelope env;
            env.mail_from = "a@b";
            env.rcpt_to = {"c@d"};
            auto sent = co_await cli.send_frozen(bytes_of(mime), mime.size(), env);
            BOOST_CHECK(sent.state == submission_state::queued);
            BOOST_CHECK(static_cast<bool>(sent));
            BOOST_CHECK_EQUAL(sent.queue_id, "ABC123");
            BOOST_CHECK_EQUAL(sent.server.status, 250);
        }, asio::use_future);
    client_ctx.run();
    fut.get();
    server.join();

    BOOST_CHECK_EQUAL(mime, original);
    BOOST_CHECK_EQUAL(received, expected);
    BOOST_CHECK(mail_from.find("SIZE=" + std::to_string(mime.size())) != std::string::npos);
    BOOST_CHECK(received.find("\r\n..dot\r\n") != std::string::npos);
    BOOST_CHECK(received.find("----=_Boundary.1\r\n") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rejected_and_unknown_do_not_open_a_second_data)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(tcp::v4(), 0));
    const unsigned short port = acc.local_endpoint().port();
    bool saw_second_data = false;

    std::thread server([&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
        asio::write(sock, asio::buffer(std::string("220 localhost\r\n")));
        (void)read_line(sock);
        asio::write(sock, asio::buffer(std::string("250 localhost\r\n")));

        auto exchange = [&](const std::string& data_reply) {
            BOOST_CHECK(read_line(sock).rfind("MAIL FROM:", 0) == 0);
            asio::write(sock, asio::buffer(std::string("250 OK\r\n")));
            BOOST_CHECK(read_line(sock).rfind("RCPT TO:", 0) == 0);
            asio::write(sock, asio::buffer(std::string("250 OK\r\n")));
            BOOST_CHECK_EQUAL(read_line(sock), "DATA");
            asio::write(sock, asio::buffer(std::string("354 Go ahead\r\n")));
            std::string data;
            std::array<char, 256> buf{};
            while (data.find("\r\n.\r\n") == std::string::npos)
            {
                const std::size_t n = sock.read_some(asio::buffer(buf));
                data.append(buf.data(), n);
            }
            asio::write(sock, asio::buffer(data_reply));
        };

        exchange("550 5.7.1 rejected\r\n");
        exchange("250 2.0.0 Ok: queued as AB-12\r\n");
        BOOST_CHECK_EQUAL(read_line(sock), "RSET");
        asio::write(sock, asio::buffer(std::string("250 OK\r\n")));

        std::array<char, 64> extra{};
        sock.async_read_some(asio::buffer(extra), [&](const asio::error_code& ec, std::size_t n) {
            if (!ec && n > 0)
                saw_second_data = true;
        });
        server_ctx.run_for(std::chrono::milliseconds(500));
    });

    asio::io_context client_ctx;
    auto fut = asio::co_spawn(client_ctx,
        [port]() -> asio::awaitable<void>
        {
            client cli(co_await asio::this_coro::executor, with_timeout());
            BOOST_REQUIRE(co_await cli.connect("127.0.0.1", port));
            BOOST_REQUIRE(co_await cli.read_greeting());
            BOOST_REQUIRE(co_await cli.ehlo("localhost"));
            envelope env;
            env.mail_from = "a@b";
            env.rcpt_to = {"c@d"};
            const std::string mime = "Subject: x\r\n\r\nHi\r\n";

            auto rejected = co_await cli.send_frozen(bytes_of(mime), mime.size(), env);
            BOOST_CHECK(rejected.state == submission_state::rejected);
            BOOST_CHECK(!rejected);
            BOOST_CHECK_EQUAL(rejected.server.status, 550);

            auto unknown = co_await cli.send_frozen(bytes_of(mime), mime.size(), env);
            BOOST_CHECK(unknown.state == submission_state::unknown);
            BOOST_CHECK(!unknown);

            auto rset = co_await cli.rset();
            BOOST_REQUIRE(rset);
            auto again = co_await cli.send_frozen(bytes_of(mime), mime.size(), env);
            BOOST_CHECK(again.state == submission_state::not_submitted);
            auto send_again = co_await cli.send(mailxx::message{}, env);
            BOOST_CHECK(!send_again);
        }, asio::use_future);
    client_ctx.run();
    fut.get();
    server.join();
    BOOST_CHECK(!saw_second_data);
}

BOOST_AUTO_TEST_CASE(missing_reply_after_the_dot_is_unknown)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(tcp::v4(), 0));
    const unsigned short port = acc.local_endpoint().port();

    std::thread server([&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
        asio::write(sock, asio::buffer(std::string("220 localhost\r\n")));
        (void)read_line(sock);
        asio::write(sock, asio::buffer(std::string("250 localhost\r\n")));
        (void)read_line(sock);
        asio::write(sock, asio::buffer(std::string("250 OK\r\n")));
        (void)read_line(sock);
        asio::write(sock, asio::buffer(std::string("250 OK\r\n")));
        BOOST_CHECK_EQUAL(read_line(sock), "DATA");
        asio::write(sock, asio::buffer(std::string("354 Go ahead\r\n")));
        std::string data;
        std::array<char, 256> buf{};
        while (data.find("\r\n.\r\n") == std::string::npos)
        {
            const std::size_t n = sock.read_some(asio::buffer(buf));
            data.append(buf.data(), n);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
    });

    asio::io_context client_ctx;
    auto fut = asio::co_spawn(client_ctx,
        [port]() -> asio::awaitable<void>
        {
            client cli(co_await asio::this_coro::executor, with_timeout());
            BOOST_REQUIRE(co_await cli.connect("127.0.0.1", port));
            BOOST_REQUIRE(co_await cli.read_greeting());
            BOOST_REQUIRE(co_await cli.ehlo("localhost"));
            envelope env;
            env.mail_from = "a@b";
            env.rcpt_to = {"c@d"};
            const std::string mime = "Subject: x\r\n\r\nHi\r\n";
            auto sent = co_await cli.send_frozen(bytes_of(mime), mime.size(), env);
            BOOST_CHECK(sent.state == submission_state::unknown);
            BOOST_CHECK(!sent);
            auto again = co_await cli.send_frozen(bytes_of(mime), mime.size(), env);
            BOOST_CHECK(again.state == submission_state::not_submitted);
        }, asio::use_future);
    client_ctx.run();
    fut.get();
    server.join();
}

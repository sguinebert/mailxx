/*

test_imap_literal_limit.cpp
---------------------------

Validates that oversized IMAP literals are rejected before buffering.

*/

#define BOOST_TEST_MODULE imap_literal_limit_test

#include <string>
#include <thread>

#include <boost/test/unit_test.hpp>

#include <mailxx/imap/client.hpp>

namespace asio = mailxx::asio;
using tcp = asio::ip::tcp;

BOOST_AUTO_TEST_CASE(imap_greeting_rejects_oversized_literal)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(tcp::v4(), 0));
    const unsigned short port = acc.local_endpoint().port();

    std::thread server_thread([&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
        asio::write(sock, asio::buffer(std::string("* OK [CAPABILITY IMAP4rev1] ready {9}\r\n")));
    });

    mailxx::imap::options opts;
    opts.max_literal_size = 8;

    asio::io_context client_ctx;
    auto fut = asio::co_spawn(client_ctx,
        [port, opts]() -> asio::awaitable<void>
        {
            mailxx::imap::client cli(co_await asio::this_coro::executor, opts);
            auto conn_res = co_await cli.connect("127.0.0.1", port);
            BOOST_REQUIRE(conn_res);

            auto greet_res = co_await cli.read_greeting();
            BOOST_REQUIRE(!greet_res);
            BOOST_CHECK(greet_res.error().code == mailxx::errc::imap_parse_error);
            BOOST_CHECK_NE(greet_res.error().detail.find("literal_size=9"), std::string::npos);
            BOOST_CHECK_NE(greet_res.error().detail.find("max_literal_size=8"), std::string::npos);
        }, asio::use_future);

    client_ctx.run();
    fut.get();

    if (server_thread.joinable())
        server_thread.join();
}

BOOST_AUTO_TEST_CASE(imap_greeting_rejects_literal_size_overflow)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(tcp::v4(), 0));
    const unsigned short port = acc.local_endpoint().port();

    std::thread server_thread([&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
        asio::write(sock, asio::buffer(std::string("* OK [CAPABILITY IMAP4rev1] ready {184467440737095516160}\r\n")));
    });

    asio::io_context client_ctx;
    auto fut = asio::co_spawn(client_ctx,
        [port]() -> asio::awaitable<void>
        {
            mailxx::imap::client cli(co_await asio::this_coro::executor);
            auto conn_res = co_await cli.connect("127.0.0.1", port);
            BOOST_REQUIRE(conn_res);

            auto greet_res = co_await cli.read_greeting();
            BOOST_REQUIRE(!greet_res);
            BOOST_CHECK(greet_res.error().code == mailxx::errc::imap_parse_error);
            BOOST_CHECK_EQUAL(greet_res.error().message, "IMAP literal size overflow.");
        }, asio::use_future);

    client_ctx.run();
    fut.get();

    if (server_thread.joinable())
        server_thread.join();
}

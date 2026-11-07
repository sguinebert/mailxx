#define BOOST_TEST_MODULE loopback_test

#include <future>
#include <string>
#include <boost/test/unit_test.hpp>
#include <mailxx/imap/client.hpp>
#include <mailxx/net/loopback.hpp>
#include <mailxx/smtp/client.hpp>

namespace asio = mailxx::asio;
using tcp = asio::ip::tcp;

BOOST_AUTO_TEST_CASE(loopback_address_covers_ipv4_block_and_ipv6)
{
    BOOST_CHECK(mailxx::net::is_loopback_address(asio::ip::make_address("127.0.0.1")));
    BOOST_CHECK(mailxx::net::is_loopback_address(asio::ip::make_address("127.255.255.255")));
    BOOST_CHECK(!mailxx::net::is_loopback_address(asio::ip::make_address("128.0.0.1")));
    BOOST_CHECK(!mailxx::net::is_loopback_address(asio::ip::make_address("8.8.8.8")));
    BOOST_CHECK(mailxx::net::is_loopback_address(asio::ip::make_address("::1")));
    BOOST_CHECK(!mailxx::net::is_loopback_address(asio::ip::make_address("::2")));
}

BOOST_AUTO_TEST_CASE(require_loopback_rejects_before_connect)
{
    asio::io_context ctx;
    auto smtp_fut = asio::co_spawn(ctx,
        []() -> asio::awaitable<void>
        {
            mailxx::smtp::options opt;
            opt.require_loopback = true;
            mailxx::smtp::client cli(co_await asio::this_coro::executor, opt);
            auto connected = co_await cli.connect("203.0.113.5", 9);
            BOOST_CHECK(!connected);
            BOOST_CHECK(connected.error().message.find("Loopback") != std::string::npos);
            BOOST_CHECK(!cli.peer_certificate_sha256());
        },
        asio::use_future);
    auto imap_fut = asio::co_spawn(ctx,
        []() -> asio::awaitable<void>
        {
            mailxx::imap::options opt;
            opt.require_loopback = true;
            mailxx::imap::client cli(co_await asio::this_coro::executor, opt);
            auto connected = co_await cli.connect("203.0.113.5", 9);
            BOOST_CHECK(!connected);
            BOOST_CHECK(connected.error().message.find("Loopback") != std::string::npos);
            BOOST_CHECK(!cli.peer_certificate_sha256());
        },
        asio::use_future);
    ctx.run();
    BOOST_CHECK_NO_THROW(smtp_fut.get());
    BOOST_CHECK_NO_THROW(imap_fut.get());
}

BOOST_AUTO_TEST_CASE(require_loopback_accepts_local_listener)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    const auto port = acc.local_endpoint().port();
    std::future<void> accepted = std::async(std::launch::async, [&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
    });

    asio::io_context ctx;
    auto fut = asio::co_spawn(ctx,
        [port]() -> asio::awaitable<void>
        {
            mailxx::smtp::options opt;
            opt.require_loopback = true;
            mailxx::smtp::client cli(co_await asio::this_coro::executor, opt);
            auto connected = co_await cli.connect("127.0.0.1", port);
            BOOST_REQUIRE(connected);
            BOOST_CHECK(!cli.peer_certificate_sha256());
        },
        asio::use_future);
    ctx.run();
    BOOST_CHECK_NO_THROW(fut.get());
    accepted.get();
}

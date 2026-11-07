/*

test_imap_peek.cpp
-------------------

BODY.PEEK portion, exact literal length, UIDVALIDITY, and bounded UID search.

*/

#define BOOST_TEST_MODULE imap_peek_test

#include <array>
#include <string>
#include <thread>
#include <boost/test/unit_test.hpp>
#include <mailxx/imap/client.hpp>

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

static std::string tag_of(const std::string& line)
{
    const auto pos = line.find(' ');
    return pos == std::string::npos ? line : line.substr(0, pos);
}

static void greet_and_examine(tcp::socket& sock)
{
    asio::write(sock, asio::buffer(std::string("* OK ready\r\n")));
    const std::string examine = read_line(sock);
    BOOST_CHECK(examine.find("EXAMINE") != std::string::npos);
    const std::string tag = tag_of(examine);
    asio::write(sock, asio::buffer(
        std::string("* OK [UIDVALIDITY 42] valid\r\n* OK [UIDNEXT 9] next\r\n")
        + tag + " OK [READ-ONLY] done\r\n"));
}

BOOST_AUTO_TEST_CASE(credentials_clear_wipes_the_secret)
{
    mailxx::imap::credentials cred;
    cred.username = "user";
    cred.secret = "secret-value";
    cred.clear();
    BOOST_CHECK(cred.secret.empty());
    BOOST_CHECK_EQUAL(cred.username, "user");
}

BOOST_AUTO_TEST_CASE(peek_returns_the_exact_portion_and_keeps_flags)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(tcp::v4(), 0));
    const unsigned short port = acc.local_endpoint().port();
    std::string fetch_cmd;

    std::thread server([&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
        greet_and_examine(sock);
        fetch_cmd = read_line(sock);
        const std::string tag = tag_of(fetch_cmd);
        asio::write(sock, asio::buffer(
            std::string("* 1 FETCH (UID 7 BODY[1]<0> {5}\r\nhello) FLAGS (\\Seen)\r\n")
            + tag + " OK done\r\n"));
    });

    asio::io_context client_ctx;
    auto fut = asio::co_spawn(client_ctx,
        [port]() -> asio::awaitable<void>
        {
            mailxx::imap::client cli(co_await asio::this_coro::executor);
            BOOST_REQUIRE(co_await cli.connect("127.0.0.1", port));
            BOOST_REQUIRE(co_await cli.read_greeting());
            BOOST_REQUIRE(co_await cli.examine("INBOX"));
            mailxx::imap::body_span portion;
            portion.offset = 0;
            portion.length = 5;
            auto body = co_await cli.uid_fetch_body(7, "1", portion, 16);
            BOOST_REQUIRE(body);
            BOOST_CHECK_EQUAL(*body, "hello");
        }, asio::use_future);
    client_ctx.run();
    fut.get();
    server.join();

    BOOST_CHECK(fetch_cmd.find("BODY.PEEK[1]<0.5>") != std::string::npos);
    BOOST_CHECK(fetch_cmd.find("FLAGS") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(shorter_literal_is_rejected_and_oversized_closes_the_session)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(tcp::v4(), 0));
    const unsigned short port = acc.local_endpoint().port();

    std::thread server([&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
        greet_and_examine(sock);

        const std::string short_fetch = read_line(sock);
        const std::string short_tag = tag_of(short_fetch);
        asio::write(sock, asio::buffer(
            std::string("* 1 FETCH (BODY[1] {4}\r\nabcd)\r\n") + short_tag + " OK done\r\n"));

        const std::string noop = read_line(sock);
        asio::write(sock, asio::buffer(tag_of(noop) + " OK noop\r\n"));

        const std::string big_fetch = read_line(sock);
        asio::write(sock, asio::buffer(std::string("* 1 FETCH (BODY[1] {8}\r\n")));
    });

    asio::io_context client_ctx;
    auto fut = asio::co_spawn(client_ctx,
        [port]() -> asio::awaitable<void>
        {
            mailxx::imap::client cli(co_await asio::this_coro::executor);
            BOOST_REQUIRE(co_await cli.connect("127.0.0.1", port));
            BOOST_REQUIRE(co_await cli.read_greeting());
            BOOST_REQUIRE(co_await cli.examine("INBOX"));
            mailxx::imap::body_span portion;
            portion.length = 5;
            auto short_body = co_await cli.uid_fetch_body(7, "1", portion, 16);
            BOOST_CHECK(!short_body);
            BOOST_CHECK(short_body.error().message.find("differs") != std::string::npos);

            auto noop = co_await cli.noop();
            BOOST_CHECK(noop);

            portion.length = 4;
            auto big = co_await cli.uid_fetch_body(7, "1", portion, 4);
            BOOST_CHECK(!big);
            BOOST_CHECK(big.error().message.find("ceiling") != std::string::npos);

            auto after = co_await cli.noop();
            BOOST_CHECK(!after);
        }, asio::use_future);
    client_ctx.run();
    fut.get();
    server.join();
}

BOOST_AUTO_TEST_CASE(uidvalidity_change_fails_without_replacing_the_retained_value)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(tcp::v4(), 0));
    const unsigned short port = acc.local_endpoint().port();

    std::thread server([&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
        greet_and_examine(sock);
        const std::string changed = read_line(sock);
        asio::write(sock, asio::buffer(
            std::string("* OK [UIDVALIDITY 99] changed\r\n") + tag_of(changed) + " OK noop\r\n"));
        const std::string same = read_line(sock);
        asio::write(sock, asio::buffer(
            std::string("* OK [UIDVALIDITY 42] same\r\n") + tag_of(same) + " OK noop\r\n"));
    });

    asio::io_context client_ctx;
    auto fut = asio::co_spawn(client_ctx,
        [port]() -> asio::awaitable<void>
        {
            mailxx::imap::client cli(co_await asio::this_coro::executor);
            BOOST_REQUIRE(co_await cli.connect("127.0.0.1", port));
            BOOST_REQUIRE(co_await cli.read_greeting());
            auto examined = co_await cli.examine("INBOX");
            BOOST_REQUIRE(examined);
            BOOST_CHECK_EQUAL(examined->second.uid_validity, 42u);
            auto changed = co_await cli.noop();
            BOOST_CHECK(!changed);
            BOOST_CHECK(changed.error().message.find("UIDVALIDITY") != std::string::npos);
            auto same = co_await cli.noop();
            BOOST_CHECK(same);
        }, asio::use_future);
    client_ctx.run();
    fut.get();
    server.join();
}

BOOST_AUTO_TEST_CASE(uid_search_keeps_order_and_rejects_duplicates_and_overflow)
{
    asio::io_context server_ctx;
    tcp::acceptor acc(server_ctx, tcp::endpoint(tcp::v4(), 0));
    const unsigned short port = acc.local_endpoint().port();

    std::thread server([&] {
        tcp::socket sock(server_ctx);
        acc.accept(sock);
        asio::write(sock, asio::buffer(std::string("* OK ready\r\n")));
        const std::string dup = read_line(sock);
        asio::write(sock, asio::buffer(
            std::string("* SEARCH 4 2 4\r\n") + tag_of(dup) + " OK search\r\n"));
        const std::string over = read_line(sock);
        asio::write(sock, asio::buffer(
            std::string("* SEARCH 1 2 3\r\n") + tag_of(over) + " OK search\r\n"));
        const std::string ok = read_line(sock);
        asio::write(sock, asio::buffer(
            std::string("* SEARCH 9 2 4\r\n") + tag_of(ok) + " OK search\r\n"));
    });

    asio::io_context client_ctx;
    auto fut = asio::co_spawn(client_ctx,
        [port]() -> asio::awaitable<void>
        {
            mailxx::imap::client cli(co_await asio::this_coro::executor);
            BOOST_REQUIRE(co_await cli.connect("127.0.0.1", port));
            BOOST_REQUIRE(co_await cli.read_greeting());
            auto dup = co_await cli.uid_search("ALL", 10);
            BOOST_CHECK(!dup);
            auto over = co_await cli.uid_search("ALL", 2);
            BOOST_CHECK(!over);
            auto ids = co_await cli.uid_search("ALL", 3);
            BOOST_REQUIRE(ids);
            BOOST_REQUIRE_EQUAL(ids->size(), 3u);
            BOOST_CHECK_EQUAL(ids->at(0), 9u);
            BOOST_CHECK_EQUAL(ids->at(1), 2u);
            BOOST_CHECK_EQUAL(ids->at(2), 4u);
        }, asio::use_future);
    client_ctx.run();
    fut.get();
    server.join();
}

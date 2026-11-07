#define BOOST_TEST_MODULE dialog_extensions

#include <chrono>
#include <boost/test/unit_test.hpp>
#include <mailxx/imap/types.hpp>
#include <mailxx/net/dialog.hpp>
#include <mailxx/net/upgradable_stream.hpp>

namespace asio = mailxx::asio;
using tcp = asio::ip::tcp;

BOOST_AUTO_TEST_CASE(idle_event_parses_exists_expunge_and_fetch)
{
    const auto exists = mailxx::imap::parse_idle_event("* 12 EXISTS");
    BOOST_CHECK(exists.kind == mailxx::imap::idle_event_kind::exists);
    BOOST_CHECK_EQUAL(exists.number, 12u);

    const auto expunge = mailxx::imap::parse_idle_event("* 4 EXPUNGE");
    BOOST_CHECK(expunge.kind == mailxx::imap::idle_event_kind::expunge);
    BOOST_CHECK_EQUAL(expunge.number, 4u);

    const auto fetch = mailxx::imap::parse_idle_event("* 7 FETCH (FLAGS (\\Seen))");
    BOOST_CHECK(fetch.kind == mailxx::imap::idle_event_kind::fetch);
    BOOST_CHECK_EQUAL(fetch.number, 7u);

    const auto other = mailxx::imap::parse_idle_event("* OK Still here");
    BOOST_CHECK(other.kind == mailxx::imap::idle_event_kind::other);
    BOOST_CHECK_EQUAL(other.number, 0u);
}

BOOST_AUTO_TEST_CASE(fetch_flags_reads_the_parenthesized_list)
{
    const auto flags = mailxx::imap::parse_fetch_flags("* 1 FETCH (FLAGS (\\Seen \\Flagged) BODY[1] {3}");
    BOOST_REQUIRE_EQUAL(flags.size(), 2u);
    BOOST_CHECK_EQUAL(flags[0], "\\Seen");
    BOOST_CHECK_EQUAL(flags[1], "\\Flagged");
}

BOOST_AUTO_TEST_CASE(deflate_layer_round_trips_a_line)
{
    asio::io_context ctx;
    auto fut = asio::co_spawn(ctx, []() -> asio::awaitable<void>
    {
        auto ex = co_await asio::this_coro::executor;
        tcp::acceptor acc(ex, tcp::endpoint(tcp::v4(), 0));
        tcp::socket client(ex);
        tcp::socket server(ex);
        asio::steady_timer ready(ex);
        ready.expires_after(std::chrono::seconds(2));
        asio::co_spawn(ex, [&]() -> asio::awaitable<void>
        {
            server = co_await acc.async_accept(asio::use_awaitable);
            ready.cancel();
        }, asio::detached);
        co_await client.async_connect(
            tcp::endpoint(asio::ip::address_v4::loopback(), acc.local_endpoint().port()),
            asio::use_awaitable);
        co_await ready.async_wait(asio::use_nothrow_awaitable);

        mailxx::net::upgradable_stream client_stream(std::move(client));
        mailxx::net::upgradable_stream server_stream(std::move(server));
        const bool enabled = client_stream.enable_deflate(64u * 1024u) && server_stream.enable_deflate(64u * 1024u);
#if defined(MAILXX_HAS_ZLIB)
        BOOST_REQUIRE(enabled);
        mailxx::net::dialog<mailxx::net::upgradable_stream> client_dlg(std::move(client_stream));
        mailxx::net::dialog<mailxx::net::upgradable_stream> server_dlg(std::move(server_stream));
        auto written = co_await client_dlg.write_line_view_r("HELLO");
        BOOST_REQUIRE(written);
        auto line = co_await server_dlg.read_line_r();
        BOOST_REQUIRE(line);
        BOOST_CHECK_EQUAL(*line, "HELLO");

        tcp::socket narrow_client(ex);
        tcp::socket narrow_server(ex);
        tcp::acceptor narrow_acc(ex, tcp::endpoint(tcp::v4(), 0));
        asio::steady_timer narrow_ready(ex);
        narrow_ready.expires_after(std::chrono::seconds(2));
        asio::co_spawn(ex, [&]() -> asio::awaitable<void>
        {
            narrow_server = co_await narrow_acc.async_accept(asio::use_awaitable);
            narrow_ready.cancel();
        }, asio::detached);
        co_await narrow_client.async_connect(
            tcp::endpoint(asio::ip::address_v4::loopback(), narrow_acc.local_endpoint().port()),
            asio::use_awaitable);
        co_await narrow_ready.async_wait(asio::use_nothrow_awaitable);
        mailxx::net::upgradable_stream narrow_client_stream(std::move(narrow_client));
        mailxx::net::upgradable_stream narrow_server_stream(std::move(narrow_server));
        BOOST_REQUIRE(narrow_client_stream.enable_deflate(8));
        BOOST_REQUIRE(narrow_server_stream.enable_deflate(8));
        mailxx::net::dialog<mailxx::net::upgradable_stream> narrow_client_dlg(std::move(narrow_client_stream));
        mailxx::net::dialog<mailxx::net::upgradable_stream> narrow_server_dlg(std::move(narrow_server_stream));
        auto wide = co_await narrow_client_dlg.write_line_view_r("HELLO THERE");
        BOOST_REQUIRE(wide);
        auto rejected = co_await narrow_server_dlg.read_line_r();
        BOOST_CHECK(!rejected);
#else
        BOOST_CHECK(!enabled);
#endif
        co_return;
    }, asio::use_future);
    ctx.run();
    fut.get();
}

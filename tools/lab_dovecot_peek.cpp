/*
lab_dovecot_peek
----------------

Opt-in recipe for a local Dovecot lab. It is not part of ctest.

BODY.PEEK reads one portion. The \\Seen flag must stay unchanged. A second read
that asks for a different length must fail.
*/

#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>

#include <mailxx/imap/client.hpp>

namespace asio = mailxx::asio;

namespace
{

bool has_seen(const mailxx::imap::response& resp)
{
    for (const auto& line : resp.untagged_lines)
    {
        if (line.find("\\Seen") != std::string::npos)
            return true;
    }
    for (const auto& line : resp.tagged_lines)
    {
        if (line.find("\\Seen") != std::string::npos)
            return true;
    }
    return false;
}

asio::awaitable<int> run(std::string host, unsigned short port, std::string user, std::string secret,
    std::string mailbox, std::uint32_t uid, std::string section, std::uint64_t offset, std::uint64_t length)
{
    const auto exec = co_await asio::this_coro::executor;
    mailxx::imap::options opt;
    opt.require_loopback = true;
    opt.allow_cleartext_auth = true;
    opt.require_tls_for_auth = false;
    opt.timeout = std::chrono::seconds(10);
    mailxx::imap::client imap(exec, opt);

    auto connected = co_await imap.connect(host, port);
    if (!connected || !co_await imap.read_greeting() || !co_await imap.login(user, secret))
    {
        std::cerr << "IMAP login failed\n";
        co_return 1;
    }
    if (!co_await imap.examine(mailbox))
    {
        std::cerr << "IMAP EXAMINE failed\n";
        co_return 1;
    }

    const std::string uid_text = std::to_string(uid);
    auto flags_before = co_await imap.fetch(uid_text, "(FLAGS)", true);
    if (!flags_before)
    {
        std::cerr << "FLAGS before peek failed\n";
        co_return 1;
    }
    const bool seen_before = has_seen(*flags_before);

    mailxx::imap::body_span portion{offset, length};
    auto body = co_await imap.uid_fetch_body(uid, section, portion, static_cast<std::size_t>(length));
    if (!body || body->size() != length)
    {
        std::cerr << "BODY.PEEK did not return the requested length\n";
        co_return 1;
    }

    auto flags_after = co_await imap.fetch(uid_text, "(FLAGS)", true);
    if (!flags_after)
    {
        std::cerr << "FLAGS after peek failed\n";
        co_return 1;
    }
    if (has_seen(*flags_after) != seen_before)
    {
        std::cerr << "\\Seen changed during BODY.PEEK\n";
        co_return 1;
    }

    mailxx::imap::body_span mismatch{offset, length + 1};
    auto rejected = co_await imap.uid_fetch_body(uid, section, mismatch, static_cast<std::size_t>(length + 1));
    if (rejected)
    {
        std::cerr << "A different literal length was accepted\n";
        co_return 1;
    }
    std::cout << "peek " << body->size() << " seen_unchanged mismatch_rejected\n";
    co_return 0;
}

}

int main(int argc, char** argv)
{
    if (argc != 10)
    {
        std::cerr << "Usage: lab_dovecot_peek <host> <port> <user> <secret> <mailbox> <uid> <section> <offset> <length>\n";
        return 2;
    }
    try
    {
        asio::io_context ctx;
        auto fut = asio::co_spawn(ctx, run(argv[1], static_cast<unsigned short>(std::stoul(argv[2])),
            argv[3], argv[4], argv[5], static_cast<std::uint32_t>(std::stoul(argv[6])), argv[7],
            std::stoull(argv[8]), std::stoull(argv[9])), asio::use_future);
        ctx.run();
        return fut.get();
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << "\n";
        return 1;
    }
}

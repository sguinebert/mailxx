/*
lab_wsl_proof
-------------

Opt-in proof against a local Postfix and Dovecot. It is not part of ctest.

The first submission uses send_frozen. When the server announced CHUNKING, that
path is BDAT and the body octets stay unchanged. The second submission adds DSN
parameters on MAIL FROM and RCPT TO only. IMAP then reads flags and a bounded
BODY.PEEK, holds IDLE until one event, moves the message when MOVE is announced,
and enables each extension only after its capability.
*/

#include <cstdlib>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <mailxx/imap/client.hpp>
#include <mailxx/smtp/client.hpp>

namespace asio = mailxx::asio;

namespace
{

const std::string body_token = "mailxx-frozen-token\r\n";

std::string mime_of(std::string_view id, std::string_view from, std::string_view to)
{
    std::string mime;
    mime += "From: <";
    mime += from;
    mime += ">\r\nTo: <";
    mime += to;
    mime += ">\r\nSubject: mailxx lab proof\r\nMessage-ID: <";
    mime += id;
    mime += ">\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n";
    mime += "Content-Transfer-Encoding: 7bit\r\nDate: Sat, 07 Nov 2026 14:00:00 +0000\r\n\r\n";
    mime += body_token;
    return mime;
}

void print_submission(const char* label, const mailxx::smtp::submission& sent)
{
    std::cout << label << " state " << static_cast<int>(sent.state) << " id " << sent.queue_id;
    if (!sent.server.lines.empty())
        std::cout << " reply " << sent.server.lines.front();
    std::cout << "\n";
}

asio::awaitable<int> run(std::string host, unsigned short smtp_port, unsigned short imap_port,
    std::string user, std::string secret, std::string from, std::string to)
{
    const auto exec = co_await asio::this_coro::executor;
    const auto stamp = std::chrono::system_clock::now().time_since_epoch().count();
    const std::string id_bdat = std::to_string(stamp) + ".bdat";
    const std::string id_dsn = std::to_string(stamp) + ".dsn";
    const std::string id_idle = std::to_string(stamp) + ".idle";
    const std::string mime_bdat = mime_of(id_bdat, from, to);
    const std::string mime_dsn = mime_of(id_dsn, from, to);
    const std::string mime_idle = mime_of(id_idle, from, to);

    mailxx::smtp::options smtp_opt;
    smtp_opt.require_loopback = true;
    smtp_opt.timeout = std::chrono::seconds(15);
    mailxx::smtp::client smtp(exec, smtp_opt);
    auto connected = co_await smtp.connect(host, smtp_port);
    if (!connected)
    {
        std::cerr << "SMTP connect: " << connected.error().message << "\n";
        co_return 1;
    }
    if (!co_await smtp.read_greeting() || !co_await smtp.ehlo("localhost"))
    {
        std::cerr << "SMTP greeting failed\n";
        co_return 1;
    }
    std::cout << "chunking " << smtp.supports_chunking() << " dsn " << smtp.supports_dsn() << "\n";
    if (!smtp.supports_chunking() || !smtp.supports_dsn())
    {
        std::cerr << "Postfix did not announce CHUNKING and DSN\n";
        co_return 1;
    }

    mailxx::smtp::envelope envelope;
    envelope.mail_from = from;
    envelope.rcpt_to.push_back(to);
    const auto bdat_bytes = std::as_bytes(std::span<const char>(mime_bdat.data(), mime_bdat.size()));
    const auto bdat_sent = co_await smtp.send_frozen(bdat_bytes, mime_bdat.size(), envelope);
    print_submission("bdat", bdat_sent);
    if (!bdat_sent)
        co_return 1;

    mailxx::smtp::dsn_options dsn = mailxx::smtp::dsn_options::on_failure();
    dsn.envid = "mailxx-" + std::to_string(stamp);
    mailxx::smtp::envelope_dsn dsn_env(envelope, dsn);
    const auto dsn_bytes = std::as_bytes(std::span<const char>(mime_dsn.data(), mime_dsn.size()));
    const auto dsn_sent = co_await smtp.send_frozen(dsn_bytes, mime_dsn.size(), dsn_env);
    print_submission("dsn", dsn_sent);
    if (!dsn_sent)
        co_return 1;
    co_await smtp.quit();

    mailxx::imap::options imap_opt;
    imap_opt.require_loopback = true;
    imap_opt.allow_cleartext_auth = true;
    imap_opt.require_tls_for_auth = false;
    imap_opt.timeout = std::chrono::seconds(15);
    mailxx::imap::client imap(exec, imap_opt);
    auto imap_connected = co_await imap.connect(host, imap_port);
    if (!imap_connected)
    {
        std::cerr << "IMAP connect: " << imap_connected.error().message << "\n";
        co_return 1;
    }
    auto greeting = co_await imap.read_greeting();
    if (!greeting)
    {
        std::cerr << "IMAP greeting: " << greeting.error().message << "\n";
        co_return 1;
    }
    auto logged = co_await imap.login(user, secret);
    if (!logged)
    {
        std::cerr << "IMAP login: " << logged.error().message << " " << logged.error().detail << "\n";
        co_return 1;
    }
    auto caps = co_await imap.capability();
    if (!caps)
    {
        std::cerr << "IMAP CAPABILITY failed\n";
        co_return 1;
    }
    auto advertised = [&](std::string_view name)
    {
        for (const auto& line : caps->untagged_lines)
        {
            if (line.find(name) != std::string::npos)
                return true;
        }
        for (const auto& line : caps->tagged_lines)
        {
            if (line.find(name) != std::string::npos)
                return true;
        }
        return false;
    };
    const bool has_utf8 = advertised("UTF8=ACCEPT");
    const bool has_condstore = advertised("CONDSTORE");
    const bool has_qresync = advertised("QRESYNC");
    const bool has_move = advertised("MOVE");
    const bool has_compress = advertised("COMPRESS=DEFLATE");
    std::cout << "utf8 " << has_utf8 << " condstore " << has_condstore << " qresync " << has_qresync
              << " move " << has_move << " compress " << has_compress << "\n";

    if (has_utf8)
    {
        auto resp = co_await imap.enable_utf8();
        if (!resp || resp->st != mailxx::imap::status::ok)
        {
            std::cerr << "UTF8=ACCEPT enable failed\n";
            co_return 1;
        }
        std::cout << "utf8 enabled\n";
    }
    if (has_condstore)
    {
        auto resp = co_await imap.enable_condstore();
        if (!resp || resp->st != mailxx::imap::status::ok)
        {
            std::cerr << "CONDSTORE enable failed\n";
            co_return 1;
        }
        std::cout << "condstore enabled\n";
    }
    if (has_qresync)
    {
        auto resp = co_await imap.enable_qresync();
        if (!resp || resp->st != mailxx::imap::status::ok)
        {
            std::cerr << "QRESYNC enable failed\n";
            co_return 1;
        }
        std::cout << "qresync enabled\n";
    }

    auto selected = co_await imap.select("INBOX");
    if (!selected)
    {
        std::cerr << "IMAP SELECT failed\n";
        co_return 1;
    }
    const auto uid_validity = selected->second.uid_validity;
    const auto modseq = imap.highest_modseq();
    std::cout << "uidvalidity " << uid_validity << " modseq "
              << (modseq ? std::to_string(*modseq) : std::string("none")) << "\n";
    if (has_qresync && modseq && uid_validity != 0)
    {
        auto resynced = co_await imap.select_qresync("INBOX", uid_validity, *modseq);
        if (!resynced)
        {
            std::cerr << "QRESYNC SELECT failed\n";
            co_return 1;
        }
        std::cout << "qresync select\n";
    }

    const std::string criteria = "HEADER Message-ID <" + id_bdat + ">";
    std::vector<std::uint32_t> ids;
    for (int attempt = 0; attempt < 8 && ids.empty(); ++attempt)
    {
        if (attempt != 0)
            co_await asio::steady_timer(exec, std::chrono::seconds(1)).async_wait(asio::use_awaitable);
        auto found = co_await imap.uid_search(criteria, 8);
        if (found && !found->empty())
            ids = std::move(*found);
    }
    if (ids.empty())
    {
        std::cerr << "Delivered message was not found\n";
        co_return 1;
    }
    const auto uid = ids.back();
    mailxx::imap::body_span portion{0, body_token.size()};
    auto peeked = co_await imap.uid_fetch_flags_and_body(uid, "TEXT", portion, body_token.size());
    if (!peeked || peeked->body != body_token)
    {
        std::cerr << "FLAGS plus BODY.PEEK did not return the frozen body\n";
        co_return 1;
    }
    std::cout << "peek flags " << peeked->flags.size() << " body " << peeked->body.size() << "\n";

    auto idle = co_await imap.idle_start();
    if (!idle)
    {
        std::cerr << "IDLE start failed\n";
        co_return 1;
    }
    mailxx::smtp::client smtp_idle(exec, smtp_opt);
    auto idle_connected = co_await smtp_idle.connect(host, smtp_port);
    if (!idle_connected || !co_await smtp_idle.read_greeting() || !co_await smtp_idle.ehlo("localhost"))
    {
        std::cerr << "SMTP connect during IDLE failed\n";
        co_return 1;
    }
    const auto idle_bytes = std::as_bytes(std::span<const char>(mime_idle.data(), mime_idle.size()));
    const auto idle_sent = co_await smtp_idle.send_frozen(idle_bytes, mime_idle.size(), envelope);
    print_submission("idle-mail", idle_sent);
    if (!idle_sent)
        co_return 1;

    bool saw_exists = false;
    for (int n = 0; n < 4 && !saw_exists; ++n)
    {
        auto event = co_await idle->idle_read_event();
        if (!event)
        {
            std::cerr << "IDLE read failed\n";
            co_return 1;
        }
        std::cout << "idle kind " << static_cast<int>(event->kind) << " n " << event->number << "\n";
        if (event->kind == mailxx::imap::idle_event_kind::exists)
            saw_exists = true;
    }
    auto stopped = co_await idle->idle_stop();
    if (!stopped || !saw_exists)
    {
        std::cerr << "IDLE did not report EXISTS\n";
        co_return 1;
    }

    if (has_move)
    {
        auto created = co_await imap.command("CREATE Trash");
        if (!created)
            std::cout << "create trash " << created.error().detail << "\n";
        auto moved = co_await imap.uid_move(uid, "Trash");
        if (!moved || moved->st != mailxx::imap::status::ok)
        {
            std::cerr << "UID MOVE failed";
            if (!moved)
                std::cerr << " " << moved.error().detail;
            std::cerr << "\n";
            co_return 1;
        }
        std::cout << "moved " << uid << "\n";
    }
    else
        std::cout << "move absent\n";

    if (has_compress)
    {
        auto compressed = co_await imap.compress_deflate();
        if (!compressed || compressed->st != mailxx::imap::status::ok)
        {
            std::cerr << "COMPRESS DEFLATE failed\n";
            co_return 1;
        }
        auto noop = co_await imap.noop();
        if (!noop || noop->st != mailxx::imap::status::ok)
        {
            std::cerr << "NOOP after COMPRESS failed\n";
            co_return 1;
        }
        std::cout << "compress noop\n";
    }
    else
        std::cout << "compress absent\n";
    co_return 0;
}

}

int main(int argc, char** argv)
{
    if (argc != 8)
    {
        std::cerr << "Usage: lab_wsl_proof <host> <smtp-port> <imap-port> <user> <secret> <mail-from> <rcpt>\n";
        return 2;
    }
    try
    {
        asio::io_context ctx;
        const char* secret = argv[5];
        std::string secret_buf;
        if (std::string_view(secret) == "-")
        {
            const char* from_env = std::getenv("MAILXX_LAB_SECRET");
            if (from_env == nullptr || from_env[0] == '\0')
            {
                std::cerr << "MAILXX_LAB_SECRET is empty\n";
                return 2;
            }
            secret_buf = from_env;
            secret = secret_buf.c_str();
        }
        auto fut = asio::co_spawn(ctx, run(argv[1], static_cast<unsigned short>(std::stoul(argv[2])),
            static_cast<unsigned short>(std::stoul(argv[3])), argv[4], secret, argv[6], argv[7]),
            asio::use_future);
        ctx.run();
        return fut.get();
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << "\n";
        return 1;
    }
}

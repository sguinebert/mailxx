/*
lab_postfix_frozen
-------------------

Opt-in recipe for a local Postfix and Dovecot lab. It is not part of ctest.

The MIME file is sent unchanged: no header is added and the bytes are not rewritten.
send_frozen must report a queued message and a short queue id. The same octets are
then read back with BODY.PEEK[] and compared by SHA-256.
*/

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <thread>

#include <openssl/sha.h>

#include <mailxx/imap/client.hpp>
#include <mailxx/smtp/client.hpp>

namespace asio = mailxx::asio;

namespace
{

std::string sha256_hex(std::string_view bytes)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), digest);
    static constexpr char hex[] = "0123456789abcdef";
    std::string out(SHA256_DIGEST_LENGTH * 2, '0');
    for (unsigned i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    return out;
}

std::string message_id_of(std::string_view mime)
{
    std::size_t line_begin = 0;
    while (line_begin < mime.size())
    {
        auto line_end = mime.find("\r\n", line_begin);
        if (line_end == std::string_view::npos)
            line_end = mime.size();
        const auto line = mime.substr(line_begin, line_end - line_begin);
        if (line.empty())
            return {};
        constexpr std::string_view name = "message-id:";
        if (line.size() > name.size())
        {
            bool match = true;
            for (std::size_t i = 0; i < name.size(); ++i)
            {
                const char ch = line[i];
                const char lower = (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
                if (lower != name[i])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                std::size_t value = name.size();
                while (value < line.size() && (line[value] == ' ' || line[value] == '\t'))
                    ++value;
                return std::string(line.substr(value));
            }
        }
        if (line_end == mime.size())
            break;
        line_begin = line_end + 2;
    }
    return {};
}

asio::awaitable<int> run(std::string mime_path, std::string smtp_host, unsigned short smtp_port,
    std::string imap_host, unsigned short imap_port, std::string user, std::string secret,
    std::string mailbox, std::string mail_from, std::string rcpt)
{
    std::ifstream input(mime_path, std::ios::binary);
    if (!input)
    {
        std::cerr << "Cannot open " << mime_path << "\n";
        co_return 1;
    }
    std::string mime((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    const std::string original_hash = sha256_hex(mime);
    std::cout << "sha256 " << original_hash << "\n";

    const auto exec = co_await asio::this_coro::executor;
    mailxx::smtp::options smtp_opt;
    smtp_opt.require_loopback = true;
    smtp_opt.timeout = std::chrono::seconds(10);
    mailxx::smtp::client smtp(exec, smtp_opt);
    auto connected = co_await smtp.connect(smtp_host, smtp_port);
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

    mailxx::smtp::envelope envelope;
    envelope.mail_from = std::move(mail_from);
    envelope.rcpt_to.push_back(std::move(rcpt));
    const auto bytes = std::as_bytes(std::span<const char>(mime.data(), mime.size()));
    const auto sent = co_await smtp.send_frozen(bytes, mime.size(), envelope);
    std::cout << "state " << static_cast<int>(sent.state) << " id " << sent.queue_id << "\n";
    if (!sent || sent.queue_id.empty())
    {
        std::cerr << "Submission was not queued\n";
        co_return 1;
    }

    const std::string message_id = message_id_of(mime);
    if (message_id.empty())
    {
        std::cerr << "MIME file has no Message-ID header\n";
        co_return 1;
    }

    mailxx::imap::options imap_opt;
    imap_opt.require_loopback = true;
    imap_opt.allow_cleartext_auth = true;
    imap_opt.require_tls_for_auth = false;
    imap_opt.timeout = std::chrono::seconds(10);
    mailxx::imap::client imap(exec, imap_opt);
    auto imap_connected = co_await imap.connect(imap_host, imap_port);
    if (!imap_connected || !co_await imap.read_greeting() || !co_await imap.login(user, secret))
    {
        std::cerr << "IMAP login failed\n";
        co_return 1;
    }
    if (!co_await imap.examine(mailbox))
    {
        std::cerr << "IMAP EXAMINE failed\n";
        co_return 1;
    }

    const std::string criteria = "HEADER Message-ID " + message_id;
    std::string reread;
    for (int attempt = 0; attempt < 8 && reread.empty(); ++attempt)
    {
        if (attempt != 0)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        auto ids = co_await imap.uid_search(criteria, 8);
        if (!ids || ids->empty())
            continue;
        auto body = co_await imap.uid_fetch_body(ids->back(), "BODY.PEEK[]");
        if (!body)
            continue;
        reread = std::move(*body);
    }
    if (reread.empty())
    {
        std::cerr << "Delivered message was not found\n";
        co_return 1;
    }

    const std::string reread_hash = sha256_hex(reread);
    std::cout << "reread " << reread_hash << "\n";
    if (reread_hash != original_hash)
    {
        std::cerr << "Reread octets differ from the frozen MIME\n";
        co_return 1;
    }
    std::cout << "queued " << sent.queue_id << "\n";
    co_return 0;
}

}

int main(int argc, char** argv)
{
    if (argc != 11)
    {
        std::cerr << "Usage: lab_postfix_frozen <mime-file> <smtp-host> <smtp-port> <imap-host> <imap-port> "
                     "<user> <secret> <mailbox> <mail-from> <rcpt>\n";
        return 2;
    }
    try
    {
        asio::io_context ctx;
        auto fut = asio::co_spawn(ctx, run(argv[1], argv[2], static_cast<unsigned short>(std::stoul(argv[3])),
            argv[4], static_cast<unsigned short>(std::stoul(argv[5])), argv[6], argv[7], argv[8], argv[9], argv[10]),
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

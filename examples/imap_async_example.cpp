/*

imap_async_example.cpp
----------------------

Demonstrates the async IMAP v2 client with C++20 coroutines.

Copyright (C) 2024, mailxx contributors.

Distributed under the FreeBSD license.

*/


#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <mailxx/imap/client.hpp>
#include <mailxx/net/tls_mode.hpp>


using mailxx::imap::client;
using mailxx::imap::error;
using mailxx::net::dialog_error;
using std::cout;
using std::endl;


int main()
{
    boost::asio::io_context io_ctx;
    boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tls_client);

    boost::asio::co_spawn(io_ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            try
            {
                mailxx::imap::options options;
                options.tls.use_default_verify_paths = true;
                options.tls.verify = mailxx::net::verify_mode::peer;
                options.tls.verify_host = true;

                client conn(io_ctx.get_executor(), options);
                co_await conn.connect("imap.example.com", "993",
                    mailxx::net::tls_mode::implicit, &ssl_ctx, "imap.example.com");
                auto greeting = co_await conn.read_greeting();
                if (!greeting.untagged_lines.empty())
                    cout << "Server greeting: " << greeting.untagged_lines.front() << endl;

                co_await conn.login("user@example.com", "password");

                auto [list_resp, folders] = co_await conn.list("", "*");
                (void)list_resp;
                cout << "Found " << folders.size() << " mailboxes:" << endl;
                for (const auto& folder : folders)
                {
                    cout << "  - " << folder.name << endl;
                }

                auto [select_resp, stat] = co_await conn.select("INBOX");
                (void)select_resp;
                cout << "INBOX has " << stat.messages_no << " messages, "
                     << stat.recent << " recent, "
                     << stat.unseen << " unseen." << endl;

                auto [search_resp, msg_ids] = co_await conn.search("UNSEEN");
                (void)search_resp;
                cout << "Found " << msg_ids.size() << " unseen messages." << endl;

                if (!msg_ids.empty())
                {
                    const std::string seq = std::to_string(msg_ids.front());
                    auto fetch_resp = co_await conn.fetch(seq, "BODY[HEADER.FIELDS (FROM SUBJECT DATE)]");
                    cout << "Fetched message headers." << endl;
                    for (const auto& literal : fetch_resp.literals)
                    {
                        cout << literal << endl;
                    }

                    co_await conn.store(seq, "FLAGS.SILENT", "(\\Seen)", "+FLAGS");
                    cout << "Marked message as seen." << endl;
                }

                co_await conn.close();
                co_await conn.logout();
                cout << "Logged out successfully." << endl;
            }
            catch (const error& exc)
            {
                cout << exc.what() << endl;
            }
            catch (const dialog_error& exc)
            {
                cout << exc.what() << endl;
            }
            co_return;
        },
        boost::asio::detached);

    io_ctx.run();
    return EXIT_SUCCESS;
}

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
#include "example_util.hpp"
#include <mailxx/imap/client.hpp>
#include <mailxx/net/tls_mode.hpp>


using mailxx::imap::client;
using std::cout;
using std::endl;


int main()
{
    boost::asio::io_context io_ctx;
    boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tls_client);

    boost::asio::co_spawn(io_ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            mailxx::imap::options options;
            options.tls.use_default_verify_paths = true;
            options.tls.verify = mailxx::net::verify_mode::peer;
            options.tls.verify_host = true;

            client conn(io_ctx.get_executor(), options);
            auto connect_res = co_await conn.connect("imap.example.com", "993",
                mailxx::net::tls_mode::implicit, &ssl_ctx, "imap.example.com");
            if (!connect_res)
            {
                print_error(connect_res.error());
                co_return;
            }

            auto greeting_res = co_await conn.read_greeting();
            if (!greeting_res)
            {
                print_error(greeting_res.error());
                co_return;
            }
            const auto& greeting = greeting_res.value();
            if (!greeting.untagged_lines.empty())
                cout << "Server greeting: " << greeting.untagged_lines.front() << endl;

            auto login_res = co_await conn.login("user@example.com", "password");
            if (!login_res)
            {
                print_error(login_res.error());
                co_return;
            }

            auto list_res = co_await conn.list("", "*");
            if (!list_res)
            {
                print_error(list_res.error());
                co_return;
            }
            const auto& [list_resp, folders] = list_res.value();
            (void)list_resp;
            cout << "Found " << folders.size() << " mailboxes:" << endl;
            for (const auto& folder : folders)
            {
                cout << "  - " << folder.name << endl;
            }

            auto select_res = co_await conn.select("INBOX");
            if (!select_res)
            {
                print_error(select_res.error());
                co_return;
            }
            const auto& [select_resp, stat] = select_res.value();
            (void)select_resp;
            cout << "INBOX has " << stat.messages_no << " messages, "
                 << stat.recent << " recent, "
                 << stat.unseen << " unseen." << endl;

            auto search_res = co_await conn.search("UNSEEN");
            if (!search_res)
            {
                print_error(search_res.error());
                co_return;
            }
            const auto& [search_resp, msg_ids] = search_res.value();
            (void)search_resp;
            cout << "Found " << msg_ids.size() << " unseen messages." << endl;

            if (!msg_ids.empty())
            {
                const std::string seq = std::to_string(msg_ids.front());
                auto fetch_res = co_await conn.fetch(seq, "BODY[HEADER.FIELDS (FROM SUBJECT DATE)]");
                if (!fetch_res)
                {
                    print_error(fetch_res.error());
                    co_return;
                }
                const auto& fetch_resp = fetch_res.value();
                cout << "Fetched message headers." << endl;
                for (const auto& literal : fetch_resp.literals)
                {
                    cout << literal << endl;
                }

                auto store_res = co_await conn.store(seq, "FLAGS.SILENT", "(\\Seen)", "+FLAGS");
                if (!store_res)
                {
                    print_error(store_res.error());
                    co_return;
                }
                cout << "Marked message as seen." << endl;
            }

            auto close_res = co_await conn.close();
            if (!close_res)
            {
                print_error(close_res.error());
                co_return;
            }

            auto logout_res = co_await conn.logout();
            if (!logout_res)
            {
                print_error(logout_res.error());
                co_return;
            }
            cout << "Logged out successfully." << endl;
            co_return;
        },
        boost::asio::detached);

    io_ctx.run();
    return EXIT_SUCCESS;
}

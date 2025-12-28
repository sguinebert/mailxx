/*

imaps_search.cpp
----------------

Connects to an IMAP server over TLS and searches for messages
that satisfy the criteria.


Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#include <iostream>
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
            auto connect_res = co_await conn.connect("imap-mail.outlook.com", "993",
                mailxx::net::tls_mode::implicit, &ssl_ctx, "imap-mail.outlook.com");
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

            // modify username/password to use real credentials
            auto login_res = co_await conn.login("mailxx@outlook.com", "mailxxpass");
            if (!login_res)
            {
                print_error(login_res.error());
                co_return;
            }

            auto select_res = co_await conn.select("INBOX");
            if (!select_res)
            {
                print_error(select_res.error());
                co_return;
            }
            const auto& [select_resp, stat] = select_res.value();
            (void)select_resp;
            (void)stat;

            auto search_res = co_await conn.search("SUBJECT \\"mailxx\\"", true);
            if (!search_res)
            {
                print_error(search_res.error());
                co_return;
            }
            const auto& [search_resp, ids] = search_res.value();
            (void)search_resp;
            for (auto msg_uid : ids)
            {
                cout << msg_uid << endl;
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
            co_return;
        },
        boost::asio::detached);

    io_ctx.run();
    return EXIT_SUCCESS;
}

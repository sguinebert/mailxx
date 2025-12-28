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
                co_await conn.connect("imap-mail.outlook.com", "993",
                    mailxx::net::tls_mode::implicit, &ssl_ctx, "imap-mail.outlook.com");
                co_await conn.read_greeting();
                // modify username/password to use real credentials
                co_await conn.login("mailxx@outlook.com", "mailxxpass");

                auto [select_resp, stat] = co_await conn.select("INBOX");
                (void)select_resp;
                (void)stat;

                auto [search_resp, ids] = co_await conn.search("SUBJECT \\"mailxx\\"", true);
                (void)search_resp;
                for (auto msg_uid : ids)
                {
                    cout << msg_uid << endl;
                }

                co_await conn.close();
                co_await conn.logout();
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

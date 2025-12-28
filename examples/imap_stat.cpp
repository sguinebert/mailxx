/*

imaps_stat.cpp
--------------
  
Connects to an IMAP server over TLS and gets the number of messages in mailbox.


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
                co_await conn.connect("imap.zoho.com", "993",
                    mailxx::net::tls_mode::implicit, &ssl_ctx, "imap.zoho.com");
                co_await conn.read_greeting();
                // modify to use an existing zoho account
                co_await conn.login("mailxx@zoho.com", "mailxxpass");

                auto [resp, stat] = co_await conn.select("INBOX");
                (void)resp;
                cout << "Number of messages in mailbox: " << stat.messages_no << endl;

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

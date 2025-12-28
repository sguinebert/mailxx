/*

imaps_stat.cpp
--------------
  
Connects to an IMAP server over SSL and gets the first message from the inbox.


Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <mailxx/imap/client.hpp>
#include <mailxx/mime/message.hpp>
#include <mailxx/net/tls_mode.hpp>


using mailxx::codec;
using mailxx::message;
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
                co_await conn.login("mailxx@zoho.com", "mailxxpass");

                auto [select_resp, stat] = co_await conn.select("INBOX");
                (void)select_resp;
                (void)stat;

                auto fetch_resp = co_await conn.fetch("1", "BODY[]");
                if (!fetch_resp.literals.empty())
                {
                    message msg;
                    msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
                    msg.parse(fetch_resp.literals.front());
                    cout << "msg.subject()=" << msg.subject() << endl;
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

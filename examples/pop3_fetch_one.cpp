/*

pop3s_fetch_one.cpp
-------------------

Connects to POP3 server via SSL and fetches the first message from mailbox.


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
#include <mailxx/mime/message.hpp>
#include <mailxx/net/tls_mode.hpp>
#include <mailxx/pop3/client.hpp>


using mailxx::codec;
using mailxx::message;
using mailxx::pop3::client;
using mailxx::pop3::error;
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
                mailxx::pop3::options options;
                options.tls.use_default_verify_paths = true;
                options.tls.verify = mailxx::net::verify_mode::peer;
                options.tls.verify_host = true;

                client conn(io_ctx.get_executor(), options);
                co_await conn.connect("pop.mail.yahoo.com", "995",
                    mailxx::net::tls_mode::implicit, &ssl_ctx, "pop.mail.yahoo.com");
                co_await conn.read_greeting();
                // modify to use existing yahoo account
                co_await conn.login("mailxx@yahoo.com", "mailxxpass");

                std::string raw = co_await conn.retr(1);
                message msg;
                msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
                msg.parse(raw);
                cout << msg.subject() << endl;

                co_await conn.quit();
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

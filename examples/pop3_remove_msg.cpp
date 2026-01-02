/*

pop3_remove_msg.cpp
-------------------

Connects to a POP3 server and removes the first message in mailbox.


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
#include <mailxx/net/tls_mode.hpp>
#include <mailxx/pop3/client.hpp>


using mailxx::pop3::client;


int main()
{
    boost::asio::io_context io_ctx;
    boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tls_client);

    boost::asio::co_spawn(io_ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            mailxx::pop3::options options;
            options.tls.use_default_verify_paths = true;
            options.tls.verify = mailxx::net::verify_mode::peer;
            options.tls.verify_host = true;

            client conn(io_ctx.get_executor(), options);
            if (auto connect_res = co_await conn.connect("pop.mailserver.com", "995",
                mailxx::net::tls_mode::implicit, &ssl_ctx, "pop.mailserver.com"); !connect_res)
            {
                print_error(connect_res.error());
                co_return;
            }
            if (auto greeting_res = co_await conn.read_greeting(); !greeting_res)
            {
                print_error(greeting_res.error());
                co_return;
            }
            // modify to use real account
            if (auto login_res = co_await conn.login("mailxx@mailserver.com", "mailxxpass"); !login_res)
            {
                print_error(login_res.error());
                co_return;
            }
            // remove first message from mailbox
            if (auto dele_res = co_await conn.dele(1); !dele_res)
            {
                print_error(dele_res.error());
                co_return;
            }
            if (auto quit_res = co_await conn.quit(); !quit_res)
            {
                print_error(quit_res.error());
                co_return;
            }
            co_return;
        },
        boost::asio::detached);

    io_ctx.run();
    return EXIT_SUCCESS;
}

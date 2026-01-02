/*

smtps_simple_msg.cpp
--------------------

Connects to an SMTP server via START_TLS and sends a simple message.


Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/


#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include "example_util.hpp"
#include <mailxx/mime/message.hpp>
#include <mailxx/net/tls_mode.hpp>
#include <mailxx/smtp/client.hpp>


using mailxx::message;
using mailxx::mail_address;
using mailxx::smtp::auth_method;
using mailxx::smtp::client;
int main()
{
    boost::asio::io_context io_ctx;
    boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tls_client);

    boost::asio::co_spawn(io_ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            // create mail message
            message msg;
            msg.from(mail_address("mailxx library", "mailxx@gmail.com"));// set the correct sender name and address
            msg.add_recipient(mail_address("mailxx library", "mailxx@gmail.com"));// set the correct recipent name and address
            msg.subject("smtps simple message");
            msg.content("Hello, World!");

            // connect to server
            mailxx::smtp::options options;
            options.tls.use_default_verify_paths = true;
            options.tls.verify = mailxx::net::verify_mode::peer;
            options.tls.verify_host = true;
            options.auto_starttls = true;

            client conn(io_ctx.get_executor(), options);
            if (auto connect_res = co_await conn.connect("smtp.gmail.com", "587",
                mailxx::net::tls_mode::starttls, &ssl_ctx, "smtp.gmail.com"); !connect_res)
            {
                print_error(connect_res.error());
                co_return;
            }

            // modify username/password to use real credentials
            if (auto auth_res = co_await conn.authenticate("mailxx@gmail.com", "mailxxpass", auth_method::login); !auth_res)
            {
                print_error(auth_res.error());
                co_return;
            }
            if (auto send_res = co_await conn.send(msg); !send_res)
            {
                print_error(send_res.error());
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

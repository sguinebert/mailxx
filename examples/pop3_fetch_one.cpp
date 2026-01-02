/*

pop3s_fetch_one.cpp
-------------------

Connects to POP3 server via SSL and fetches the first message from mailbox.


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
#include <mailxx/pop3/client.hpp>


using mailxx::codec;
using mailxx::message;
using mailxx::pop3::client;
using std::cout;
using std::endl;


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
            if (auto connect_res = co_await conn.connect("pop.mail.yahoo.com", "995",
                mailxx::net::tls_mode::implicit, &ssl_ctx, "pop.mail.yahoo.com"); !connect_res)
            {
                print_error(connect_res.error());
                co_return;
            }
            if (auto greeting_res = co_await conn.read_greeting(); !greeting_res)
            {
                print_error(greeting_res.error());
                co_return;
            }
            // modify to use existing yahoo account
            if (auto login_res = co_await conn.login("mailxx@yahoo.com", "mailxxpass"); !login_res)
            {
                print_error(login_res.error());
                co_return;
            }

            auto retr_res = co_await conn.retr(1);
            if (!retr_res)
            {
                print_error(retr_res.error());
                co_return;
            }
            std::string raw = retr_res.value();
            message msg;
            msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
            auto parse_res = msg.parse(raw);
            if (!parse_res)
            {
                print_error(parse_res.error());
                co_return;
            }
            cout << msg.subject() << endl;

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

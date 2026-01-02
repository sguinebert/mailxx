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
#include "example_util.hpp"
#include <mailxx/imap/client.hpp>
#include <mailxx/mime/message.hpp>
#include <mailxx/net/tls_mode.hpp>


using mailxx::codec;
using mailxx::message;
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
            auto connect_res = co_await conn.connect("imap.zoho.com", "993",
                mailxx::net::tls_mode::implicit, &ssl_ctx, "imap.zoho.com");
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

            auto login_res = co_await conn.login("mailxx@zoho.com", "mailxxpass");
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

            auto fetch_res = co_await conn.fetch("1", "BODY[]");
            if (!fetch_res)
            {
                print_error(fetch_res.error());
                co_return;
            }
            const auto& fetch_resp = fetch_res.value();
            if (!fetch_resp.literals.empty())
            {
                message msg;
                msg.line_policy(codec::line_len_policy_t::RECOMMENDED);
                auto parse_res = msg.parse(fetch_resp.literals.front());
                if (!parse_res)
                {
                    print_error(parse_res.error());
                    co_return;
                }
                cout << "msg.subject()=" << msg.subject() << endl;
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

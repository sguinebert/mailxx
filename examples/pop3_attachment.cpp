/*

pop3s_attachment.cpp
--------------------

Fetches attachments of a message from a POP3 server via TLS.

For this sample to be executed properly, use the message sent by `smtps_attachment.cpp`.


Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#include <fstream>
#include <iostream>
#include <string>
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
using mailxx::string_t;
using mailxx::pop3::client;
using std::cout;
using std::endl;
using std::ofstream;
using std::string;


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
            if (auto connect_res = co_await conn.connect("pop3.mailserver.com", "995",
                mailxx::net::tls_mode::implicit, &ssl_ctx, "pop3.mailserver.com"); !connect_res)
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
            ofstream ofs1("alepho.png", std::ios::binary);
            string_t att1;
            auto att1_res = msg.attachment(1, ofs1, att1);
            if (!att1_res)
            {
                print_error(att1_res.error());
                co_return;
            }
            ofstream ofs2("infiniti.png", std::ios::binary);
            string_t att2;
            auto att2_res = msg.attachment(2, ofs2, att2);
            if (!att2_res)
            {
                print_error(att2_res.error());
                co_return;
            }
            cout << "Received message with subject `" << msg.subject() << "` and attached files `" <<
                att1 << "` and `" << att2 << "` saved as `alepho.png` and `infiniti.png`." << endl;

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

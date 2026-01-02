/*

smtps_attachment.cpp
--------------------
 
Connects to an SMTP server via SSL and sends a message with attached files.

 
Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#include <iostream>
#include <fstream>
#include <list>
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
using mailxx::string_t;
using mailxx::mail_address;
using mailxx::smtp::auth_method;
using mailxx::smtp::client;
using std::ifstream;
using std::string;
using std::tuple;
using std::make_tuple;
using std::list;


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
            msg.subject("smtps message with attachment");
            msg.content("Here are Aleph0 and Infinity pictures.");

            ifstream ifs1("aleph0.png", std::ios::binary);
            ifstream ifs2("infinity.png", std::ios::binary);
            list<tuple<std::istream&, string_t, message::content_type_t>> atts;
            atts.push_back(make_tuple(std::ref(ifs1), "aleph0.png", message::content_type_t(message::media_type_t::IMAGE, "png")));
            atts.push_back(make_tuple(std::ref(ifs2), "infinity.png", message::content_type_t(message::media_type_t::IMAGE, "png")));
            auto attach_res = msg.attach(atts);
            if (!attach_res)
            {
                print_error(attach_res.error());
                co_return;
            }

            // use a server to login over tls connectivity
            mailxx::smtp::options options;
            options.tls.use_default_verify_paths = true;
            options.tls.verify = mailxx::net::verify_mode::peer;
            options.tls.verify_host = true;
            options.auto_starttls = true;

            client conn(io_ctx.get_executor(), options);
            if (auto connect_res = co_await conn.connect("smtp.mailserver.com", "587",
                mailxx::net::tls_mode::starttls, &ssl_ctx, "smtp.mailserver.com"); !connect_res)
            {
                print_error(connect_res.error());
                co_return;
            }
            // modify username/password to use real credentials
            if (auto auth_res = co_await conn.authenticate("mailxx@mailserver.com", "mailxxpass", auth_method::login); !auth_res)
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

/*

smtps_multipart.cpp
-------------------

Connects to an SMTP server via START_TLS and sends a multipart message.


Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#include <iostream>
#include <fstream>
#include <sstream>
#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <mailxx/mime/message.hpp>
#include <mailxx/net/tls_mode.hpp>
#include <mailxx/smtp/client.hpp>


using mailxx::message;
using mailxx::mail_address;
using mailxx::mime;
using mailxx::smtp::auth_method;
using mailxx::smtp::client;
using mailxx::smtp::error;
using mailxx::net::dialog_error;
using std::cout;
using std::endl;
using std::ifstream;
using std::ostringstream;


int main()
{
    boost::asio::io_context io_ctx;
    boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tls_client);

    boost::asio::co_spawn(io_ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            try
            {
                // create mail message
                message msg;
                msg.from(mail_address("mailxx library", "mailxx@mailserver.com"));// set the correct sender name and address
                msg.add_recipient(mail_address("mailxx library", "mailxx@mailserver.com"));// set the correct recipent name and address
                msg.subject("smtps multipart message");
                msg.content_type(message::media_type_t::MULTIPART, "related");
                msg.content_type().boundary("012456789@mailxx.dev");

                mime title;
                title.content_type(message::media_type_t::TEXT, "html", "utf-8");
                title.content_transfer_encoding(mime::content_transfer_encoding_t::BIT_8);
                title.content("<html><head></head><body><h1>??????, ?????!</h1></body></html>");

                ifstream ifs("aleph0.png");
                ostringstream ofs;
                ofs << ifs.rdbuf();

                mime img;
                img.content_type(message::media_type_t::IMAGE, "png");
                img.content_transfer_encoding(mime::content_transfer_encoding_t::BASE_64);
                img.content_disposition(mime::content_disposition_t::INLINE);
                img.content(ofs.str());
                img.name("a0.png");

                msg.add_part(title);
                msg.add_part(img);

                // connect to server over start tls
                mailxx::smtp::options options;
                options.tls.use_default_verify_paths = true;
                options.tls.verify = mailxx::net::verify_mode::peer;
                options.tls.verify_host = true;
                options.auto_starttls = true;

                client conn(io_ctx.get_executor(), options);
                co_await conn.connect("smtp.mailserver.com", "587",
                    mailxx::net::tls_mode::starttls, &ssl_ctx, "smtp.mailserver.com");

                // modify username/password to use real credentials
                co_await conn.authenticate("mailxx@mailserver.com", "mailxxpass", auth_method::login);
                co_await conn.send(msg);
                co_await conn.quit();
            }
            catch (error& exc)
            {
                cout << exc.what() << endl;
            }
            catch (dialog_error& exc)
            {
                cout << exc.what() << endl;
            }
            co_return;
        },
        boost::asio::detached);

    io_ctx.run();
    return EXIT_SUCCESS;
}

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

boost::asio::awaitable<void> send_email(boost::asio::io_context& io_ctx, boost::asio::ssl::context& ssl_ctx)
{
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

    if (auto auth_res = co_await conn.authenticate("user@gmail.com", "password", auth_method::login); !auth_res)
    {
        print_error(auth_res.error());
        co_return;
    }

    message msg;
    msg.from(mail_address("Sender", "user@gmail.com"));
    msg.add_recipient(mail_address("Recipient", "recipient@example.com"));
    msg.subject("Test from mailxx async");
    msg.content("Hello, World!");

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

    std::cout << "Email sent successfully!" << std::endl;
}

int main()
{
    boost::asio::io_context io_ctx;
    boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tls_client);

    boost::asio::co_spawn(io_ctx, send_email(io_ctx, ssl_ctx), boost::asio::detached);
    io_ctx.run();
    return 0;
}

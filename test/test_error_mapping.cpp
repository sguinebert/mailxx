/*

test_error_mapping.cpp
----------------------

Copyright (C) 2025, Sylvain Guinebert.

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/


#define BOOST_TEST_MODULE error_mapping_test

#include <boost/test/unit_test.hpp>

#include <mailxx/net/error_mapping.hpp>
#include <mailxx/smtp/error_mapping.hpp>


BOOST_AUTO_TEST_CASE(net_error_mapping)
{
    BOOST_TEST(mailxx::to_string(mailxx::net::map_net_error(
        mailxx::net::io_stage::read,
        mailxx::asio::error::operation_aborted,
        true)) == "net_timeout");

    BOOST_TEST(mailxx::to_string(mailxx::net::map_net_error(
        mailxx::net::io_stage::read,
        mailxx::asio::error::operation_aborted,
        false)) == "net_cancelled");

    BOOST_TEST(mailxx::to_string(mailxx::net::map_net_error(
        mailxx::net::io_stage::read,
        mailxx::asio::error::eof,
        false)) == "net_eof");

    BOOST_TEST(mailxx::to_string(mailxx::net::map_net_error(
        mailxx::net::io_stage::connect,
        mailxx::asio::error::connection_refused,
        false)) == "net_connection_refused");

    BOOST_TEST(mailxx::to_string(mailxx::net::map_net_error(
        mailxx::net::io_stage::resolve,
        mailxx::asio::error::host_not_found,
        false)) == "net_resolve_failed");
}

BOOST_AUTO_TEST_CASE(smtp_error_mapping)
{
    using mailxx::smtp::command_kind;

    BOOST_TEST(mailxx::to_string(mailxx::smtp::map_smtp_reply(command_kind::rcpt_to, 550)) ==
        "smtp_rejected_recipient");

    BOOST_TEST(mailxx::to_string(mailxx::smtp::map_smtp_reply(command_kind::auth, 535)) ==
        "smtp_auth_failed");

    BOOST_TEST(mailxx::to_string(mailxx::smtp::map_smtp_reply(command_kind::data_cmd, 503)) ==
        "smtp_data_rejected");

    BOOST_TEST(mailxx::to_string(mailxx::smtp::map_smtp_reply(command_kind::other, 421)) ==
        "smtp_service_not_available");

    BOOST_TEST(mailxx::to_string(mailxx::smtp::map_smtp_reply(command_kind::other, 450)) ==
        "smtp_temporary_failure");

    BOOST_TEST(mailxx::to_string(mailxx::smtp::map_smtp_reply(command_kind::other, 550)) ==
        "smtp_permanent_failure");
}

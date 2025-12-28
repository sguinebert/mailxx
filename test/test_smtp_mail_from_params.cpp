/*

test_smtp_mail_from_params.cpp
-------------------------------

Copyright (C) 2025, Sylvain Guinebert.

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#define BOOST_TEST_MODULE smtp_mail_from_params_test

#include <boost/test/unit_test.hpp>
#include <mailxx/smtp/types.hpp>


BOOST_AUTO_TEST_CASE(smtp_mail_from_extensions_all)
{
    mailxx::smtp::detail::mail_extension_flags flags;
    flags.use_size = true;
    flags.use_smtputf8 = true;
    flags.use_8bitmime = true;
    flags.supports_size = true;
    flags.supports_smtputf8 = true;
    flags.supports_8bitmime = true;

    const std::string cmd = mailxx::smtp::detail::build_mail_from_command(
        "alice@example.com", 123, true, true, flags);
    BOOST_TEST(cmd == "MAIL FROM: <alice@example.com> SIZE=123 SMTPUTF8 BODY=8BITMIME");
}

BOOST_AUTO_TEST_CASE(smtp_mail_from_extensions_filtered)
{
    mailxx::smtp::detail::mail_extension_flags flags;
    flags.use_size = true;
    flags.use_smtputf8 = true;
    flags.use_8bitmime = true;
    flags.supports_size = true;
    flags.supports_smtputf8 = true;
    flags.supports_8bitmime = false;

    const std::string cmd = mailxx::smtp::detail::build_mail_from_command(
        "bob@example.com", 42, true, false, flags);
    BOOST_TEST(cmd == "MAIL FROM: <bob@example.com> SIZE=42");
}

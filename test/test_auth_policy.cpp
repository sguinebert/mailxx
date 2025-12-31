/*

test_auth_policy.cpp
--------------------

Copyright (C) 2025, Sylvain Guinebert.

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#define BOOST_TEST_MODULE auth_policy_test

#include <boost/test/unit_test.hpp>
#include <mailxx/detail/auth_policy.hpp>
#include <mailxx/imap/types.hpp>


BOOST_AUTO_TEST_CASE(auth_policy_requires_tls)
{
    mailxx::imap::options opts;
    opts.require_tls_for_auth = true;
    opts.allow_cleartext_auth = false;

    auto res = mailxx::detail::ensure_auth_allowed(false, opts, mailxx::errc::imap_invalid_state);
    BOOST_TEST(!res.has_value());
    BOOST_TEST(mailxx::to_string(res.error().code) == "imap_invalid_state");
    BOOST_TEST(mailxx::detail::ensure_auth_allowed(true, opts, mailxx::errc::imap_invalid_state).has_value());
}

BOOST_AUTO_TEST_CASE(auth_policy_allows_opt_in)
{
    mailxx::imap::options opts;
    opts.require_tls_for_auth = true;
    opts.allow_cleartext_auth = true;

    BOOST_TEST(mailxx::detail::ensure_auth_allowed(false, opts, mailxx::errc::imap_invalid_state).has_value());
}

BOOST_AUTO_TEST_CASE(auth_policy_disabled)
{
    mailxx::imap::options opts;
    opts.require_tls_for_auth = false;
    opts.allow_cleartext_auth = false;

    BOOST_TEST(mailxx::detail::ensure_auth_allowed(false, opts, mailxx::errc::imap_invalid_state).has_value());
}

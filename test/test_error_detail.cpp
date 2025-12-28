/*

test_error_detail.cpp
---------------------

Copyright (C) 2025, Sylvain Guinebert.

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#define BOOST_TEST_MODULE error_detail_test

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

#include <mailxx/detail/error_detail.hpp>


BOOST_AUTO_TEST_CASE(error_detail_add_lines)
{
    mailxx::detail::error_detail detail;
    std::vector<std::string> lines = {"alpha", "beta"};
    detail.add_lines("line", lines);
    BOOST_TEST(detail.str() == "line0=alpha\nline1=beta\n");
}

BOOST_AUTO_TEST_CASE(error_detail_add_lines_redact)
{
    mailxx::detail::error_detail detail;
    std::vector<std::string> lines = {"PASS secret", "AUTH PLAIN dGVzdA=="};
    detail.add_lines("line", lines, true);
    BOOST_TEST(detail.str() == "line0=PASS <redacted>\nline1=AUTH PLAIN <redacted>\n");
}

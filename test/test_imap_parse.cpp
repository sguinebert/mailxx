/*

test_imap_parse.cpp
-------------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#define BOOST_TEST_MODULE imap_parse_test

#include <boost/test/unit_test.hpp>
#include <mailxx/imap/types.hpp>


BOOST_AUTO_TEST_CASE(imap_parse_exists_recent)
{
    mailxx::imap::mailbox_stat stat;
    mailxx::imap::parse_mailbox_stat("* 23 EXISTS", stat);
    mailxx::imap::parse_mailbox_stat("* 7 RECENT", stat);

    BOOST_TEST(stat.messages_no == 23u);
    BOOST_TEST(stat.recent == 7u);
}

BOOST_AUTO_TEST_CASE(imap_parse_ok_items)
{
    mailxx::imap::mailbox_stat stat;
    mailxx::imap::parse_mailbox_stat("* OK [UNSEEN 12] unseen", stat);
    mailxx::imap::parse_mailbox_stat("* OK [UIDNEXT 33] next", stat);
    mailxx::imap::parse_mailbox_stat("* OK [UIDVALIDITY 12345] valid", stat);

    BOOST_TEST(stat.unseen == 12u);
    BOOST_TEST(stat.uid_next == 33u);
    BOOST_TEST(stat.uid_validity == 12345u);
}

BOOST_AUTO_TEST_CASE(imap_parse_search_ids)
{
    auto ids = mailxx::imap::parse_search_ids("* SEARCH 1 2 42");
    BOOST_TEST(ids.size() == 3u);
    BOOST_TEST(ids[0] == 1u);
    BOOST_TEST(ids[1] == 2u);
    BOOST_TEST(ids[2] == 42u);

    auto empty = mailxx::imap::parse_search_ids("* SEARCH");
    BOOST_TEST(empty.empty());

    auto not_search = mailxx::imap::parse_search_ids("* OK [UIDVALIDITY 1]");
    BOOST_TEST(not_search.empty());
}

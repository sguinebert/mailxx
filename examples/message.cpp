/*

message.cpp
-----------

Various encodings when dealing with the message.
The example keeps code snippets in the various encodings. To see them properly, change the file encoding as marked in the snippet.


Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/


#include <cstdlib>
#include <iostream>
#include <mailxx/mime/mailboxes.hpp>
#include <mailxx/mime/message.hpp>


using std::cout;
using std::endl;
using std::string;
using mailxx::string_t;
using mailxx::mail_address;
using mailxx::mime;
using mailxx::message;


int main()
{
    auto require_ok = [](auto&& res, const char* action) {
        if (!res)
        {
            std::cerr << action << " error: " << res.error().message;
            if (!res.error().detail.empty())
                std::cerr << ": " << res.error().detail;
            std::cerr << '\n';
            return false;
        }
        return true;
    };

    // Set the file encoding to UTF-8 to match this snippet.
    {
        message msg;
        msg.from(mail_address("mail io", "contact@mailxx.dev"));
        msg.add_recipient(mail_address("mail io", "contact@mailxx.dev"));
        // The subject is encoded as Quoted Printable because it is explicitly set.
        msg.subject("Hello, World!", mailxx::codec::codec_t::QUOTED_PRINTABLE);
        msg.content("Hello, World!");
        string msg_str;
        if (!require_ok(msg.format(msg_str), "format"))
            return EXIT_FAILURE;
        cout << msg_str << endl;
        // The subject is printed as `=?ASCII?Q?Hello,_World!?=`
    }

    // Set the file encoding to UTF-8 to match this snippet.
    {
        message msg;
        msg.from(mail_address("mail io", "contact@mailxx.dev"));
        msg.add_recipient(mail_address("mail io", "contact@mailxx.dev"));
        // The subject remains in 8bit because such header is set.
        msg.subject("Hello, World!", mailxx::codec::codec_t::UTF8);
        msg.content("Hello, World!");
        string msg_str;
        if (!require_ok(msg.format(msg_str), "format"))
            return EXIT_FAILURE;
        cout << msg_str << endl;
    }

    // Set the file encoding to ISO-8859-2 to match this snippet.
    {
        message msg;
        msg.from(mail_address("mail io", "contact@mailxx.dev"));
        msg.add_recipient(mail_address("mail io", "contact@mailxx.dev"));
        msg.content_transfer_encoding(mime::content_transfer_encoding_t::QUOTED_PRINTABLE);
        msg.subject_raw(string_t("Hello, World!", "iso-8859-2"));
        msg.content("Hello, World!");
        string msg_str;
        if (!require_ok(msg.format(msg_str), "format"))
            return EXIT_FAILURE;
        cout << msg_str << endl;
        // The subject is printed as `Hello, World!` in the ISO-8859-2 encoding.
    }

    // Set the file encoding to ISO-8859-5 to match this snippet.
    {
        message msg;
        msg.from(mail_address("mail io", "contact@mailxx.dev"));
        msg.add_recipient(mail_address("mail io", "contact@mailxx.dev"));
        msg.content_transfer_encoding(mime::content_transfer_encoding_t::BASE_64);
        msg.subject_raw(string_t("Hello, World!", "iso-8859-5"));
        msg.content("Hello, World!");
        string msg_str;
        if (!require_ok(msg.format(msg_str), "format"))
            return EXIT_FAILURE;
        cout << msg_str << endl;
    }

    // Set the file encoding to UTF-8 to match this snippet.
    {
        message msg;
        msg.from(mail_address("mail io", "contact@mailxx.dev"));
        msg.add_recipient(mail_address("mail io", "contact@mailxx.dev"));
        msg.content_transfer_encoding(mime::content_transfer_encoding_t::BASE_64);
        msg.subject_raw(string_t("Hello, World!", "utf-8",
            mailxx::codec::codec_t::QUOTED_PRINTABLE));
        msg.content("Hello, World!");
        string msg_str;
        if (!require_ok(msg.format(msg_str), "format"))
            return EXIT_FAILURE;
        cout << msg_str << endl;
        // The subject is printed as `=?UTF-8?Q?Hello,_World!?=`.
    }

    {
        string msg_str = "From: mail io <contact@mailxx.dev>\r\n"
            "To: mail io <contact@mailxx.dev>\r\n"
            "Date: Sat, 18 Jun 2022 05:56:34 +0000\r\n"
            "Subject: =?ISO-8859-2?Q?Hello,_World!?=\r\n"
            "\r\n"
            "Hello, World!\r\n";
        message msg;
        if (!require_ok(msg.parse(msg_str), "parse"))
            return EXIT_FAILURE;
        cout << msg.subject() << endl;
        // The subject is printed as `Hello, World!` in the ISO-8859-2 encoding.
    }

    {
        string msg_str = "From: mail io <contact@mailxx.dev>\r\n"
            "To: mail io <contact@mailxx.dev>\r\n"
            "Date: Sat, 18 Jun 2022 05:56:34 +0000\r\n"
            "Subject: =?ISO-8859-5?Q?Hello,_World!?=\r\n"
            "\r\n"
            "Hello, World!\r\n";
        message msg;
        if (!require_ok(msg.parse(msg_str), "parse"))
            return EXIT_FAILURE;
        cout << msg.subject() << endl;
        // The subject is printed as `Hello, World!` in the ISO-8859-5 encoding.
    }

    {
        string msg_str = "From: mail io <contact@mailxx.dev>\r\n"
            "To: mail io <contact@mailxx.dev>\r\n"
            "Date: Sat, 18 Jun 2022 05:56:34 +0000\r\n"
            "Subject: =?UTF-8?Q?Hello,_World!?=\r\n"
            "\r\n"
            "Hello, World!\r\n";
        message msg;
        msg.line_policy(mailxx::codec::line_len_policy_t::MANDATORY);
        if (!require_ok(msg.parse(msg_str), "parse"))
            return EXIT_FAILURE;
        cout << msg.subject() << endl;
        // The subject is printed as `Hello, World!` in the UTF-8 encoding.
    }

    return EXIT_SUCCESS;
}

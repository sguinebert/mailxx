/*

mailxx.cppm
-----------

C++20 root module interface for mailxx library.
This module re-exports all mailxx submodules for convenient single-import usage.

Usage:
    import mailxx;           // Import everything
    // or selectively:
    import mailxx.smtp;      // Just SMTP client
    import mailxx.imap;      // Just IMAP client
    import mailxx.pop3;      // Just POP3 client
    import mailxx.mime;      // Just MIME/message handling
    import mailxx.codec;     // Just encoding/decoding
    import mailxx.net;       // Just networking primitives

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/

export module mailxx;

// Re-export all submodules
export import mailxx.codec;
export import mailxx.net;
export import mailxx.mime;
export import mailxx.smtp;
export import mailxx.pop3;
export import mailxx.imap;

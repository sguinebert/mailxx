/*

auth_policy.hpp
---------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/

#pragma once

#include <mailxx/detail/log.hpp>
#include <mailxx/net/dialog.hpp>

namespace mailxx::detail
{

template <typename Error = mailxx::net::dialog_error, typename Options>
inline void ensure_auth_allowed(bool is_tls, const Options& options)
{
    if (is_tls || !options.require_tls_for_auth)
        return;
    if (options.allow_cleartext_auth)
    {
        MAILXX_WARN("AUTH without TLS allowed by configuration.");
        return;
    }
    throw Error("TLS required for authentication; call start_tls() or use tls_mode::implicit", "");
}

} // namespace mailxx::detail

#pragma once

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/result.hpp>
#include <mailxx/net/tls_options.hpp>

namespace mailxx::net
{

/**
Configure the TLS trust store for a context.
**/
inline result<void> configure_trust_store(mailxx::asio::ssl::context& ctx, const tls_options& options)
{
    mailxx::asio::error_code ec;
    if (options.use_default_verify_paths)
    {
        ctx.set_default_verify_paths(ec);
        if (ec)
            return fail<void>(errc::tls_verify_failed, "TLS trust store configuration failed.", ec.message(), ec);
    }

    for (const auto& file : options.ca_files)
    {
        if (!file.empty())
        {
            ctx.load_verify_file(file, ec);
            if (ec)
                return fail<void>(errc::tls_verify_failed, "TLS trust store configuration failed.", ec.message(), ec);
        }
    }

    for (const auto& path : options.ca_paths)
    {
        if (!path.empty())
        {
            ctx.add_verify_path(path, ec);
            if (ec)
                return fail<void>(errc::tls_verify_failed, "TLS trust store configuration failed.", ec.message(), ec);
        }
    }
    return ok();
}

} // namespace mailxx::net

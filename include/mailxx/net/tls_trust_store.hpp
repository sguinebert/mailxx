#pragma once

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/net/tls_options.hpp>

namespace mailxx::net
{

/**
Configure the TLS trust store for a context.
**/
inline void configure_trust_store(mailxx::asio::ssl::context& ctx, const tls_options& options)
{
    if (options.use_default_verify_paths)
        ctx.set_default_verify_paths();

    for (const auto& file : options.ca_files)
    {
        if (!file.empty())
            ctx.load_verify_file(file);
    }

    for (const auto& path : options.ca_paths)
    {
        if (!path.empty())
            ctx.add_verify_path(path);
    }
}

} // namespace mailxx::net

#pragma once

namespace mailxx::net
{

/**
TLS mode for protocol connections.
**/
enum class tls_mode
{
    none,
    starttls,
    implicit
};

} // namespace mailxx::net

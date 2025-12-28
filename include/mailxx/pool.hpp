/*

pool.hpp
--------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

Connection pooling for mailxx clients.

*/

#pragma once

#include <mailxx/pool/pool_config.hpp>
#include <mailxx/pool/connection_pool.hpp>
#include <mailxx/pool/smtp_pool.hpp>
// #include <mailxx/pool/imap_pool.hpp>  // Requires imap_client refactoring

/**
 * @file pool.hpp
 * @brief Connection pooling for high-throughput email operations.
 * 
 * @section Overview
 * 
 * The pool module provides connection pooling for SMTP (and eventually IMAP)
 * clients. This is essential for high-volume email operations where creating
 * a new connection for each operation would be prohibitively expensive.
 * 
 * @section Benefits
 * 
 * - **Performance**: Reuse existing TCP+TLS connections (saves ~200ms per email)
 * - **Resource efficiency**: Limit concurrent connections to prevent exhaustion
 * - **Reliability**: Automatic connection validation and recycling
 * - **Monitoring**: Built-in statistics for observability
 * 
 * @section Usage
 * 
 * @subsection SingleMessage Single Message Sending
 * 
 * @code
 * #include <mailxx/pool.hpp>
 * 
 * asio::io_context ctx;
 * ssl::context tls_ctx(ssl::context::tlsv13_client);
 * 
 * mailxx::pool::smtp_pool pool(ctx.get_executor());
 * pool.configure("smtp.gmail.com", "587", tls_ctx, {"user@gmail.com", "app_password"});
 * 
 * co_await pool.warmup();  // Pre-create connections
 * 
 * mailxx::message msg;
 * // ... configure message ...
 * 
 * auto reply = co_await pool.send(msg);
 * @endcode
 * 
 * @subsection BatchSending Batch Sending
 * 
 * @code
 * std::vector<mailxx::message> messages;
 * // ... populate messages ...
 * 
 * auto results = co_await pool.send_batch(messages);
 * 
 * std::cout << "Success rate: " << results.success_rate() << "%\n";
 * for (const auto& r : results.results) {
 *     if (!r.success) {
 *         std::cerr << "Message " << r.index << " failed: " << r.error << "\n";
 *     }
 * }
 * @endcode
 * 
 * @subsection CustomOperations Custom Operations
 * 
 * @code
 * // Acquire a connection for custom operations
 * auto conn = co_await pool.acquire();
 * 
 * // Use the connection directly
 * co_await conn->send(msg1);
 * co_await conn->rset();
 * co_await conn->send(msg2);
 * 
 * // Connection automatically returned to pool when 'conn' goes out of scope
 * @endcode
 * 
 * @subsection Configuration Configuration Options
 * 
 * @code
 * // Use preset configurations
 * auto config = mailxx::pool::pool_config::high_traffic();
 * 
 * // Or customize
 * mailxx::pool::pool_config config;
 * config.min_connections = 5;
 * config.max_connections = 50;
 * config.idle_timeout = std::chrono::seconds{120};
 * config.validate_on_acquire = false;  // Faster but riskier
 * 
 * mailxx::pool::smtp_pool pool(executor, config);
 * @endcode
 * 
 * @subsection Monitoring Monitoring
 * 
 * @code
 * auto stats = pool.stats();
 * 
 * std::cout << "Pool utilization: " << (stats.utilization() * 100) << "%\n";
 * std::cout << "Hit rate: " << (stats.hit_rate() * 100) << "%\n";
 * std::cout << "Connections created: " << stats.connections_created << "\n";
 * std::cout << "Average wait time: " << stats.avg_wait_time.count() << "µs\n";
 * @endcode
 * 
 * @section BestPractices Best Practices
 * 
 * 1. **Call warmup()** after configure() to pre-create connections
 * 2. **Use send_batch_single_connection()** for messages to the same domain
 * 3. **Disable validate_on_acquire** for maximum throughput (if reliability allows)
 * 4. **Monitor stats()** to tune pool size for your workload
 * 5. **Call drain()** before shutting down to cleanly close connections
 * 
 * @section ThreadSafety Thread Safety
 * 
 * - Pool operations are thread-safe (internally synchronized)
 * - Each pooled_connection should only be used by one coroutine at a time
 * - Statistics access is thread-safe
 */

namespace mailxx::pool
{

/**
 * @brief Pool module version.
 */
inline constexpr struct
{
    int major = 1;
    int minor = 0;
    int patch = 0;
} version;

} // namespace mailxx::pool

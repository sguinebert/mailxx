/*

pool/pool_config.hpp
--------------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/

#pragma once

#include <cstddef>
#include <chrono>
#include <functional>
#include <string>
#include <optional>

namespace mailxx::pool
{

/**
 * Configuration for connection pools.
 */
struct pool_config
{
    /// Minimum connections to keep warm (pre-created)
    std::size_t min_connections = 1;
    
    /// Maximum concurrent connections
    std::size_t max_connections = 10;
    
    /// Close idle connections after this duration (0 = never)
    std::chrono::seconds idle_timeout{300};  // 5 minutes
    
    /// Recycle connections after this duration (0 = never)
    std::chrono::seconds max_lifetime{3600};  // 1 hour
    
    /// Timeout when waiting to acquire a connection
    std::chrono::milliseconds acquire_timeout{5000};  // 5 seconds
    
    /// Validate connection (NOOP) before returning to caller
    bool validate_on_acquire = true;
    
    /// Maximum pending acquisition requests (0 = unlimited)
    std::size_t max_pending_requests = 100;
    
    /// Retry creating connections on failure
    unsigned int creation_retry_count = 3;
    
    /// Delay between creation retries
    std::chrono::milliseconds creation_retry_delay{500};
    
    // ==================== Factory Methods ====================
    
    /// Default configuration for low-traffic applications
    static pool_config low_traffic()
    {
        pool_config cfg;
        cfg.min_connections = 1;
        cfg.max_connections = 5;
        cfg.idle_timeout = std::chrono::seconds{600};
        return cfg;
    }
    
    /// Configuration for high-traffic applications
    static pool_config high_traffic()
    {
        pool_config cfg;
        cfg.min_connections = 5;
        cfg.max_connections = 50;
        cfg.idle_timeout = std::chrono::seconds{120};
        cfg.validate_on_acquire = false;  // Trust connections for speed
        return cfg;
    }
    
    /// Configuration for bulk operations (newsletters, etc.)
    static pool_config bulk_sending()
    {
        pool_config cfg;
        cfg.min_connections = 10;
        cfg.max_connections = 100;
        cfg.idle_timeout = std::chrono::seconds{60};
        cfg.max_lifetime = std::chrono::seconds{1800};  // 30 min
        cfg.validate_on_acquire = false;
        cfg.acquire_timeout = std::chrono::milliseconds{30000};
        return cfg;
    }
};


/**
 * Pool statistics for monitoring.
 */
struct pool_stats
{
    std::size_t total_connections = 0;     ///< All connections (idle + in_use)
    std::size_t idle_connections = 0;      ///< Available in pool
    std::size_t in_use_connections = 0;    ///< Currently borrowed
    std::size_t pending_requests = 0;      ///< Waiting for a connection
    
    std::size_t connections_created = 0;   ///< Total created since start
    std::size_t connections_closed = 0;    ///< Total closed since start
    std::size_t connections_recycled = 0;  ///< Closed due to max_lifetime
    std::size_t connections_failed = 0;    ///< Failed to create
    
    std::size_t acquisitions_total = 0;    ///< Total acquire() calls
    std::size_t acquisitions_immediate = 0;///< Returned immediately (had idle)
    std::size_t acquisitions_waited = 0;   ///< Had to wait for a connection
    std::size_t acquisitions_timeout = 0;  ///< Timed out waiting
    
    /// Average wait time for acquisitions that waited
    std::chrono::microseconds avg_wait_time{0};
    
    /// Pool utilization (in_use / max)
    [[nodiscard]] double utilization() const noexcept
    {
        return total_connections > 0 
            ? static_cast<double>(in_use_connections) / total_connections 
            : 0.0;
    }
    
    /// Hit rate (immediate / total)
    [[nodiscard]] double hit_rate() const noexcept
    {
        return acquisitions_total > 0
            ? static_cast<double>(acquisitions_immediate) / acquisitions_total
            : 0.0;
    }
};


/**
 * Connection metadata stored alongside each pooled connection.
 */
struct connection_metadata
{
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_used_at;
    std::size_t times_used = 0;
    
    connection_metadata()
        : created_at(std::chrono::steady_clock::now())
        , last_used_at(created_at)
    {
    }
    
    void mark_used()
    {
        last_used_at = std::chrono::steady_clock::now();
        ++times_used;
    }
    
    [[nodiscard]] std::chrono::seconds age() const
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - created_at);
    }
    
    [[nodiscard]] std::chrono::seconds idle_time() const
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - last_used_at);
    }
};


/**
 * Credentials for pool connections.
 */
struct pool_credentials
{
    std::string username;
    std::string password;
    
    pool_credentials() = default;
    pool_credentials(std::string user, std::string pass)
        : username(std::move(user)), password(std::move(pass))
    {
    }
    
    [[nodiscard]] bool empty() const noexcept
    {
        return username.empty();
    }
};


/**
 * Server endpoint configuration.
 */
struct pool_endpoint
{
    std::string host;
    std::string service;  // Port or service name
    bool use_tls = true;
    std::string tls_sni;  // SNI hostname (empty = use host)
    
    pool_endpoint() = default;
    pool_endpoint(std::string h, std::string svc, bool tls = true)
        : host(std::move(h)), service(std::move(svc)), use_tls(tls)
    {
    }
    
    pool_endpoint(std::string h, unsigned short port, bool tls = true)
        : host(std::move(h)), service(std::to_string(port)), use_tls(tls)
    {
    }
};

} // namespace mailxx::pool

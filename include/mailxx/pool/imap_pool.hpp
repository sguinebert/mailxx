/*

pool/imap_pool.hpp
------------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/

#pragma once

#if !defined(MAILXX_ENABLE_EXPERIMENTAL_POOL)
#error "mailxx::pool::imap_pool is experimental and depends on legacy IMAP. Define MAILXX_ENABLE_EXPERIMENTAL_POOL to enable it (legacy IMAP required)."
#else

#include <memory>
#include <string>
#include <optional>
#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/pool/connection_pool.hpp>
#include <mailxx/pool/pool_config.hpp>
#include <mailxx/imap/client.hpp>
#include <mailxx/net/upgradable_stream.hpp>

namespace mailxx::pool
{

using namespace mailxx::asio;

/**
 * IMAP connection pool for parallel mailbox operations.
 * 
 * Useful for:
 * - Parallel folder synchronization
 * - Bulk message operations across accounts
 * - High-throughput IMAP proxy servers
 * 
 * Note: IMAP connections are typically long-lived, so pooling is less
 * critical than for SMTP. This pool is mainly useful when you need
 * multiple simultaneous connections to the same server.
 * 
 * Usage:
 * @code
 * imap_pool pool(io_context.get_executor());
 * pool.configure("imap.gmail.com", "993", tls_ctx, {"user@gmail.com", "password"});
 * 
 * co_await pool.warmup();
 * 
 * // Parallel fetch from multiple folders
 * auto conn1 = co_await pool.acquire();
 * auto conn2 = co_await pool.acquire();
 * 
 * auto [resp1, stat1] = co_await conn1->select("INBOX");
 * auto [resp2, stat2] = co_await conn2->select("Sent");
 * @endcode
 */
class imap_pool
{
public:
    // IMAP client with TLS stream
    using stream_type = ssl::stream<mailxx::net::upgradable_stream>;
    using client_type = mailxx::imap_client<stream_type>;
    using pool_type = connection_pool<client_type>;
    using pooled_type = pooled_connection<client_type>;
    
    /**
     * Create an IMAP pool.
     * 
     * @param executor The executor for async operations
     * @param config Pool configuration
     */
    explicit imap_pool(any_io_executor executor, pool_config config = pool_config::low_traffic())
        : executor_(std::move(executor))
        , config_(std::move(config))
    {
    }
    
    /**
     * Configure the pool connection parameters.
     * 
     * @param endpoint Server endpoint
     * @param tls_ctx TLS context
     * @param credentials Authentication credentials
     * @param auth_method Authentication method
     */
    void configure(
        pool_endpoint endpoint,
        ssl::context& tls_ctx,
        pool_credentials credentials,
        mailxx::imap_base::auth_method_t auth_method = mailxx::imap_base::auth_method_t::LOGIN)
    {
        endpoint_ = std::move(endpoint);
        tls_ctx_ = &tls_ctx;
        credentials_ = std::move(credentials);
        auth_method_ = auth_method;
        
        // Create the pool
        pool_ = std::make_shared<pool_type>(
            executor_,
            config_,
            [this]() -> awaitable<std::unique_ptr<client_type>> {
                co_return co_await create_client();
            }
        );
        
        // Set validator (NOOP to check connection is alive)
        pool_->set_validator([](client_type& client) -> awaitable<bool> {
            try
            {
                auto response = co_await client.noop();
                co_return response.ok();
            }
            catch (...)
            {
                co_return false;
            }
        });
    }
    
    /**
     * Convenience configure with separate parameters.
     */
    void configure(
        const std::string& host,
        const std::string& service,
        ssl::context& tls_ctx,
        pool_credentials credentials,
        mailxx::imap_base::auth_method_t auth_method = mailxx::imap_base::auth_method_t::LOGIN)
    {
        configure(pool_endpoint{host, service, true}, tls_ctx, std::move(credentials), auth_method);
    }
    
    /**
     * Pre-create connections.
     */
    awaitable<void> warmup()
    {
        ensure_configured();
        co_await pool_->warmup();
    }
    
    /**
     * Acquire a connection from the pool.
     * Connection is not selected into any mailbox.
     */
    awaitable<pooled_type> acquire()
    {
        ensure_configured();
        co_return co_await pool_->acquire();
    }
    
    /**
     * Acquire a connection and select a mailbox.
     * 
     * @param mailbox Mailbox to select (e.g., "INBOX")
     * @return Pair of (pooled connection, mailbox stats)
     */
    awaitable<std::pair<pooled_type, mailxx::imap_base::mailbox_stat_t>> 
    acquire_with_select(const std::string& mailbox)
    {
        ensure_configured();
        
        auto conn = co_await pool_->acquire();
        
        try
        {
            auto [response, stat] = co_await conn->select(mailbox);
            co_return std::make_pair(std::move(conn), std::move(stat));
        }
        catch (...)
        {
            conn.invalidate();
            throw;
        }
    }
    
    /**
     * Execute a fetch operation using a pooled connection.
     * 
     * @param mailbox Mailbox to select
     * @param sequence Message sequence or UID range
     * @param items Items to fetch
     * @param uid Use UIDs instead of sequence numbers
     * @return Fetch response
     */
    awaitable<mailxx::imap_base::response_t> fetch(
        const std::string& mailbox,
        const std::string& sequence,
        const std::string& items,
        bool uid = false)
    {
        auto conn = co_await acquire();
        
        try
        {
            co_await conn->select(mailbox);
            auto response = co_await conn->fetch(sequence, items, uid);
            co_return response;
        }
        catch (...)
        {
            conn.invalidate();
            throw;
        }
    }
    
    /**
     * Search for messages using a pooled connection.
     */
    awaitable<std::vector<unsigned long>> search(
        const std::string& mailbox,
        const std::list<mailxx::imap_base::search_condition_t>& conditions,
        bool uid = false)
    {
        auto conn = co_await acquire();
        
        try
        {
            co_await conn->select(mailbox);
            auto [response, results] = co_await conn->search(conditions, uid);
            co_return results;
        }
        catch (...)
        {
            conn.invalidate();
            throw;
        }
    }
    
    /**
     * Drain all connections.
     */
    awaitable<void> drain()
    {
        if (pool_)
        {
            co_await pool_->drain();
        }
    }
    
    /**
     * Get pool statistics.
     */
    pool_stats stats() const
    {
        return pool_ ? pool_->stats() : pool_stats{};
    }
    
    /**
     * Get available connections count.
     */
    std::size_t available() const
    {
        return pool_ ? pool_->available() : 0;
    }
    
    /**
     * Get in-use connections count.
     */
    std::size_t in_use() const
    {
        return pool_ ? pool_->in_use() : 0;
    }
    
    /**
     * Check if configured.
     */
    bool is_configured() const noexcept
    {
        return pool_ != nullptr;
    }

private:
    void ensure_configured() const
    {
        if (!pool_)
            throw pool_error("IMAP pool not configured. Call configure() first.");
    }
    
    awaitable<std::unique_ptr<client_type>> create_client()
    {
        // Create upgradable stream and upgrade to TLS
        mailxx::net::upgradable_stream base_stream(executor_);
        
        // Resolve and connect
        tcp::resolver resolver(executor_);
        auto endpoints = co_await resolver.async_resolve(
            endpoint_.host, endpoint_.service, use_awaitable);
        co_await async_connect(base_stream.lowest_layer(), endpoints, use_awaitable);
        
        // Upgrade to TLS
        const std::string sni = endpoint_.tls_sni.empty() ? endpoint_.host : endpoint_.tls_sni;
        co_await base_stream.start_tls(*tls_ctx_, sni);
        
        // Create IMAP client with TLS stream
        // Note: The client takes ownership of the dialog/stream
        mailxx::net::dialog<mailxx::net::upgradable_stream> dlg(std::move(base_stream));
        
        // We need to create the client differently - IMAP client expects the stream
        // For now, we'll create a simplified version
        // This is a placeholder - actual implementation depends on imap_client structure
        
        throw pool_error("IMAP pool client creation not fully implemented - requires imap_client refactoring");
        
        // auto client = std::make_unique<client_type>(std::move(dlg));
        // co_await client->read_greeting();
        // co_await client->authenticate(credentials_.username, credentials_.password, auth_method_);
        // co_return client;
    }
    
    any_io_executor executor_;
    pool_config config_;
    
    pool_endpoint endpoint_;
    ssl::context* tls_ctx_ = nullptr;
    pool_credentials credentials_;
    mailxx::imap_base::auth_method_t auth_method_ = mailxx::imap_base::auth_method_t::LOGIN;
    
    std::shared_ptr<pool_type> pool_;
};

} // namespace mailxx::pool

#endif // MAILXX_ENABLE_EXPERIMENTAL_POOL

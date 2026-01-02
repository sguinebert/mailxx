/*

pool/imap_pool.hpp
------------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/

#pragma once

#if !defined(MAILXX_ENABLE_EXPERIMENTAL_POOL)
#error "mailxx::pool::imap_pool is experimental and depends on legacy IMAP. Define MAILXX_ENABLE_EXPERIMENTAL_POOL to enable it (legacy IMAP required)."
#else

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/result.hpp>
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
    // IMAP client type
    using client_type = mailxx::imap::client;
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
    mailxx::result_void configure(
        pool_endpoint endpoint,
        ssl::context& tls_ctx,
        pool_credentials credentials,
        mailxx::imap::auth_method auth_method = mailxx::imap::auth_method::login)
    {
        endpoint_ = std::move(endpoint);
        tls_ctx_ = &tls_ctx;
        credentials_ = std::move(credentials);
        auth_method_ = auth_method;
        
        // Create the pool
        pool_ = std::make_shared<pool_type>(
            executor_,
            config_,
            [this]() -> awaitable<mailxx::result<std::unique_ptr<client_type>>> {
                co_return co_await create_client();
            }
        );
        
        // Set validator (NOOP to check connection is alive)
        pool_->set_validator([](client_type& client) -> awaitable<mailxx::result<bool>> {
            auto response = co_await client.noop();
            if (!response)
                co_return mailxx::fail<bool>(std::move(response).error());
            co_return mailxx::ok(response->ok());
        });

        return mailxx::ok();
    }
    
    /**
     * Convenience configure with separate parameters.
     */
    mailxx::result_void configure(
        const std::string& host,
        const std::string& service,
        ssl::context& tls_ctx,
        pool_credentials credentials,
        mailxx::imap::auth_method auth_method = mailxx::imap::auth_method::login)
    {
        return configure(pool_endpoint{host, service, true}, tls_ctx, std::move(credentials), auth_method);
    }
    
    /**
     * Pre-create connections.
     */
    awaitable<mailxx::result_void> warmup()
    {
        auto ready = ensure_configured();
        if (!ready)
            co_return ready;
        MAILXX_TRY_CO_AWAIT(pool_->warmup());
        co_return mailxx::ok();
    }
    
    /**
     * Acquire a connection from the pool.
     * Connection is not selected into any mailbox.
     */
    awaitable<mailxx::result<pooled_type>> acquire()
    {
        auto ready = ensure_configured();
        if (!ready)
            co_return mailxx::fail<pooled_type>(std::move(ready).error());
        co_return co_await pool_->acquire();
    }
    
    /**
     * Acquire a connection and select a mailbox.
     * 
     * @param mailbox Mailbox to select (e.g., "INBOX")
     * @return Pair of (pooled connection, mailbox stats)
     */
    awaitable<mailxx::result<std::pair<pooled_type, mailxx::imap::mailbox_stat>>>
    acquire_with_select(const std::string& mailbox)
    {
        auto ready = ensure_configured();
        if (!ready)
            co_return mailxx::fail<std::pair<pooled_type, mailxx::imap::mailbox_stat>>(std::move(ready).error());

        pooled_type conn;
        MAILXX_CO_TRY_ASSIGN(conn, co_await pool_->acquire());

        auto sel_res = co_await conn->select(mailbox);
        if (!sel_res)
        {
            conn.invalidate();
            co_return mailxx::fail<std::pair<pooled_type, mailxx::imap::mailbox_stat>>(std::move(sel_res).error());
        }

        auto [response, stat] = std::move(*sel_res);
        (void)response;
        co_return mailxx::ok(std::make_pair(std::move(conn), std::move(stat)));
    }
    
    /**
     * Execute a fetch operation using a pooled connection.
     * 
     * @param mailbox Mailbox to select
     * @param sequence Message sequence or UID range
     * @param items Items to fetch
     * @param uid Use UIDs instead of sequence numbers
     * @return Result containing the fetch response
     */
    awaitable<mailxx::result<mailxx::imap::response>> fetch(
        const std::string& mailbox,
        const std::string& sequence,
        const std::string& items,
        bool uid = false)
    {
        auto ready = ensure_configured();
        if (!ready)
            co_return mailxx::fail<mailxx::imap::response>(std::move(ready).error());

        pooled_type conn;
        MAILXX_CO_TRY_ASSIGN(conn, co_await pool_->acquire());

        auto sel_res = co_await conn->select(mailbox);
        if (!sel_res)
        {
            conn.invalidate();
            co_return mailxx::fail<mailxx::imap::response>(std::move(sel_res).error());
        }

        auto fetch_res = co_await conn->fetch(sequence, items, uid);
        if (!fetch_res)
        {
            conn.invalidate();
            co_return mailxx::fail<mailxx::imap::response>(std::move(fetch_res).error());
        }

        co_return mailxx::ok(std::move(*fetch_res));
    }
    
    /**
     * Search for messages using a pooled connection.
     *
     * @param mailbox Mailbox to select
     * @param criteria Search criteria (IMAP SEARCH syntax)
     * @param uid Use UIDs instead of sequence numbers
     * @return Result containing matched message ids
     */
    awaitable<mailxx::result<std::vector<std::uint32_t>>> search(
        const std::string& mailbox,
        std::string_view criteria,
        bool uid = false)
    {
        auto ready = ensure_configured();
        if (!ready)
            co_return mailxx::fail<std::vector<std::uint32_t>>(std::move(ready).error());

        pooled_type conn;
        MAILXX_CO_TRY_ASSIGN(conn, co_await pool_->acquire());

        auto sel_res = co_await conn->select(mailbox);
        if (!sel_res)
        {
            conn.invalidate();
            co_return mailxx::fail<std::vector<std::uint32_t>>(std::move(sel_res).error());
        }

        auto search_res = co_await conn->search(criteria, uid);
        if (!search_res)
        {
            conn.invalidate();
            co_return mailxx::fail<std::vector<std::uint32_t>>(std::move(search_res).error());
        }

        auto [response, results] = std::move(*search_res);
        (void)response;
        co_return mailxx::ok(std::move(results));
    }
    
    /**
     * Drain all connections.
     */
    awaitable<mailxx::result_void> drain()
    {
        if (!pool_)
            co_return mailxx::ok();
        co_return co_await pool_->drain();
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
    mailxx::result_void ensure_configured() const
    {
        if (!pool_)
            return mailxx::fail_void(errc::pool_invalid_state, "IMAP pool not configured. Call configure() first.");
        return mailxx::ok();
    }
    
    awaitable<mailxx::result<std::unique_ptr<client_type>>> create_client()
    {
        auto client = std::make_unique<client_type>(executor_);

        auto tls_mode = endpoint_.use_tls ? mailxx::net::tls_mode::implicit : mailxx::net::tls_mode::none;
        ssl::context* tls_ctx = endpoint_.use_tls ? tls_ctx_ : nullptr;
        const std::string sni = endpoint_.tls_sni.empty() ? endpoint_.host : endpoint_.tls_sni;

        MAILXX_TRY_CO_AWAIT(client->connect(endpoint_.host, endpoint_.service, tls_mode, tls_ctx, sni));
        MAILXX_TRY_CO_AWAIT(client->read_greeting());

        if (!credentials_.empty())
        {
            mailxx::imap::credentials cred{credentials_.username, credentials_.password};
            MAILXX_TRY_CO_AWAIT(client->authenticate(std::move(cred), auth_method_));
        }

        co_return mailxx::ok(std::move(client));
    }
    
    any_io_executor executor_;
    pool_config config_;
    
    pool_endpoint endpoint_;
    ssl::context* tls_ctx_ = nullptr;
    pool_credentials credentials_;
    mailxx::imap::auth_method auth_method_ = mailxx::imap::auth_method::login;
    
    std::shared_ptr<pool_type> pool_;
};

} // namespace mailxx::pool

#endif // MAILXX_ENABLE_EXPERIMENTAL_POOL

/*

pool/smtp_pool.hpp
------------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/

#pragma once

#include <memory>
#include <span>
#include <vector>
#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/pool/connection_pool.hpp>
#include <mailxx/pool/pool_config.hpp>
#include <mailxx/pool/rate_limiter.hpp>
#include <mailxx/smtp/client.hpp>
#include <mailxx/smtp/types.hpp>

namespace mailxx::pool
{

using namespace mailxx::asio;

/**
 * Result of a batch send operation.
 */
struct batch_result
{
    struct entry
    {
        std::size_t index;           ///< Index in original batch
        bool success;                ///< Whether send succeeded
        smtp::reply reply;           ///< Server reply (if success)
        std::string error;           ///< Error message (if failed)
    };
    
    std::vector<entry> results;
    std::size_t successful = 0;
    std::size_t failed = 0;
    
    [[nodiscard]] bool all_successful() const noexcept
    {
        return failed == 0;
    }
    
    [[nodiscard]] double success_rate() const noexcept
    {
        return results.empty() ? 0.0 
            : static_cast<double>(successful) / results.size() * 100.0;
    }
};


/**
 * SMTP connection pool for high-volume sending.
 * 
 * Usage:
 * @code
 * smtp_pool pool(io_context.get_executor());
 * pool.configure("smtp.gmail.com", "587", tls_ctx, {"user@gmail.com", "password"});
 * 
 * co_await pool.warmup();
 * 
 * // Send single message
 * auto reply = co_await pool.send(message);
 * 
 * // Send batch
 * auto results = co_await pool.send_batch(messages);
 * @endcode
 */
class smtp_pool
{
public:
    using client_type = smtp::client;
    using pool_type = connection_pool<client_type>;
    using pooled_type = pooled_connection<client_type>;
    
    /**
     * Create an SMTP pool.
     * 
     * @param executor The executor for async operations
     * @param config Pool configuration (default: low_traffic)
     */
    explicit smtp_pool(any_io_executor executor, pool_config config = pool_config::low_traffic())
        : executor_(std::move(executor))
        , config_(std::move(config))
    {
    }
    
    /**
     * Configure the pool connection parameters.
     * Must be called before any send operations.
     * 
     * @param endpoint Server endpoint (host, port, TLS)
     * @param tls_ctx TLS context for secure connections
     * @param credentials Optional authentication credentials
     * @param auth_method Authentication method (default: auto_detect)
     */
    void configure(
        pool_endpoint endpoint,
        ssl::context& tls_ctx,
        std::optional<pool_credentials> credentials = std::nullopt,
        smtp::auth_method auth_method = smtp::auth_method::auto_detect)
    {
        endpoint_ = std::move(endpoint);
        tls_ctx_ = &tls_ctx;
        credentials_ = std::move(credentials);
        auth_method_ = auth_method;
        
        // Create the pool with factory
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
                auto reply = co_await client.noop();
                co_return reply.is_positive_completion();
            }
            catch (...)
            {
                co_return false;
            }
        });
    }
    
    /**
     * Convenience configure method with separate parameters.
     */
    void configure(
        const std::string& host,
        const std::string& service,
        ssl::context& tls_ctx,
        std::optional<pool_credentials> credentials = std::nullopt,
        smtp::auth_method auth_method = smtp::auth_method::auto_detect)
    {
        configure(pool_endpoint{host, service, true}, tls_ctx, std::move(credentials), auth_method);
    }
    
    /**
     * Pre-create connections (warmup).
     */
    awaitable<void> warmup()
    {
        ensure_configured();
        co_await pool_->warmup();
    }
    
    /**
     * Send a single message using a pooled connection.
     * Respects rate limiting if configured.
     * 
     * @param msg The message to send
     * @param env Optional envelope (sender/recipients override)
     * @return Server reply
     */
    awaitable<smtp::reply> send(
        const mailxx::message& msg,
        const smtp::envelope& env = smtp::envelope{})
    {
        ensure_configured();
        
        // Apply rate limiting before acquiring connection
        co_await apply_rate_limit();
        
        auto conn = co_await pool_->acquire();
        
        try
        {
            auto reply = co_await conn->send(msg, env);
            co_return reply;
        }
        catch (...)
        {
            // Connection might be broken, invalidate it
            conn.invalidate();
            throw;
        }
    }
    
    /**
     * Send a batch of messages.
     * Uses multiple connections in parallel for throughput.
     * Respects rate limiting if configured.
     * 
     * @param messages Messages to send
     * @param envs Optional envelopes (must be same size as messages or empty)
     * @return Batch results with success/failure for each message
     */
    awaitable<batch_result> send_batch(
        std::span<const mailxx::message> messages,
        std::span<const smtp::envelope> envs = {})
    {
        ensure_configured();
        
        if (!envs.empty() && envs.size() != messages.size())
            throw pool_error("Envelope count must match message count");
        
        batch_result results;
        results.results.reserve(messages.size());
        
        // Process messages with available connections
        // For simplicity, we do one at a time but with connection reuse
        // A more advanced implementation could use multiple connections in parallel
        
        pooled_type conn;
        
        for (std::size_t i = 0; i < messages.size(); ++i)
        {
            // Apply rate limiting for each message
            co_await apply_rate_limit();
            
            batch_result::entry entry;
            entry.index = i;
            
            try
            {
                // Get connection if we don't have one
                if (!conn)
                {
                    conn = co_await pool_->acquire();
                }
                
                const smtp::envelope& env = envs.empty() ? smtp::envelope{} : envs[i];
                
                entry.reply = co_await conn->send(messages[i], env);
                entry.success = true;
                ++results.successful;
                
                // RSET after each message to prepare for next
                co_await conn->rset();
            }
            catch (const std::exception& e)
            {
                entry.success = false;
                entry.error = e.what();
                ++results.failed;
                
                // Invalidate connection on error
                if (conn)
                {
                    conn.invalidate();
                    conn.release();
                }
            }
            
            results.results.push_back(std::move(entry));
        }
        
        co_return results;
    }
    
    /**
     * Send batch using a single connection (most efficient for same recipient domain).
     * Sends all messages on one connection without releasing it.
     * 
     * @param messages Messages to send
     * @return Batch results
     */
    awaitable<batch_result> send_batch_single_connection(
        std::span<const mailxx::message> messages)
    {
        ensure_configured();
        
        batch_result results;
        results.results.reserve(messages.size());
        
        auto conn = co_await pool_->acquire();
        
        for (std::size_t i = 0; i < messages.size(); ++i)
        {
            // Apply rate limiting for each message
            co_await apply_rate_limit();
            
            batch_result::entry entry;
            entry.index = i;
            
            try
            {
                entry.reply = co_await conn->send(messages[i]);
                entry.success = true;
                ++results.successful;
                
                // RSET for next message
                if (i + 1 < messages.size())
                {
                    co_await conn->rset();
                }
            }
            catch (const std::exception& e)
            {
                entry.success = false;
                entry.error = e.what();
                ++results.failed;
                
                // Try RSET to recover, or get new connection
                try
                {
                    co_await conn->rset();
                }
                catch (...)
                {
                    conn.invalidate();
                    conn.release();
                    
                    // Get new connection for remaining messages
                    if (i + 1 < messages.size())
                    {
                        try
                        {
                            conn = co_await pool_->acquire();
                        }
                        catch (...)
                        {
                            // Can't continue, mark rest as failed
                            for (std::size_t j = i + 1; j < messages.size(); ++j)
                            {
                                results.results.push_back({j, false, {}, "Connection lost"});
                                ++results.failed;
                            }
                            break;
                        }
                    }
                }
            }
            
            results.results.push_back(std::move(entry));
        }
        
        co_return results;
    }
    
    /**
     * Acquire a raw connection for custom operations.
     */
    awaitable<pooled_type> acquire()
    {
        ensure_configured();
        co_return co_await pool_->acquire();
    }
    
    /**
     * Drain all connections and shut down the pool.
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
     * Get number of available connections.
     */
    std::size_t available() const
    {
        return pool_ ? pool_->available() : 0;
    }
    
    /**
     * Get number of connections in use.
     */
    std::size_t in_use() const
    {
        return pool_ ? pool_->in_use() : 0;
    }
    
    /**
     * Check if pool is configured.
     */
    bool is_configured() const noexcept
    {
        return pool_ != nullptr;
    }

    // ========== Rate Limiting ==========

    /**
     * Enable rate limiting for send operations.
     * 
     * @param config Rate limit configuration
     * 
     * Example:
     * @code
     * pool.set_rate_limit(rate_limit_config::per_second(5));  // Max 5 emails/sec
     * pool.set_rate_limit(rate_limit_config::per_minute(100)); // Max 100 emails/min
     * @endcode
     */
    void set_rate_limit(rate_limit_config config)
    {
        if (rate_limiter_)
        {
            rate_limiter_->configure(std::move(config));
        }
        else
        {
            rate_limiter_ = std::make_unique<rate_limiter>(executor_, std::move(config));
        }
    }

    /**
     * Disable rate limiting.
     */
    void disable_rate_limit()
    {
        rate_limiter_.reset();
    }

    /**
     * Check if rate limiting is enabled.
     */
    bool has_rate_limit() const noexcept
    {
        return rate_limiter_ != nullptr && rate_limiter_->config().enabled;
    }

    /**
     * Get rate limiter (for manual control).
     * @return Pointer to rate limiter, or nullptr if disabled
     */
    rate_limiter* get_rate_limiter() noexcept
    {
        return rate_limiter_.get();
    }

private:
    void ensure_configured() const
    {
        if (!pool_)
            throw pool_error("SMTP pool not configured. Call configure() first.");
    }

    /**
     * Apply rate limiting if enabled.
     */
    awaitable<void> apply_rate_limit()
    {
        if (rate_limiter_)
        {
            co_await rate_limiter_->acquire();
        }
    }
    
    awaitable<std::unique_ptr<client_type>> create_client()
    {
        auto client = std::make_unique<client_type>(executor_);
        
        // Connect
        co_await client->connect(endpoint_.host, endpoint_.service);
        co_await client->read_greeting();
        co_await client->ehlo();
        
        // TLS if needed
        if (endpoint_.use_tls && tls_ctx_)
        {
            const std::string sni = endpoint_.tls_sni.empty() ? endpoint_.host : endpoint_.tls_sni;
            co_await client->start_tls(*tls_ctx_, sni);
            co_await client->ehlo();  // Re-EHLO after STARTTLS
        }
        
        // Authenticate if credentials provided
        if (credentials_.has_value() && !credentials_->empty())
        {
            co_await client->authenticate(
                credentials_->username, 
                credentials_->password, 
                auth_method_
            );
        }
        
        co_return client;
    }
    
    any_io_executor executor_;
    pool_config config_;
    
    pool_endpoint endpoint_;
    ssl::context* tls_ctx_ = nullptr;
    std::optional<pool_credentials> credentials_;
    smtp::auth_method auth_method_ = smtp::auth_method::auto_detect;
    
    std::shared_ptr<pool_type> pool_;
    std::unique_ptr<rate_limiter> rate_limiter_;
};

} // namespace mailxx::pool

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
#include <mailxx/detail/result.hpp>
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
    mailxx::result_void configure(
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
            [this]() -> awaitable<mailxx::result<std::unique_ptr<client_type>>> {
                co_return co_await create_client();
            }
        );
        
        // Set validator (NOOP to check connection is alive)
        pool_->set_validator([](client_type& client) -> awaitable<mailxx::result<bool>> {
            auto reply = co_await client.noop();
            if (!reply)
                co_return mailxx::fail<bool>(std::move(reply).error());
            co_return mailxx::ok(reply->is_positive_completion());
        });

        return mailxx::ok();
    }
    
    /**
     * Convenience configure method with separate parameters.
     */
    mailxx::result_void configure(
        const std::string& host,
        const std::string& service,
        ssl::context& tls_ctx,
        std::optional<pool_credentials> credentials = std::nullopt,
        smtp::auth_method auth_method = smtp::auth_method::auto_detect)
    {
        return configure(pool_endpoint{host, service, true}, tls_ctx, std::move(credentials), auth_method);
    }
    
    /**
     * Pre-create connections (warmup).
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
     * Send a single message using a pooled connection.
     * Respects rate limiting if configured.
     * 
     * @param msg The message to send
     * @param env Optional envelope (sender/recipients override)
     * @return Server reply
     */
    awaitable<mailxx::result<smtp::reply>> send(
        const mailxx::message& msg,
        const smtp::envelope& env = smtp::envelope{})
    {
        auto ready = ensure_configured();
        if (!ready)
            co_return mailxx::fail<smtp::reply>(std::move(ready).error());
        
        // Apply rate limiting before acquiring connection
        co_await apply_rate_limit();
        
        pooled_type conn;
        MAILXX_CO_TRY_ASSIGN(conn, co_await pool_->acquire());

        auto reply = co_await conn->send(msg, env);
        if (!reply)
        {
            conn.invalidate();
            co_return mailxx::fail<smtp::reply>(std::move(reply).error());
        }
        co_return std::move(*reply);
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
    awaitable<mailxx::result<batch_result>> send_batch(
        std::span<const mailxx::message> messages,
        std::span<const smtp::envelope> envs = {})
    {
        auto ready = ensure_configured();
        if (!ready)
            co_return mailxx::fail<batch_result>(std::move(ready).error());
        
        if (!envs.empty() && envs.size() != messages.size())
            co_return mailxx::fail<batch_result>(errc::pool_config_error, "Envelope count must match message count");
        
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
            
            // Get connection if we don't have one
            if (!conn)
            {
                MAILXX_CO_TRY_ASSIGN(conn, co_await pool_->acquire());
            }

            const smtp::envelope& env = envs.empty() ? smtp::envelope{} : envs[i];

            auto send_res = co_await conn->send(messages[i], env);
            if (send_res)
            {
                entry.reply = std::move(*send_res);
                entry.success = true;
                ++results.successful;

                auto rset_res = co_await conn->rset();
                if (!rset_res && conn)
                {
                    conn.invalidate();
                    conn.release();
                }
            }
            else
            {
                entry.success = false;
                entry.error = format_error(send_res.error());
                ++results.failed;

                if (conn)
                {
                    conn.invalidate();
                    conn.release();
                }
            }
            
            results.results.push_back(std::move(entry));
        }
        
        co_return mailxx::ok(std::move(results));
    }
    
    /**
     * Send batch using a single connection (most efficient for same recipient domain).
     * Sends all messages on one connection without releasing it.
     * 
     * @param messages Messages to send
     * @return Batch results
     */
    awaitable<mailxx::result<batch_result>> send_batch_single_connection(
        std::span<const mailxx::message> messages)
    {
        auto ready = ensure_configured();
        if (!ready)
            co_return mailxx::fail<batch_result>(std::move(ready).error());
        
        batch_result results;
        results.results.reserve(messages.size());

        pooled_type conn;
        auto conn_res = co_await pool_->acquire();
        if (!conn_res)
            co_return mailxx::fail<batch_result>(std::move(conn_res).error());
        conn = std::move(*conn_res);
        
        for (std::size_t i = 0; i < messages.size(); ++i)
        {
            // Apply rate limiting for each message
            co_await apply_rate_limit();
            
            batch_result::entry entry;
            entry.index = i;

            if (!conn)
            {
                auto reacquire = co_await pool_->acquire();
                if (!reacquire)
                {
                    for (std::size_t j = i; j < messages.size(); ++j)
                    {
                        results.results.push_back({j, false, {}, format_error(reacquire.error())});
                        ++results.failed;
                    }
                    break;
                }
                conn = std::move(*reacquire);
            }

            auto send_res = co_await conn->send(messages[i]);
            if (send_res)
            {
                entry.reply = std::move(*send_res);
                entry.success = true;
                ++results.successful;

                if (i + 1 < messages.size())
                {
                    auto rset_res = co_await conn->rset();
                    if (!rset_res && conn)
                    {
                        conn.invalidate();
                        conn.release();
                    }
                }
            }
            else
            {
                entry.success = false;
                entry.error = format_error(send_res.error());
                ++results.failed;

                if (conn)
                {
                    conn.invalidate();
                    conn.release();
                }
            }
            
            results.results.push_back(std::move(entry));
        }
        
        co_return mailxx::ok(std::move(results));
    }
    
    /**
     * Acquire a raw connection for custom operations.
     */
    awaitable<mailxx::result<pooled_type>> acquire()
    {
        auto ready = ensure_configured();
        if (!ready)
            co_return mailxx::fail<pooled_type>(std::move(ready).error());
        co_return co_await pool_->acquire();
    }
    
    /**
     * Drain all connections and shut down the pool.
     */
    awaitable<mailxx::result_void> drain()
    {
        if (pool_)
        {
            MAILXX_TRY_CO_AWAIT(pool_->drain());
        }
        co_return mailxx::ok();
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
    static std::string format_error(const error_info& err)
    {
        std::string msg = err.message.empty() ? std::string(to_string(err.code)) : err.message;
        if (!err.detail.empty())
        {
            if (!msg.empty())
                msg += ": ";
            msg += err.detail;
        }
        return msg;
    }

    mailxx::result_void ensure_configured() const
    {
        if (!pool_)
            return mailxx::fail_void(errc::pool_invalid_state, "SMTP pool not configured. Call configure() first.");
        return mailxx::ok();
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
    
    awaitable<mailxx::result<std::unique_ptr<client_type>>> create_client()
    {
        auto client = std::make_unique<client_type>(executor_);
        
        // Connect
        MAILXX_TRY_CO_AWAIT(client->connect(endpoint_.host, endpoint_.service));
        MAILXX_TRY_CO_AWAIT(client->read_greeting());
        MAILXX_TRY_CO_AWAIT(client->ehlo());
        
        // TLS if needed
        if (endpoint_.use_tls && tls_ctx_)
        {
            const std::string sni = endpoint_.tls_sni.empty() ? endpoint_.host : endpoint_.tls_sni;
            MAILXX_TRY_CO_AWAIT(client->start_tls(*tls_ctx_, sni));
            MAILXX_TRY_CO_AWAIT(client->ehlo());  // Re-EHLO after STARTTLS
        }
        
        // Authenticate if credentials provided
        if (credentials_.has_value() && !credentials_->empty())
        {
            MAILXX_TRY_CO_AWAIT(client->authenticate(
                credentials_->username, 
                credentials_->password, 
                auth_method_
            ));
        }
        
        co_return mailxx::ok(std::move(client));
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

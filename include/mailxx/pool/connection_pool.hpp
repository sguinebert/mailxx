/*

pool/connection_pool.hpp
------------------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/

#pragma once

#include <memory>
#include <vector>
#include <deque>
#include <functional>
#include <atomic>
#include <mutex>
#include <optional>
#include <variant>
#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/log.hpp>
#include <mailxx/detail/result.hpp>
#include <mailxx/pool/pool_config.hpp>

namespace mailxx::pool
{

using namespace mailxx::asio;


// Forward declaration
template<typename Client>
class connection_pool;


/**
 * RAII wrapper for a pooled connection.
 * Automatically returns the connection to the pool when destroyed.
 */
template<typename Client>
class pooled_connection
{
public:
    using pool_type = connection_pool<Client>;
    
    pooled_connection() = default;
    
    pooled_connection(pooled_connection&& other) noexcept
        : client_(std::move(other.client_))
        , metadata_(std::move(other.metadata_))
        , pool_(other.pool_)
        , valid_(other.valid_)
    {
        other.pool_.reset();
        other.valid_ = false;
    }
    
    pooled_connection& operator=(pooled_connection&& other) noexcept
    {
        if (this != &other)
        {
            release();
            client_ = std::move(other.client_);
            metadata_ = std::move(other.metadata_);
            pool_ = other.pool_;
            valid_ = other.valid_;
            other.pool_.reset();
            other.valid_ = false;
        }
        return *this;
    }
    
    // Non-copyable
    pooled_connection(const pooled_connection&) = delete;
    pooled_connection& operator=(const pooled_connection&) = delete;
    
    ~pooled_connection()
    {
        release();
    }
    
    /// Access the underlying client
    Client& operator*() { return *client_; }
    const Client& operator*() const { return *client_; }
    
    Client* operator->() { return client_.get(); }
    const Client* operator->() const { return client_.get(); }
    
    Client* get() { return client_.get(); }
    const Client* get() const { return client_.get(); }
    
    /// Check if connection is valid
    explicit operator bool() const noexcept { return valid_ && client_ != nullptr; }
    
    /// Mark connection as invalid (won't be returned to pool)
    void invalidate() noexcept { valid_ = false; }
    
    /// Get connection metadata
    const connection_metadata& metadata() const { return metadata_; }
    
    /// Explicitly release back to pool (normally done by destructor)
    void release()
    {
        if (client_)
        {
            metadata_.mark_used();
            if (auto pool = pool_.lock())
            {
                pool->return_connection(std::move(client_), std::move(metadata_), valid_);
            }
            client_.reset();
        }
        valid_ = false;
    }
    
private:
    friend class connection_pool<Client>;
    
    pooled_connection(std::unique_ptr<Client> client, connection_metadata meta, std::weak_ptr<pool_type> pool)
        : client_(std::move(client))
        , metadata_(std::move(meta))
        , pool_(pool)
        , valid_(true)
    {
    }
    
    std::unique_ptr<Client> client_;
    connection_metadata metadata_;
    std::weak_ptr<pool_type> pool_;
    bool valid_ = false;
};


/**
 * Generic connection pool with async support.
 * 
 * @tparam Client The client type (e.g., smtp::client, imap_client)
 */
template<typename Client>
class connection_pool : public std::enable_shared_from_this<connection_pool<Client>>
{
public:
    using client_type = Client;
    using pooled_type = pooled_connection<Client>;
    using factory_type = std::function<awaitable<mailxx::result<std::unique_ptr<Client>>>()>;
    using validator_type = std::function<awaitable<mailxx::result<bool>>(Client&)>;
    
    /**
     * Create a connection pool.
     * 
     * @param executor The executor for async operations
     * @param config Pool configuration
     * @param factory Function that creates new connections
     */
    connection_pool(any_io_executor executor, pool_config config, factory_type factory)
        : executor_(std::move(executor))
        , config_(std::move(config))
        , factory_(std::move(factory))
        , channel_(executor_, config_.max_connections)
        , shutdown_(false)
    {
        if (!factory_)
        {
            init_error_ = make_error(errc::pool_config_error, "Pool factory function is required.");
            shutdown_.store(true, std::memory_order_release);
        }
    }
    
    ~connection_pool()
    {
        // Note: Should call drain() before destruction in async context
        shutdown_.store(true, std::memory_order_release);
    }
    
    // Non-copyable, non-movable
    connection_pool(const connection_pool&) = delete;
    connection_pool& operator=(const connection_pool&) = delete;
    connection_pool(connection_pool&&) = delete;
    connection_pool& operator=(connection_pool&&) = delete;
    
    /**
     * Set a custom validator function.
     * Called before returning a connection if validate_on_acquire is true.
     */
    void set_validator(validator_type validator)
    {
        validator_ = std::move(validator);
    }
    
    /**
     * Pre-create minimum connections (warmup the pool).
     */
    awaitable<mailxx::result_void> warmup()
    {
        MAILXX_LOG_INFO("POOL", "Warming up pool with " << config_.min_connections << " connections");

        auto ready = ensure_ready();
        if (!ready)
            co_return ready;

        std::vector<awaitable<mailxx::result_void>> tasks;
        for (std::size_t i = 0; i < config_.min_connections; ++i)
        {
            MAILXX_TRY_CO_AWAIT(create_and_add_connection());
        }
        co_return mailxx::ok();
    }
    
    /**
     * Acquire a connection from the pool.
     * Creates a new connection if pool is empty and under max limit.
     * Waits if pool is at max capacity.
     * 
     * @return Result containing a pooled connection or an error
     */
    awaitable<mailxx::result<pooled_type>> acquire()
    {
        auto ready = ensure_ready();
        if (!ready)
            co_return mailxx::fail<pooled_type>(std::move(ready).error());
        
        auto start_time = std::chrono::steady_clock::now();
        
        // Update stats
        {
            std::lock_guard lock(stats_mutex_);
            ++stats_.acquisitions_total;
            ++stats_.pending_requests;
        }
        
        // Check pending limit
        if (config_.max_pending_requests > 0)
        {
            std::lock_guard lock(stats_mutex_);
            if (stats_.pending_requests > config_.max_pending_requests)
            {
                --stats_.pending_requests;
                co_return mailxx::fail<pooled_type>(errc::pool_exhausted, "Connection pool exhausted");
            }
        }

        auto result = co_await acquire_impl();

        // Update stats
        {
            std::lock_guard lock(stats_mutex_);
            --stats_.pending_requests;

            if (result)
            {
                auto wait_time = std::chrono::steady_clock::now() - start_time;
                if (wait_time > std::chrono::milliseconds{1})
                {
                    ++stats_.acquisitions_waited;
                    // Update rolling average
                    auto wait_us = std::chrono::duration_cast<std::chrono::microseconds>(wait_time);
                    stats_.avg_wait_time = std::chrono::microseconds{
                        (stats_.avg_wait_time.count() * (stats_.acquisitions_waited - 1) + wait_us.count())
                        / stats_.acquisitions_waited
                    };
                }
                else
                {
                    ++stats_.acquisitions_immediate;
                }
            }
        }

        if (!result)
            co_return mailxx::fail<pooled_type>(std::move(result).error());
        co_return std::move(*result);
    }
    
    /**
     * Drain all connections and prevent new acquisitions.
     * Waits for all in-use connections to be returned.
     */
    awaitable<mailxx::result_void> drain()
    {
        MAILXX_LOG_INFO("POOL", "Draining pool...");
        shutdown_.store(true, std::memory_order_release);
        
        // Close the channel to wake up any waiters
        channel_.close();
        
        // Wait for all in-use connections to return
        while (true)
        {
            {
                std::lock_guard lock(stats_mutex_);
                if (stats_.in_use_connections == 0)
                    break;
            }
            
            // Yield and check again
            steady_timer timer(executor_);
            timer.expires_after(std::chrono::milliseconds{100});
            auto [ec] = co_await timer.async_wait(use_nothrow_awaitable);
            if (ec)
                co_return mailxx::fail_void(errc::net_io_failed, "Pool drain wait failed", ec.message(), ec);
        }
        
        // Clear idle connections
        {
            std::lock_guard lock(pool_mutex_);
            idle_connections_.clear();
        }
        
        MAILXX_LOG_INFO("POOL", "Pool drained");
        co_return mailxx::ok();
    }
    
    /**
     * Get current pool statistics.
     */
    pool_stats stats() const
    {
        std::lock_guard lock(stats_mutex_);
        return stats_;
    }
    
    /**
     * Get number of available (idle) connections.
     */
    std::size_t available() const
    {
        std::lock_guard lock(pool_mutex_);
        return idle_connections_.size();
    }
    
    /**
     * Get number of connections currently in use.
     */
    std::size_t in_use() const
    {
        std::lock_guard lock(stats_mutex_);
        return stats_.in_use_connections;
    }
    
    /**
     * Get total number of connections (idle + in_use).
     */
    std::size_t size() const
    {
        std::lock_guard lock(stats_mutex_);
        return stats_.total_connections;
    }
    
    /**
     * Get the pool configuration.
     */
    const pool_config& config() const { return config_; }
    
    /**
     * Resize the pool (change max_connections).
     */
    void resize(std::size_t new_max)
    {
        config_.max_connections = new_max;
        // Note: excess connections will be closed naturally as they're returned
    }

private:
    friend class pooled_connection<Client>;
    
    struct pooled_entry
    {
        std::unique_ptr<Client> client;
        connection_metadata metadata;
    };
    
    mailxx::result_void ensure_ready() const
    {
        if (init_error_)
            return mailxx::fail_void(*init_error_);
        if (shutdown_.load(std::memory_order_acquire))
            return mailxx::fail_void(errc::pool_invalid_state, "Pool is shutting down");
        return mailxx::ok();
    }

    awaitable<mailxx::result<pooled_type>> acquire_impl()
    {
        auto self = this->shared_from_this();
        // Try to get an existing connection
        while (true)
        {
            std::unique_ptr<Client> client;
            connection_metadata metadata;
            
            // Check for idle connection
            {
                std::lock_guard lock(pool_mutex_);
                if (!idle_connections_.empty())
                {
                    auto entry = std::move(idle_connections_.front());
                    idle_connections_.pop_front();
                    client = std::move(entry.client);
                    metadata = std::move(entry.metadata);
                    
                    std::lock_guard slock(stats_mutex_);
                    --stats_.idle_connections;
                }
            }
            
            if (client)
            {
                // Check if connection is still valid
                bool should_recycle = false;
                
                // Check max lifetime
                if (config_.max_lifetime.count() > 0 && 
                    metadata.age() >= config_.max_lifetime)
                {
                    should_recycle = true;
                    MAILXX_LOG_DEBUG("POOL", "Connection exceeded max lifetime, recycling");
                }
                
                // Validate if configured
                if (!should_recycle && config_.validate_on_acquire && validator_)
                {
                    auto valid_res = co_await validator_(*client);
                    if (!valid_res || !*valid_res)
                    {
                        should_recycle = true;
                        MAILXX_LOG_DEBUG("POOL", "Connection validation failed, recycling");
                    }
                }
                
                if (should_recycle)
                {
                    // Discard this connection and try again
                    client.reset();
                    {
                        std::lock_guard lock(stats_mutex_);
                        --stats_.total_connections;
                        ++stats_.connections_recycled;
                    }
                    continue;  // Try to get another connection
                }
                
                // Connection is good
                {
                    std::lock_guard lock(stats_mutex_);
                    ++stats_.in_use_connections;
                }
                
                co_return mailxx::ok(pooled_type(std::move(client), std::move(metadata), self));
            }
            
            // No idle connection available, try to create new one
            bool can_create = false;
            {
                std::lock_guard lock(stats_mutex_);
                can_create = stats_.total_connections < config_.max_connections;
            }
            
            if (can_create)
            {
                auto create_res = co_await create_connection();
                if (create_res)
                {
                    client = std::move(*create_res);
                    {
                        std::lock_guard lock(stats_mutex_);
                        ++stats_.total_connections;
                        ++stats_.connections_created;
                        ++stats_.in_use_connections;
                    }

                    co_return mailxx::ok(pooled_type(std::move(client), connection_metadata{}, self));
                }

                MAILXX_LOG_WARN("POOL", "Failed to create connection: " << create_res.error().message);
                {
                    std::lock_guard lock(stats_mutex_);
                    ++stats_.connections_failed;
                }
                // Fall through to wait
            }
            
            // Pool is at capacity, wait for a connection to be returned via channel
            MAILXX_LOG_DEBUG("POOL", "Pool at capacity, waiting for connection...");

            steady_timer timer(executor_);
            timer.expires_after(config_.acquire_timeout);

            using namespace mailxx::asio::experimental::awaitable_operators;
            auto timer_wait = timer.async_wait(use_nothrow_awaitable);
            auto recv_wait = channel_.async_receive(use_nothrow_awaitable);

            auto res = co_await (std::move(timer_wait) || std::move(recv_wait));

            if (res.index() == 0)
            {
                // Timer finished first
                std::lock_guard lock(stats_mutex_);
                ++stats_.acquisitions_timeout;
                co_return mailxx::fail<pooled_type>(errc::pool_timeout, "Connection pool acquire timeout");
            }
            else
            {
                auto [ec] = std::get<1>(res);
                if (ec)
                {
                    if (ec == mailxx::asio::error::make_error_code(mailxx::asio::error::operation_aborted))
                        continue;
                    if (shutdown_.load(std::memory_order_acquire))
                        co_return mailxx::fail<pooled_type>(errc::pool_invalid_state, "Pool is shutting down");
                    continue;
                }
            }
            // Loop back and try again
        }
    }
    
    awaitable<mailxx::result<std::unique_ptr<Client>>> create_connection()
    {
        unsigned int attempts = 0;
        std::optional<error_info> last_error;
        const unsigned int max_attempts = config_.creation_retry_count == 0 ? 1 : config_.creation_retry_count;
        
        while (attempts < max_attempts)
        {
            auto res = co_await factory_();
            if (res)
                co_return res;
            last_error = res.error();

            ++attempts;
            if (attempts < max_attempts)
            {
                MAILXX_LOG_DEBUG("POOL", "Connection creation failed, retry "
                    << attempts << "/" << max_attempts);

                steady_timer timer(executor_);
                timer.expires_after(config_.creation_retry_delay);
                auto [ec] = co_await timer.async_wait(use_nothrow_awaitable);
                if (ec)
                    co_return mailxx::fail<std::unique_ptr<Client>>(errc::net_io_failed,
                        "Pool connection retry wait failed", ec.message(), ec);
            }
        }

        if (last_error)
            co_return mailxx::fail<std::unique_ptr<Client>>(std::move(*last_error));
        co_return mailxx::fail<std::unique_ptr<Client>>(errc::pool_config_error, "Connection creation failed");
    }
    
    awaitable<mailxx::result_void> create_and_add_connection()
    {
        auto client_res = co_await create_connection();
        if (!client_res)
        {
            MAILXX_LOG_WARN("POOL", "Failed to create warmup connection: " << client_res.error().message);
            {
                std::lock_guard lock(stats_mutex_);
                ++stats_.connections_failed;
            }
            co_return mailxx::fail_void(std::move(client_res).error());
        }

        auto client = std::move(*client_res);
        {
            std::lock_guard lock(pool_mutex_);
            idle_connections_.push_back({std::move(client), connection_metadata{}});
        }

        {
            std::lock_guard lock(stats_mutex_);
            ++stats_.total_connections;
            ++stats_.idle_connections;
            ++stats_.connections_created;
        }

        (void)channel_.try_send(mailxx::asio::error_code{});
        co_return mailxx::ok();
    }
    
    void return_connection(std::unique_ptr<Client> client, connection_metadata metadata, bool valid)
    {
        {
            std::lock_guard lock(stats_mutex_);
            --stats_.in_use_connections;
        }
        
        if (shutdown_.load(std::memory_order_acquire))
        {
            // Pool is shutting down, just close the connection
            client.reset();
            {
                std::lock_guard lock(stats_mutex_);
                --stats_.total_connections;
                ++stats_.connections_closed;
            }
            return;
        }
        
        if (!valid)
        {
            // Connection was invalidated, don't return to pool
            client.reset();
            {
                std::lock_guard lock(stats_mutex_);
                --stats_.total_connections;
                ++stats_.connections_closed;
            }
            return;
        }
        
        // Check max lifetime
        if (config_.max_lifetime.count() > 0 && metadata.age() >= config_.max_lifetime)
        {
            client.reset();
            {
                std::lock_guard lock(stats_mutex_);
                --stats_.total_connections;
                ++stats_.connections_recycled;
            }
            return;
        }
        
        // Return to pool
        {
            std::lock_guard lock(pool_mutex_);
            
            // Don't exceed max connections
            if (idle_connections_.size() + 1 > config_.max_connections)
            {
                client.reset();
                std::lock_guard slock(stats_mutex_);
                --stats_.total_connections;
                ++stats_.connections_closed;
                return;
            }
            
            idle_connections_.push_back({std::move(client), std::move(metadata)});
        }
        
        {
            std::lock_guard lock(stats_mutex_);
            ++stats_.idle_connections;
        }

        // Notify waiters
        (void)channel_.try_send(mailxx::asio::error_code{});
    }
    
    any_io_executor executor_;
    pool_config config_;
    factory_type factory_;
    validator_type validator_;
    
    // Channel for signaling (using Asio experimental channel)
    mailxx::asio::experimental::channel<void(mailxx::asio::error_code)> channel_;
    
    // Connection storage
    mutable std::mutex pool_mutex_;
    std::deque<pooled_entry> idle_connections_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    pool_stats stats_;
    
    // Shutdown flag
    std::atomic<bool> shutdown_;
    std::optional<error_info> init_error_;
};


/**
 * Create a shared pool (recommended for most use cases).
 */
template<typename Client>
auto make_pool(
    any_io_executor executor,
    pool_config config,
    typename connection_pool<Client>::factory_type factory)
{
    return std::make_shared<connection_pool<Client>>(
        std::move(executor), std::move(config), std::move(factory));
}

} // namespace mailxx::pool

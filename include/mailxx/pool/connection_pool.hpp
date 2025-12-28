/*

pool/connection_pool.hpp
------------------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/

#pragma once

#include <memory>
#include <vector>
#include <deque>
#include <functional>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/log.hpp>
#include <mailxx/pool/pool_config.hpp>

namespace mailxx::pool
{

using namespace mailxx::asio;

/**
 * Exception thrown when pool operations fail.
 */
class pool_error : public std::runtime_error
{
public:
    explicit pool_error(const std::string& msg) : std::runtime_error(msg) {}
    explicit pool_error(const char* msg) : std::runtime_error(msg) {}
};


/**
 * Exception thrown when acquire times out.
 */
class pool_timeout_error : public pool_error
{
public:
    pool_timeout_error() : pool_error("Connection pool acquire timeout") {}
};


/**
 * Exception thrown when pool is exhausted and cannot create more connections.
 */
class pool_exhausted_error : public pool_error
{
public:
    pool_exhausted_error() : pool_error("Connection pool exhausted") {}
};


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
        other.pool_ = nullptr;
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
            other.pool_ = nullptr;
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
        if (pool_ && client_)
        {
            metadata_.mark_used();
            pool_->return_connection(std::move(client_), std::move(metadata_), valid_);
            pool_ = nullptr;
        }
        client_.reset();
        valid_ = false;
    }
    
private:
    friend class connection_pool<Client>;
    
    pooled_connection(std::unique_ptr<Client> client, connection_metadata meta, pool_type* pool)
        : client_(std::move(client))
        , metadata_(std::move(meta))
        , pool_(pool)
        , valid_(true)
    {
    }
    
    std::unique_ptr<Client> client_;
    connection_metadata metadata_;
    pool_type* pool_ = nullptr;
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
    using factory_type = std::function<awaitable<std::unique_ptr<Client>>()>;
    using validator_type = std::function<awaitable<bool>(Client&)>;
    
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
            throw pool_error("Factory function is required");
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
    awaitable<void> warmup()
    {
        MAILXX_LOG_INFO("POOL", "Warming up pool with " << config_.min_connections << " connections");
        
        std::vector<awaitable<void>> tasks;
        for (std::size_t i = 0; i < config_.min_connections; ++i)
        {
            co_await create_and_add_connection();
        }
    }
    
    /**
     * Acquire a connection from the pool.
     * Creates a new connection if pool is empty and under max limit.
     * Waits if pool is at max capacity.
     * 
     * @return A pooled connection that auto-returns on destruction
     * @throws pool_timeout_error if acquire_timeout exceeded
     * @throws pool_exhausted_error if pool is full and max_pending exceeded
     */
    awaitable<pooled_type> acquire()
    {
        if (shutdown_.load(std::memory_order_acquire))
            throw pool_error("Pool is shutting down");
        
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
                throw pool_exhausted_error();
            }
        }
        
        try
        {
            pooled_type result = co_await acquire_impl();
            
            // Update stats
            {
                std::lock_guard lock(stats_mutex_);
                --stats_.pending_requests;
                
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
            
            co_return result;
        }
        catch (...)
        {
            std::lock_guard lock(stats_mutex_);
            --stats_.pending_requests;
            throw;
        }
    }
    
    /**
     * Drain all connections and prevent new acquisitions.
     * Waits for all in-use connections to be returned.
     */
    awaitable<void> drain()
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
            co_await timer.async_wait(use_awaitable);
        }
        
        // Clear idle connections
        {
            std::lock_guard lock(pool_mutex_);
            idle_connections_.clear();
        }
        
        MAILXX_LOG_INFO("POOL", "Pool drained");
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
    
    awaitable<pooled_type> acquire_impl()
    {
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
                    try
                    {
                        bool valid = co_await validator_(*client);
                        if (!valid)
                        {
                            should_recycle = true;
                            MAILXX_LOG_DEBUG("POOL", "Connection validation failed, recycling");
                        }
                    }
                    catch (...)
                    {
                        should_recycle = true;
                        MAILXX_LOG_DEBUG("POOL", "Connection validation threw exception, recycling");
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
                
                co_return pooled_type(std::move(client), std::move(metadata), this);
            }
            
            // No idle connection available, try to create new one
            bool can_create = false;
            {
                std::lock_guard lock(stats_mutex_);
                can_create = stats_.total_connections < config_.max_connections;
            }
            
            if (can_create)
            {
                try
                {
                    client = co_await create_connection();
                    
                    {
                        std::lock_guard lock(stats_mutex_);
                        ++stats_.total_connections;
                        ++stats_.connections_created;
                        ++stats_.in_use_connections;
                    }
                    
                    co_return pooled_type(std::move(client), connection_metadata{}, this);
                }
                catch (const std::exception& e)
                {
                    MAILXX_LOG_WARN("POOL", "Failed to create connection: " << e.what());
                    {
                        std::lock_guard lock(stats_mutex_);
                        ++stats_.connections_failed;
                    }
                    // Fall through to wait
                }
            }
            
            // Pool is at capacity, wait for a connection to be returned
            MAILXX_LOG_DEBUG("POOL", "Pool at capacity, waiting for connection...");
            
            // Use timeout
            steady_timer timer(executor_);
            timer.expires_after(config_.acquire_timeout);
            
            // Wait with timeout
            bool got_signal = false;
            
            // Simple polling approach (channel would be better but keeping it simple)
            auto deadline = std::chrono::steady_clock::now() + config_.acquire_timeout;
            while (std::chrono::steady_clock::now() < deadline)
            {
                {
                    std::lock_guard lock(pool_mutex_);
                    if (!idle_connections_.empty())
                    {
                        got_signal = true;
                        break;
                    }
                }
                
                // Check if we can create now
                {
                    std::lock_guard lock(stats_mutex_);
                    if (stats_.total_connections < config_.max_connections)
                    {
                        got_signal = true;
                        break;
                    }
                }
                
                // Short sleep to avoid busy loop
                steady_timer wait_timer(executor_);
                wait_timer.expires_after(std::chrono::milliseconds{10});
                co_await wait_timer.async_wait(use_awaitable);
            }
            
            if (!got_signal)
            {
                std::lock_guard lock(stats_mutex_);
                ++stats_.acquisitions_timeout;
                throw pool_timeout_error();
            }
            
            // Loop back and try again
        }
    }
    
    awaitable<std::unique_ptr<Client>> create_connection()
    {
        unsigned int attempts = 0;
        std::exception_ptr last_error;
        
        while (attempts < config_.creation_retry_count)
        {
            try
            {
                co_return co_await factory_();
            }
            catch (...)
            {
                last_error = std::current_exception();
                ++attempts;
                
                if (attempts < config_.creation_retry_count)
                {
                    MAILXX_LOG_DEBUG("POOL", "Connection creation failed, retry " 
                        << attempts << "/" << config_.creation_retry_count);
                    
                    steady_timer timer(executor_);
                    timer.expires_after(config_.creation_retry_delay);
                    co_await timer.async_wait(use_awaitable);
                }
            }
        }
        
        std::rethrow_exception(last_error);
    }
    
    awaitable<void> create_and_add_connection()
    {
        try
        {
            auto client = co_await create_connection();
            
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
        }
        catch (const std::exception& e)
        {
            MAILXX_LOG_WARN("POOL", "Failed to create warmup connection: " << e.what());
            {
                std::lock_guard lock(stats_mutex_);
                ++stats_.connections_failed;
            }
        }
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
    }
    
    any_io_executor executor_;
    pool_config config_;
    factory_type factory_;
    validator_type validator_;
    
    // Channel for signaling (using Asio experimental channel)
    experimental::channel<void(asio::error_code)> channel_;
    
    // Connection storage
    mutable std::mutex pool_mutex_;
    std::deque<pooled_entry> idle_connections_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    pool_stats stats_;
    
    // Shutdown flag
    std::atomic<bool> shutdown_;
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

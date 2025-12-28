/*

reconnection.hpp
----------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once

#include <chrono>
#include <optional>
#include <functional>
#include <stdexcept>
#include <random>
#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/log.hpp>

namespace mailxx::detail
{

/**
 * Reconnection policy configuration.
 * Controls automatic reconnection behavior on connection failures.
 */
struct reconnection_policy
{
    /// Enable automatic reconnection
    bool enabled = false;
    
    /// Maximum number of reconnection attempts (0 = unlimited)
    unsigned int max_attempts = 3;
    
    /// Initial delay between reconnection attempts
    std::chrono::milliseconds initial_delay{1000};
    
    /// Maximum delay between attempts (for exponential backoff)
    std::chrono::milliseconds max_delay{30000};
    
    /// Multiplier for exponential backoff (e.g., 2.0 doubles delay each attempt)
    double backoff_multiplier = 2.0;
    
    /// Add random jitter to delays (0.0 to 1.0, e.g., 0.25 = ±25%)
    double jitter_factor = 0.25;
    
    /// Callback invoked before each reconnection attempt
    /// Parameters: attempt number (1-based), delay before attempt
    /// Return false to cancel reconnection
    std::function<bool(unsigned int, std::chrono::milliseconds)> on_reconnect_attempt;
    
    /// Callback invoked when reconnection succeeds
    std::function<void()> on_reconnect_success;
    
    /// Callback invoked when all reconnection attempts fail
    std::function<void(const std::exception&)> on_reconnect_failed;
    
    /// Create a disabled (no reconnection) policy
    static reconnection_policy disabled()
    {
        return reconnection_policy{};
    }
    
    /// Create a simple policy with fixed delay
    static reconnection_policy simple(
        unsigned int attempts = 3,
        std::chrono::milliseconds delay = std::chrono::milliseconds{1000})
    {
        reconnection_policy policy;
        policy.enabled = true;
        policy.max_attempts = attempts;
        policy.initial_delay = delay;
        policy.max_delay = delay;
        policy.backoff_multiplier = 1.0;
        policy.jitter_factor = 0.0;
        return policy;
    }
    
    /// Create an exponential backoff policy
    static reconnection_policy exponential_backoff(
        unsigned int max_attempts = 5,
        std::chrono::milliseconds initial = std::chrono::milliseconds{500},
        std::chrono::milliseconds max_delay = std::chrono::milliseconds{30000},
        double multiplier = 2.0,
        double jitter = 0.25)
    {
        reconnection_policy policy;
        policy.enabled = true;
        policy.max_attempts = max_attempts;
        policy.initial_delay = initial;
        policy.max_delay = max_delay;
        policy.backoff_multiplier = multiplier;
        policy.jitter_factor = jitter;
        return policy;
    }
    
    /// Calculate delay for a specific attempt number (1-based)
    [[nodiscard]] std::chrono::milliseconds calculate_delay(unsigned int attempt) const
    {
        if (attempt == 0)
            return initial_delay;
        
        // Calculate base delay with exponential backoff
        double delay_ms = static_cast<double>(initial_delay.count());
        for (unsigned int i = 1; i < attempt; ++i)
        {
            delay_ms *= backoff_multiplier;
            if (delay_ms > static_cast<double>(max_delay.count()))
            {
                delay_ms = static_cast<double>(max_delay.count());
                break;
            }
        }
        
        // Apply jitter
        if (jitter_factor > 0.0)
        {
            thread_local std::mt19937 rng(std::random_device{}());
            std::uniform_real_distribution<double> dist(1.0 - jitter_factor, 1.0 + jitter_factor);
            delay_ms *= dist(rng);
        }
        
        auto result = std::chrono::milliseconds(static_cast<long long>(delay_ms));
        
        // Clamp to max_delay
        if (result > max_delay)
            result = max_delay;
        
        return result;
    }
};


/**
 * Connection state for reconnection tracking.
 */
struct connection_state
{
    std::string host;
    std::string service;
    unsigned int reconnect_attempts = 0;
    bool is_connected = false;
    
    void reset()
    {
        reconnect_attempts = 0;
        is_connected = false;
    }
    
    void set_connected(const std::string& h, const std::string& s)
    {
        host = h;
        service = s;
        reconnect_attempts = 0;
        is_connected = true;
    }
    
    void set_disconnected()
    {
        is_connected = false;
    }
};


/**
 * Reconnection helper for async operations.
 * Use this to wrap operations that may fail due to connection issues.
 */
template<typename Executor>
class reconnection_helper
{
public:
    using executor_type = Executor;
    
    reconnection_helper(executor_type executor, reconnection_policy policy = {})
        : executor_(executor)
        , policy_(std::move(policy))
    {
    }
    
    /// Set reconnection policy
    void set_policy(reconnection_policy policy)
    {
        policy_ = std::move(policy);
    }
    
    /// Get current policy
    const reconnection_policy& policy() const { return policy_; }
    
    /// Get connection state
    const connection_state& state() const { return state_; }
    
    /// Record successful connection
    void on_connected(const std::string& host, const std::string& service)
    {
        state_.set_connected(host, service);
    }
    
    /// Record disconnection
    void on_disconnected()
    {
        state_.set_disconnected();
    }
    
    /**
     * Execute an async operation with automatic reconnection.
     * 
     * @param connect_fn Coroutine that performs connection
     * @param operation_fn Coroutine that performs the actual operation
     * @return Result of operation_fn
     */
    template<typename ConnectFn, typename OperationFn>
    auto with_reconnection(ConnectFn connect_fn, OperationFn operation_fn)
        -> mailxx::asio::awaitable<decltype(std::declval<OperationFn>()().get())>
    {
        using namespace mailxx::asio;
        using result_type = decltype(std::declval<OperationFn>()().get());
        
        std::exception_ptr last_error;
        unsigned int attempt = 0;
        
        while (true)
        {
            try
            {
                // Try the operation
                if constexpr (std::is_void_v<result_type>)
                {
                    co_await operation_fn();
                    co_return;
                }
                else
                {
                    co_return co_await operation_fn();
                }
            }
            catch (const std::exception& e)
            {
                last_error = std::current_exception();
                
                // Check if reconnection is enabled and should retry
                if (!policy_.enabled)
                    std::rethrow_exception(last_error);
                
                if (!should_reconnect(e))
                    std::rethrow_exception(last_error);
                
                ++attempt;
                
                if (policy_.max_attempts > 0 && attempt > policy_.max_attempts)
                {
                    if (policy_.on_reconnect_failed)
                        policy_.on_reconnect_failed(e);
                    std::rethrow_exception(last_error);
                }
                
                // Calculate delay
                auto delay = policy_.calculate_delay(attempt);
                
                // Notify callback
                if (policy_.on_reconnect_attempt)
                {
                    if (!policy_.on_reconnect_attempt(attempt, delay))
                    {
                        // Callback cancelled reconnection
                        std::rethrow_exception(last_error);
                    }
                }
                
                MAILXX_LOG_INFO("RECONNECT", "Attempt " << attempt << " in " << delay.count() << "ms");
                
                // Wait before reconnecting
                steady_timer timer(executor_);
                timer.expires_after(delay);
                co_await timer.async_wait(use_awaitable);
                
                // Try to reconnect
                try
                {
                    co_await connect_fn();
                    state_.reconnect_attempts = attempt;
                    
                    if (policy_.on_reconnect_success)
                        policy_.on_reconnect_success();
                    
                    // Retry the operation on next loop iteration
                }
                catch (const std::exception& conn_error)
                {
                    MAILXX_LOG_WARN("RECONNECT", "Connection failed: " << conn_error.what());
                    // Continue loop to try again
                }
            }
        }
    }
    
protected:
    /// Check if the exception indicates a recoverable connection error
    [[nodiscard]] virtual bool should_reconnect(const std::exception& e) const
    {
        // Check for common connection-related errors
        const std::string msg = e.what();
        
        // List of keywords that indicate connection issues
        static const char* connection_keywords[] = {
            "connection",
            "disconnected",
            "broken pipe",
            "reset by peer",
            "timed out",
            "timeout",
            "eof",
            "end of file",
            "closed",
            "network"
        };
        
        for (const char* keyword : connection_keywords)
        {
            if (msg.find(keyword) != std::string::npos)
                return true;
        }
        
        return false;
    }
    
private:
    executor_type executor_;
    reconnection_policy policy_;
    connection_state state_;
};


} // namespace mailxx::detail

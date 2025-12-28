/**
 * @file rate_limiter.hpp
 * @brief Rate limiting for email sending operations.
 * @author mailxx contributors
 * 
 * Token bucket rate limiter for throttling email operations.
 * Supports both synchronous waits and async/coroutine usage.
 */

#ifndef MAILXX_POOL_RATE_LIMITER_HPP
#define MAILXX_POOL_RATE_LIMITER_HPP

#include <chrono>
#include <mutex>
#include <algorithm>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>

namespace mailxx {

using namespace boost::asio;
using namespace std::chrono;

/**
 * Rate limiter configuration.
 */
struct rate_limit_config
{
    /// Maximum number of operations per time window
    double rate{10.0};
    
    /// Time window for the rate (default: 1 second = ops per second)
    steady_clock::duration window{seconds(1)};
    
    /// Maximum burst size (tokens that can accumulate)
    size_t burst{1};
    
    /// Enable/disable rate limiting
    bool enabled{true};

    /**
     * Create config for N emails per second.
     */
    static rate_limit_config per_second(double n, size_t burst_size = 1)
    {
        return {n, seconds(1), burst_size, true};
    }
    
    /**
     * Create config for N emails per minute.
     */
    static rate_limit_config per_minute(double n, size_t burst_size = 1)
    {
        return {n, minutes(1), burst_size, true};
    }
    
    /**
     * Create config for N emails per hour.
     */
    static rate_limit_config per_hour(double n, size_t burst_size = 1)
    {
        return {n, hours(1), burst_size, true};
    }
    
    /**
     * Disable rate limiting.
     */
    static rate_limit_config unlimited()
    {
        return {0.0, seconds(1), 0, false};
    }
};

/**
 * Token bucket rate limiter.
 * 
 * Thread-safe rate limiter using the token bucket algorithm.
 * Tokens are added at a constant rate and consumed for each operation.
 * 
 * Example usage:
 * @code
 * rate_limiter limiter(executor, rate_limit_config::per_second(5));
 * 
 * for (const auto& msg : messages) {
 *     co_await limiter.acquire();  // Wait for rate limit
 *     co_await smtp.send(msg);
 * }
 * @endcode
 */
class rate_limiter
{
public:
    /**
     * Construct rate limiter.
     * @param executor Asio executor for async operations
     * @param config Rate limiting configuration
     */
    explicit rate_limiter(any_io_executor executor, rate_limit_config config = {})
        : executor_(std::move(executor))
        , config_(std::move(config))
        , tokens_(static_cast<double>(config_.burst))
        , last_refill_(steady_clock::now())
    {
    }

    /**
     * Acquire a token, waiting if necessary.
     * Non-blocking if tokens are available, otherwise waits.
     * @return Awaitable that completes when token is acquired
     */
    awaitable<void> acquire()
    {
        if (!config_.enabled)
            co_return;

        for (;;)
        {
            auto wait_time = try_acquire_impl();
            if (wait_time == steady_clock::duration::zero())
                co_return;
            
            steady_timer timer(executor_);
            timer.expires_after(wait_time);
            co_await timer.async_wait(use_awaitable);
        }
    }

    /**
     * Try to acquire a token without waiting.
     * @return true if token was acquired, false if rate limited
     */
    bool try_acquire()
    {
        if (!config_.enabled)
            return true;
        return try_acquire_impl() == steady_clock::duration::zero();
    }

    /**
     * Get time until next token is available.
     * @return Duration to wait, or zero if token is available now
     */
    steady_clock::duration time_until_available()
    {
        if (!config_.enabled)
            return steady_clock::duration::zero();

        std::lock_guard lock(mutex_);
        refill_tokens();
        
        if (tokens_ >= 1.0)
            return steady_clock::duration::zero();
        
        return compute_wait_time();
    }

    /**
     * Reset the rate limiter to initial state.
     */
    void reset()
    {
        std::lock_guard lock(mutex_);
        tokens_ = static_cast<double>(config_.burst);
        last_refill_ = steady_clock::now();
    }

    /**
     * Update configuration.
     * Resets internal state.
     */
    void configure(rate_limit_config new_config)
    {
        std::lock_guard lock(mutex_);
        config_ = std::move(new_config);
        tokens_ = static_cast<double>(config_.burst);
        last_refill_ = steady_clock::now();
    }

    /**
     * Get current configuration.
     */
    const rate_limit_config& config() const { return config_; }

    /**
     * Get current token count (approximate, for monitoring).
     */
    double available_tokens() const
    {
        std::lock_guard lock(mutex_);
        return tokens_;
    }

private:
    /**
     * Try to acquire and return wait time if not possible.
     */
    steady_clock::duration try_acquire_impl()
    {
        std::lock_guard lock(mutex_);
        refill_tokens();
        
        if (tokens_ >= 1.0)
        {
            tokens_ -= 1.0;
            return steady_clock::duration::zero();
        }
        
        return compute_wait_time();
    }

    /**
     * Refill tokens based on elapsed time.
     */
    void refill_tokens()
    {
        const auto now = steady_clock::now();
        const auto elapsed = now - last_refill_;
        
        // Tokens to add = (elapsed / window) * rate
        const auto window_ns = duration_cast<nanoseconds>(config_.window).count();
        const auto elapsed_ns = duration_cast<nanoseconds>(elapsed).count();
        
        if (window_ns > 0 && elapsed_ns > 0)
        {
            const double tokens_to_add = (static_cast<double>(elapsed_ns) / window_ns) * config_.rate;
            tokens_ = std::min(tokens_ + tokens_to_add, static_cast<double>(config_.burst));
            last_refill_ = now;
        }
    }

    /**
     * Compute wait time for one token.
     */
    steady_clock::duration compute_wait_time() const
    {
        if (config_.rate <= 0)
            return hours(24);  // Effectively blocked
        
        // Time for 1 token = window / rate
        const auto window_ns = duration_cast<nanoseconds>(config_.window).count();
        const auto wait_ns = static_cast<long long>(window_ns / config_.rate);
        
        // Account for partial token
        const double needed = 1.0 - tokens_;
        const auto actual_wait = static_cast<long long>(wait_ns * needed);
        
        return nanoseconds(actual_wait);
    }

    any_io_executor executor_;
    rate_limit_config config_;
    
    mutable std::mutex mutex_;
    double tokens_;
    steady_clock::time_point last_refill_;
};

/**
 * Scoped rate limiter guard for RAII-style acquisition.
 */
class [[nodiscard]] rate_limit_guard
{
public:
    /**
     * Acquire rate limit asynchronously.
     */
    static awaitable<rate_limit_guard> acquire(rate_limiter& limiter)
    {
        co_await limiter.acquire();
        co_return rate_limit_guard{};
    }

private:
    rate_limit_guard() = default;
};

} // namespace mailxx

#endif // MAILXX_POOL_RATE_LIMITER_HPP

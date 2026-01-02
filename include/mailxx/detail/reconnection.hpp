/*

reconnection.hpp
----------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once

#include <chrono>
#include <functional>
#include <mailxx/detail/result.hpp>

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
    
    /// Add random jitter to delays (0.0 to 1.0, e.g., 0.25 = 25%)
    double jitter_factor = 0.25;
    
    /// Callback invoked before each reconnection attempt
    /// Parameters: attempt number (1-based), delay before attempt
    /// Return false to cancel reconnection
    std::function<bool(unsigned int, std::chrono::milliseconds)> on_reconnect_attempt;
    
    /// Callback invoked when reconnection succeeds
    std::function<void()> on_reconnect_success;
    
    /// Callback invoked when all reconnection attempts fail
    std::function<void(const mailxx::error_info&)> on_reconnect_failed;
    
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
        
        auto result = std::chrono::milliseconds(static_cast<long long>(delay_ms));
        
        // Clamp to max_delay
        if (result > max_delay)
            result = max_delay;
        
        return result;
    }
};


} // namespace mailxx::detail

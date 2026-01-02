/*

async_mutex.hpp
---------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/


#pragma once

#include <algorithm>
#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <utility>

#include <mailxx/detail/asio_decl.hpp>
#include <mailxx/detail/result.hpp>

namespace mailxx::detail
{

class async_mutex
{
public:
    class scoped_lock
    {
    public:
        scoped_lock() noexcept = default;

        scoped_lock(const scoped_lock&) = delete;
        scoped_lock& operator=(const scoped_lock&) = delete;

        scoped_lock(scoped_lock&& other) noexcept
            : mutex_(std::exchange(other.mutex_, nullptr))
        {
        }

        scoped_lock& operator=(scoped_lock&& other) noexcept
        {
            if (this != &other)
            {
                unlock();
                mutex_ = std::exchange(other.mutex_, nullptr);
            }
            return *this;
        }

        ~scoped_lock()
        {
            unlock();
        }

    private:
        friend class async_mutex;

        explicit scoped_lock(async_mutex& mutex) noexcept
            : mutex_(&mutex)
        {
        }

        void unlock() noexcept
        {
            if (mutex_ != nullptr)
            {
                mutex_->unlock();
                mutex_ = nullptr;
            }
        }

        async_mutex* mutex_{nullptr};
    };

    explicit async_mutex(mailxx::asio::any_io_executor executor)
        : executor_(std::move(executor))
    {
    }

    async_mutex(const async_mutex&) = delete;
    async_mutex& operator=(const async_mutex&) = delete;

    /// Lock the mutex asynchronously.
    /// @return Success with scoped_lock or error on cancellation/failure.
    mailxx::asio::awaitable<mailxx::result<scoped_lock>> lock()
    {
        // Use compare_exchange for thread-safe check-and-set
        bool expected = false;
        if (locked_.compare_exchange_strong(expected, true, std::memory_order_acquire))
        {
            co_return mailxx::ok(scoped_lock(*this));
        }

        auto waiter = std::make_shared<waiter_t>(executor_);
        waiter->timer.expires_at(mailxx::asio::steady_timer::time_point::max());
        
        {
            std::lock_guard<std::mutex> guard(waiters_mutex_);
            waiters_.push_back(waiter);
        }

        auto [ec] = co_await waiter->timer.async_wait(mailxx::asio::use_nothrow_awaitable);

        if (!waiter->ready.load(std::memory_order_acquire))
        {
            std::lock_guard<std::mutex> guard(waiters_mutex_);
            auto it = std::find(waiters_.begin(), waiters_.end(), waiter);
            if (it != waiters_.end())
                waiters_.erase(it);

            if (ec)
                co_return mailxx::fail<scoped_lock>(
                    errc::net_io_failed,
                    "async_mutex lock wait failed",
                    ec.message(),
                    ec);
            co_return mailxx::fail<scoped_lock>(errc::net_cancelled, "async_mutex lock cancelled");
        }

        (void)ec;
        locked_.store(true, std::memory_order_acquire);
        co_return mailxx::ok(scoped_lock(*this));
    }

private:
    struct waiter_t
    {
        explicit waiter_t(mailxx::asio::any_io_executor executor)
            : timer(std::move(executor))
        {
        }

        mailxx::asio::steady_timer timer;
        std::atomic<bool> ready{false};
    };

    void unlock() noexcept
    {
        std::shared_ptr<waiter_t> waiter;
        {
            std::lock_guard<std::mutex> guard(waiters_mutex_);
            if (waiters_.empty())
            {
                locked_.store(false, std::memory_order_release);
                return;
            }

            waiter = waiters_.front();
            waiters_.pop_front();
        }
        
        waiter->ready.store(true, std::memory_order_release);
        waiter->timer.cancel();
    }

    mailxx::asio::any_io_executor executor_;
    std::atomic<bool> locked_{false};
    mutable std::mutex waiters_mutex_;
    std::deque<std::shared_ptr<waiter_t>> waiters_;
};

} // namespace mailxx::detail

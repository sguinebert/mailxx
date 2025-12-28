/*

test_pool_lease_drop_after_pool_destroy.cpp
-------------------------------------------

Ensure a pooled connection releasing after pool destruction does not crash.

*/

#define BOOST_TEST_MODULE pool_lease_drop_after_pool_destroy

#include <boost/test/unit_test.hpp>
#include <chrono>
#include <mailxx/pool/connection_pool.hpp>

using namespace mailxx;

struct dummy_client
{
    explicit dummy_client(bool& destroyed) : destroyed_(&destroyed) {}
    ~dummy_client()
    {
        if (destroyed_)
            *destroyed_ = true;
    }

private:
    bool* destroyed_{nullptr};
};

BOOST_AUTO_TEST_CASE(lease_destruction_after_pool_reset)
{
    asio::io_context ctx;
    bool destroyed = false;

    pool::pool_config cfg;
    cfg.max_connections = 1;
    cfg.min_connections = 0;
    cfg.acquire_timeout = std::chrono::seconds{1};

    auto factory = [&]() -> asio::awaitable<std::unique_ptr<dummy_client>>
    {
        co_return std::make_unique<dummy_client>(destroyed);
    };

    auto pool = pool::make_pool<dummy_client>(ctx.get_executor(), cfg, factory);

    asio::co_spawn(ctx,
        [pool = std::move(pool)]() mutable -> asio::awaitable<void>
        {
            auto lease = co_await pool->acquire();
            // Drop the pool while lease is still alive
            pool.reset();
            // lease destructs at scope end
            co_return;
        },
        asio::detached);

    ctx.run();

    BOOST_TEST(destroyed);
}

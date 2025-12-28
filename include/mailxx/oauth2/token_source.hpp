/*

token_source.hpp
----------------

Simple token source with refresh callback (no HTTP dependency).

*/

#pragma once

#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <utility>

#include <mailxx/detail/result.hpp>
#include <mailxx/oauth2/token.hpp>

namespace mailxx::oauth2
{

class token_source
{
public:
    using refresh_fn = std::function<mailxx::result<token>(const token& current)>;

    token_source(token initial, refresh_fn fn)
        : current_(std::move(initial)),
          refresh_(std::move(fn))
    {
    }

    mailxx::result<std::string> get_access_token()
    {
        return get_access_token(false);
    }

    mailxx::result<std::string> refresh_access_token()
    {
        return get_access_token(true);
    }

private:
    mailxx::result<std::string> get_access_token(bool force_refresh)
    {
        token snapshot;
        std::chrono::system_clock::time_point now;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            now = std::chrono::system_clock::now();
            if (!force_refresh && !current_.expired(now, skew_))
                return mailxx::ok(current_.access_token);
            snapshot = current_;
        }

        if (!refresh_)
            return mailxx::fail<std::string>(
                mailxx::errc::codec_invalid_input,
                "oauth2 refresh function missing");

        auto refreshed = refresh_(snapshot);
        if (!refreshed)
            return mailxx::fail<std::string>(std::move(refreshed).error());

        {
            std::lock_guard<std::mutex> lock(mutex_);
            current_ = std::move(refreshed).value();
            return mailxx::ok(current_.access_token);
        }
    }

    std::mutex mutex_;
    token current_;
    refresh_fn refresh_;
    std::chrono::seconds skew_{30};
};

} // namespace mailxx::oauth2

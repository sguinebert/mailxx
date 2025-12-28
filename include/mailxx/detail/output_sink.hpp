#pragma once

#include <functional>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>

namespace mailxx
{
namespace detail
{

struct output_sink
{
    virtual ~output_sink() = default;
    virtual void write(std::string_view chunk) = 0;
};

class string_sink : public output_sink
{
public:
    explicit string_sink(std::string& out) : out_(&out) {}

    void write(std::string_view chunk) override
    {
        out_->append(chunk.data(), chunk.size());
    }

private:
    std::string* out_;
};

class ostream_sink : public output_sink
{
public:
    explicit ostream_sink(std::ostream& out) : out_(&out) {}

    void write(std::string_view chunk) override
    {
        out_->write(chunk.data(), static_cast<std::streamsize>(chunk.size()));
    }

private:
    std::ostream* out_;
};

class fn_sink : public output_sink
{
public:
    explicit fn_sink(std::function<void(std::string_view)> fn)
        : fn_(std::move(fn))
    {
    }

    void write(std::string_view chunk) override
    {
        if (fn_)
            fn_(chunk);
    }

private:
    std::function<void(std::string_view)> fn_;
};

} // namespace detail
} // namespace mailxx

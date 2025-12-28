#pragma once

#include <mailxx/net/dialog.hpp>

namespace mailxx
{
namespace smtp
{

class error : public mailxx::net::dialog_error
{
public:
    using mailxx::net::dialog_error::dialog_error;
};

} // namespace smtp
} // namespace mailxx

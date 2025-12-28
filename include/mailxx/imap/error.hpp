#pragma once

#include <mailxx/net/dialog.hpp>

namespace mailxx::imap
{

class error : public mailxx::net::dialog_error
{
public:
    using mailxx::net::dialog_error::dialog_error;
};

} // namespace mailxx::imap

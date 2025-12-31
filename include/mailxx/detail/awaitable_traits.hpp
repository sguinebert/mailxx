/*

awaitable_traits.hpp
--------------------

Small utilities to extract value types from Asio awaitables.

*/

#pragma once

#include <type_traits>

#include <mailxx/detail/asio_decl.hpp>

namespace mailxx::detail
{

template<class>
struct awaitable_value;

template<class T, class Executor>
struct awaitable_value<mailxx::asio::awaitable<T, Executor>>
{
    using type = T;
};

template<class T>
using awaitable_value_t = typename awaitable_value<std::remove_cvref_t<T>>::type;

} // namespace mailxx::detail

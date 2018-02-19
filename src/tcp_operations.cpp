/*
 * Copyright 2015, akashche at redhat.com
 * Copyright 2017, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   tcp_operations.cpp
 * Author: alex
 * 
 * Created on November 12, 2015, 1:19 PM
 */

#include "tcp_operations.hpp"

#include <thread>

#include "asio.hpp"

#include "staticlib/config.hpp"
#include "staticlib/support.hpp"
#include "staticlib/pimpl/forward_macros.hpp"
#include "staticlib/utils.hpp"

namespace wilton {
namespace net {

namespace { // anonymous

std::string perform_check(asio::io_service& service, asio::ip::tcp::endpoint& endpoint,
        std::chrono::milliseconds timeout) {

    // prepare service
    service.reset();

    // prepare state
    asio::ip::tcp::socket socket{service, asio::ip::tcp::v4()};
    asio::steady_timer timer{service};
    auto connect_canceled = false;
    auto timer_canceled = false;
    auto error = std::string();

    // start timer
    timer.expires_from_now(timeout);

    // connect callback
    socket.async_connect(endpoint, [&](const std::error_code& ec) {
        if (connect_canceled) return;
        timer_canceled = true;
        timer.cancel();
        if(ec) {
            error = "ERROR: message: [" + ec.message() + "]," +
                    " code: [" + sl::support::to_string(ec.value()) + "]";
        }
    });

    // timeout callback
    timer.async_wait([&](const std::error_code&) {
        if (timer_canceled) return;
        connect_canceled = true;
        socket.close();
        error = "ERROR: operation timed out";
    });

    // perform connection, callbacks will be called only from current thread
    service.run();

    // return result, empty on success
    return error;
}

} // namespace

class tcp_operations::impl : public staticlib::pimpl::object::impl {

public:

    static std::string wait_for_connection(const std::string& ip_addr,
            uint16_t tcp_port, std::chrono::milliseconds timeout) {
        asio::io_service service{};
        asio::ip::tcp::endpoint endpoint{asio::ip::address_v4::from_string(ip_addr), tcp_port};
        uint64_t start = sl::utils::current_time_millis_steady();
        auto tc = static_cast<uint64_t>(timeout.count());
        auto attempt_timeout = std::chrono::milliseconds(100);
        std::string err = "ERROR: Invalid timeout: [" + sl::support::to_string(tc) + "] (-1)";
        while (sl::utils::current_time_millis_steady() - start < tc) {
            err = perform_check(service, endpoint, attempt_timeout);
            if (err.empty()) break;
            std::this_thread::sleep_for(attempt_timeout);
        }
        return err;
    }
    
    static std::vector<std::string> resolve_hostname(const std::string& hostname,
            std::chrono::milliseconds timeout) {

        // prepare state
        asio::io_service service{};
        asio::ip::tcp::resolver resolver{service};
        // http://think-async.com/Asio/asio-1.10.6/doc/asio/reference/ip__basic_resolver_query/basic_resolver_query/overload4.html
        asio::ip::tcp::resolver::query query(asio::ip::tcp::v4(), hostname, "",
                asio::ip::resolver_query_base::flags(0));
        asio::steady_timer timer{service};
        auto resolve_canceled = false;
        auto timer_canceled = false;
        auto error = std::string();
        auto result = std::vector<std::string>();

        // start timer
        timer.expires_from_now(timeout);

        // resolve callback
        resolver.async_resolve(query, [&](const std::error_code& ec, asio::ip::tcp::resolver::iterator it) {
            if (resolve_canceled) return;
            timer_canceled = true;
            timer.cancel();
            if(ec) {
                error = "Resolve error, hostname: [" + hostname + "]," +
                        " message: [" + ec.message() + "]," +
                        " code: [" + sl::support::to_string(ec.value()) + "]";
                return;
            }
            asio::ip::tcp::resolver::iterator end{};
            while (it != asio::ip::tcp::resolver::iterator()) {
                const asio::ip::tcp::endpoint& ep = it->endpoint();
                result.emplace_back(ep.address().to_string());
                it++;
            }
        });

        // timeout callback
        timer.async_wait([&](const std::error_code&) {
            if (timer_canceled) return;
            resolve_canceled = true;
            resolver.cancel();
            error = "Operation timed out, timeout millis: [" + sl::support::to_string(timeout.count()) + "]";
        });

        // perform connection, callbacks will be called only from the current thread
        service.run();

        // check results
        if (!error.empty()) throw support::exception(TRACEMSG(error));
        return result;
    }

};

PIMPL_FORWARD_METHOD_STATIC(tcp_operations, std::vector<std::string>, resolve_hostname, 
        (const std::string&)(std::chrono::milliseconds), (), support::exception)
PIMPL_FORWARD_METHOD_STATIC(tcp_operations, std::string, wait_for_connection, 
        (const std::string&)(uint16_t)(std::chrono::milliseconds), (), support::exception)

} // namespace
}





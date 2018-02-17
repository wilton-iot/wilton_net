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

#include <atomic>
#include <mutex>
#include <thread>

#include "asio.hpp"

#include "staticlib/config.hpp"
#include "staticlib/support.hpp"
#include "staticlib/pimpl/forward_macros.hpp"

namespace wilton {
namespace net {

namespace { // anonymous

// http://stackoverflow.com/a/2834294/314015
uint64_t current_time_millis() {
    auto time = std::chrono::system_clock::now(); // get the current time
    auto since_epoch = time.time_since_epoch(); // get the duration since epoch
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(since_epoch);
    return static_cast<uint64_t>(millis.count()); // just like java (new Date()).getTime();
}

std::string perform_check(std::mutex& mutex, asio::io_service& service,
        asio::ip::tcp::endpoint& endpoint, std::chrono::milliseconds timeout) {
    // prepare service
    service.reset();

    // prepare state
    asio::ip::tcp::socket socket{service, asio::ip::tcp::v4()};
    asio::steady_timer timer{service};
    std::atomic_bool connect_cancelled{false};
    std::atomic_bool timer_cancelled{false};
    auto error_message = std::string();

    // start timer
    timer.expires_from_now(timeout);

    // connect callback
    socket.async_connect(endpoint, [&](const std::error_code& ec) {
        std::lock_guard<std::mutex> guard{mutex};
        if (connect_cancelled.load(std::memory_order_acquire)) return;
        timer_cancelled.store(true, std::memory_order_release);
        timer.cancel();
        if(ec) {
            error_message = "ERROR: " + ec.message() + " (" + sl::support::to_string(ec.value()) + ")";
        }
    });

    // timeout callback
    timer.async_wait([&](const std::error_code&) {
        std::lock_guard<std::mutex> guard{mutex};
        if (timer_cancelled.load(std::memory_order_acquire)) return;
        connect_cancelled.store(true, std::memory_order_release);
        socket.close();
        error_message = "ERROR: Connection timed out (-1)";
    });

    // perform connection
    service.run();

    // return result, empty on success
    return error_message;
}

} // namespace

class tcp_operations::impl : public staticlib::pimpl::object::impl {

public:

    static std::string wait_for_connection(const std::string& ip_addr,
            uint16_t tcp_port, std::chrono::milliseconds timeout) {
        std::mutex mutex{};
        asio::io_service service{};
        asio::ip::tcp::endpoint endpoint{asio::ip::address_v4::from_string(ip_addr), tcp_port};
        uint64_t start = current_time_millis();
        auto tc = static_cast<uint64_t>(timeout.count());
        auto attempt_timeout = std::chrono::milliseconds(100);
        std::string err = "ERROR: Invalid timeout: [" + sl::support::to_string(tc) + "] (-1)";
        while (current_time_millis() - start < tc) {
            err = perform_check(mutex, service, endpoint, attempt_timeout);
            if (err.empty()) break;
            std::this_thread::sleep_for(attempt_timeout);
        }
        return err;
    }
    
    static std::string resolve_ip_address(const std::string& hostname,
            std::chrono::milliseconds timeout) {
        (void) hostname;
        (void) timeout;
        return std::string();
    }

};

PIMPL_FORWARD_METHOD_STATIC(tcp_operations, std::string, wait_for_connection, 
        (const std::string&)(uint16_t)(std::chrono::milliseconds), (), support::exception)
PIMPL_FORWARD_METHOD_STATIC(tcp_operations, std::string, resolve_ip_address, 
        (const std::string&)(std::chrono::milliseconds), (), support::exception)

} // namespace
}





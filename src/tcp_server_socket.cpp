/*
 * Copyright 2018, alex at staticlibs.net
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
 * File:   tcp_server_socket.cpp
 * Author: alex
 *
 * Created on February 17, 2018, 3:33 PM
 */

#include "asio.hpp"

#include "staticlib/pimpl/forward_macros.hpp"

#include "tcp_server_socket.hpp"
#include "wilton_socket_impl.hpp"

namespace wilton {
namespace net {

class tcp_server_socket::impl : public wilton_socket::impl {

    asio::ip::tcp::socket socket;

public:
    impl(const std::string& ip_addr, uint16_t port, std::chrono::milliseconds timeout) :
    wilton_socket::impl(ip_addr, port, timeout),
    socket(service) {

        // prepare state
        asio::ip::tcp::endpoint endpoint{asio::ip::address_v4::from_string(ip_addr), port};
        asio::ip::tcp::acceptor acceptor{service, endpoint};
        acceptor.non_blocking(true);
        asio::steady_timer timer{service};
        auto accept_canceled = false;
        auto timer_canceled = false;
        auto error = std::string();

        // start timer
        timer.expires_from_now(timeout);

        // accept callback
        acceptor.async_accept(socket, [&](const std::error_code& ec) {
            if (accept_canceled) return;
            timer_canceled = true;
            timer.cancel();
            if(ec) {
                error = "Accept error, IP: [" + ip_addr + "]," +
                        " port: [" + sl::support::to_string(port) + "]," +
                        " message: [" + ec.message() + "]," +
                        " code: [" + sl::support::to_string(ec.value()) + "]";
                return;
            }
        });

        // timeout callback
        timer.async_wait([&](const std::error_code&) {
            if (timer_canceled) return;
            accept_canceled = true;
            acceptor.cancel();
            error = "Operation timed out, timeout millis: [" + sl::support::to_string(timeout.count()) + "]";
        });

        // perform connection, callbacks will be called only from the current thread
        service.run();

        // check results
        if (!error.empty()) throw support::exception(TRACEMSG(error));

        // set socket mode
        socket.non_blocking(true);
    }
    
    ~impl() STATICLIB_NOEXCEPT { };

    void async_write_some(sl::io::span<const char> data,
            std::function<void(const std::error_code&, size_t)> writer) override {
        socket.async_write_some(asio::buffer(data.data(), data.size()), writer);
    }

    virtual void async_read_some(std::function<void(const std::error_code&)> cb) override {
        socket.async_read_some(asio::null_buffers(), [cb](const std::error_code& ec, std::size_t) {
            cb(ec);
        });
    }

    virtual size_t sync_read_some(sl::io::span<char> buffer) override {
        return socket.read_some(asio::buffer(buffer.data(), buffer.size()));
    }

    virtual void cancel() override {
        socket.cancel();
    }

    virtual size_t available() override {
        return socket.available();
    }

};
PIMPL_FORWARD_CONSTRUCTOR(tcp_server_socket, (const std::string&)(uint16_t)(std::chrono::milliseconds),
        (), support::exception)

} // namespace
}

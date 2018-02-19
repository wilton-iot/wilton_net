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
 * File:   tcp_client_socket.cpp
 * Author: alex
 *
 * Created on February 16, 2018, 9:21 PM
 */

#include "asio.hpp"

#include "staticlib/pimpl/forward_macros.hpp"

#include "tcp_client_socket.hpp"
#include "wilton_socket_impl.hpp"

namespace wilton {
namespace net {

class tcp_client_socket::impl : public wilton_socket::impl {
    const std::string ip_address;
    const uint16_t tcp_port;
    
    asio::io_service service;
    asio::ip::tcp::socket socket;
    std::vector<char> buffer;

public:
    impl(const std::string& ip_addr, uint16_t port, std::chrono::milliseconds timeout) :
    ip_address(ip_addr.data(), ip_addr.length()),
    tcp_port(port),
    socket(service) {

        // prepare state
        asio::steady_timer timer{service};
        asio::ip::tcp::endpoint endpoint{asio::ip::address_v4::from_string(ip_addr), port};
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
                error = "Connect error, IP: [" + ip_addr + "]," +
                        " port: [" + sl::support::to_string(port) + "]," +
                        " message: [" + ec.message() + "]," +
                        " code: [" + sl::support::to_string(ec.value()) + "]";
                return;
            }
        });

        // timeout callback
        timer.async_wait([&](const std::error_code&) {
            if (timer_canceled) return;
            connect_canceled = true;
            socket.cancel();
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

    virtual void write(wilton_socket&, sl::io::span<const char> data, std::chrono::milliseconds timeout) override {
        (void) data;
        (void) timeout;
        // todo
    }

    virtual sl::io::span<const char> read_some(wilton_socket&, uint32_t max_bytes_to_read,
            std::chrono::milliseconds timeout) override {

        // prepare state
        service.reset();
        asio::steady_timer timer{service};
        auto read_canceled = false;
        auto timer_canceled = false;
        auto error = std::string();

        // start timer
        timer.expires_from_now(timeout);

        // read callback, see: http://think-async.com/Asio/asio-1.10.6/doc/asio/overview/core/reactor.html
        socket.async_read_some(asio::null_buffers(), [&](const std::error_code& ec, std::size_t) {
            if (read_canceled) return;
            timer_canceled = true;
            timer.cancel();
            if(ec) {
                error = "Read error, IP: [" + ip_address + "]," +
                        " port: [" + sl::support::to_string(tcp_port) + "]," +
                        " message: [" + ec.message() + "]," +
                        " code: [" + sl::support::to_string(ec.value()) + "]";
                return;
            }
            auto avail = socket.available();
            auto to_read = avail < max_bytes_to_read ? avail : max_bytes_to_read;
            buffer.resize(to_read);
            auto dest = asio::buffer(buffer.data(), buffer.size());
            auto read = socket.read_some(dest);
            if (0 == read) throw support::exception(TRACEMSG(
                    "Invalid empty read, IP: [" + ip_address + "]," +
                    " port: [" + sl::support::to_string(tcp_port) + "]," +
                    " max bytes to read: [" + sl::support::to_string(max_bytes_to_read) + "]," +
                    " bytes available: [" + sl::support::to_string(avail) + "]"));
            if (read < to_read) {
                buffer.resize(read);
            }
        });

        // timeout callback
        timer.async_wait([&](const std::error_code&) {
            if (timer_canceled) return;
            read_canceled = true;
            socket.cancel();
            error = "Operation timed out, timeout millis: [" + sl::support::to_string(timeout.count()) + "]";
        });

        // perform connection, callbacks will be called only from the current thread
        service.run();

        // check results
        if (!error.empty()) throw support::exception(TRACEMSG(error));

        // return view to internal buffer
        return sl::io::make_span(const_cast<const char*>(buffer.data()), buffer.size());
    }

};
PIMPL_FORWARD_CONSTRUCTOR(tcp_client_socket, (const std::string&)(uint16_t)(std::chrono::milliseconds),
        (), support::exception)

} // namespace
}

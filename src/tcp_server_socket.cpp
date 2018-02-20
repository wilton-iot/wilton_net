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
#include "tcp_socket_writer.hpp"
#include "wilton_socket_impl.hpp"

namespace wilton {
namespace net {

class tcp_server_socket::impl : public wilton_socket::impl {
    const std::string ip_address;
    const uint16_t tcp_port;

    asio::io_service service;
    asio::ip::tcp::socket socket;
    std::vector<char> read_buffer;

public:
    impl(const std::string& ip_addr, uint16_t port, std::chrono::milliseconds timeout) :
    ip_address(ip_addr.data(), ip_addr.length()),
    tcp_port(port),
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

    virtual void write(wilton_socket&, sl::io::span<const char> data, std::chrono::milliseconds timeout) override {

        // prepare state
        service.reset();
        asio::steady_timer timer{service};
        auto write_canceled = false;
        auto timer_canceled = false;
        auto error = std::string();

        // start timer
        timer.expires_from_now(timeout);

        // write callback
        auto writer = tcp_socket_writer(socket, timer, write_canceled, timer_canceled,
                error, data, 0);
        socket.async_write_some(asio::buffer(data.data(), data.size()), writer);

        // timeout callback
        timer.async_wait([&](const std::error_code&) {
            if (timer_canceled) return;
            write_canceled = true;
            socket.cancel();
            error = "Operation timed out, timeout millis: [" + sl::support::to_string(timeout.count()) + "]";
        });

        // perform connection, callbacks will be called only from the current thread
        service.run();

        // check results
        if (!error.empty()) throw support::exception(TRACEMSG(error));
    }

    virtual sl::io::span<const char> read_some(wilton_socket&, uint32_t max_bytes_to_read,
            std::chrono::milliseconds timeout) override {

        // prepare state
        read_buffer.resize(0);
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
            if (avail > 0) {
                auto to_read = avail < max_bytes_to_read ? avail : max_bytes_to_read;
                read_buffer.resize(to_read);
                auto dest = asio::buffer(read_buffer.data(), read_buffer.size());
                auto read = socket.read_some(dest);
                if (0 == read) throw support::exception(TRACEMSG(
                        "Invalid empty read, IP: [" + ip_address + "]," +
                        " port: [" + sl::support::to_string(tcp_port) + "]," +
                        " max bytes to read: [" + sl::support::to_string(max_bytes_to_read) + "]," +
                        " bytes available: [" + sl::support::to_string(avail) + "]"));
                if (read < to_read) {
                    read_buffer.resize(read);
                }
            }
        });

        // timeout callback
        timer.async_wait([&](const std::error_code&) {
            if (timer_canceled) return;
            read_canceled = true;
            socket.cancel();
            // empty response is returned on timeout
        });

        // perform connection, callbacks will be called only from the current thread
        service.run();

        // check results
        if (!error.empty()) throw support::exception(TRACEMSG(error));

        // return view to internal buffer
        if (read_buffer.size() > 0 ) {
            return sl::io::make_span(const_cast<const char*>(read_buffer.data()), read_buffer.size());
        } else {
            return sl::io::span<const char>(nullptr, 0);
        }
    }

};
PIMPL_FORWARD_CONSTRUCTOR(tcp_server_socket, (const std::string&)(uint16_t)(std::chrono::milliseconds),
        (), support::exception)

} // namespace
}

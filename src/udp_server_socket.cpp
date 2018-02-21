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
 * File:   udp_server_socket.cpp
 * Author: alex
 *
 * Created on February 21, 2018, 2:18 PM
 */

#include "asio.hpp"

#include "staticlib/pimpl/forward_macros.hpp"

#include "udp_server_socket.hpp"
#include "wilton_socket_impl.hpp"

namespace wilton {
namespace net {

class udp_server_socket::impl : public wilton_socket::impl {

    asio::ip::udp::socket socket;

public:
    impl(const std::string& ip_addr, uint16_t port, std::chrono::milliseconds) :
    wilton_socket::impl(ip_addr, port),
    socket(service) {

        // prepare state
        asio::ip::udp::endpoint endpoint{asio::ip::address_v4::from_string(ip_addr), port};
        socket.open(asio::ip::udp::v4());
        socket.bind(endpoint);

        // set socket mode
        socket.non_blocking(true);
    }
    
    ~impl() STATICLIB_NOEXCEPT { };

    void async_write_some(sl::io::span<const char>,
            std::function<void(const std::error_code&, size_t)>) override {
        throw support::exception(TRACEMSG(
                "Write operation is not supported by UDP server socket," +
                " please use UDP client socket instead"));
    }

    virtual void async_read_some(std::function<void(const std::error_code&)> cb) override {
        socket.async_receive(asio::null_buffers(), [cb](const std::error_code& ec, std::size_t) {
            cb(ec);
        });
    }

    virtual size_t sync_read_some(sl::io::span<char> buffer) override {
        return socket.receive(asio::buffer(buffer.data(), buffer.size()));
    }

    virtual void cancel() override {
        socket.cancel();
    }

    virtual size_t available() override {
        return socket.available();
    }

};
PIMPL_FORWARD_CONSTRUCTOR(udp_server_socket, (const std::string&)(uint16_t)(std::chrono::milliseconds),
        (), support::exception)

} // namespace
}

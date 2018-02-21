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
 * File:   wilton_socker_impl.hpp
 * Author: alex
 *
 * Created on February 16, 2018, 8:39 PM
 */

#ifndef WILTON_NET_WILTON_SOCKET_IMPL_HPP
#define WILTON_NET_WILTON_SOCKET_IMPL_HPP


#include "wilton_socket.hpp"

#include <functional>

#include "asio.hpp"

namespace wilton {
namespace net {

class wilton_socket::impl : public sl::pimpl::object::impl {
protected:
    const std::string ip_address;
    const uint16_t protocol_port;

    asio::io_service service;
    std::vector<char> read_buffer;

public:
    impl(const std::string& ip_addr, uint16_t port) :
    ip_address(ip_addr.data(), ip_addr.length()),
    protocol_port(port) { }

    ~impl() STATICLIB_NOEXCEPT { }

    virtual void async_write_some(sl::io::span<const char> data,
            std::function<void(const std::error_code&, size_t)> writer) = 0;

    virtual void async_read_some(std::function<void(const std::error_code&)> cb) = 0;

    virtual size_t sync_read_some(sl::io::span<char> buffer) = 0;

    virtual void cancel() = 0;

    virtual size_t available() = 0;

    void write(wilton_socket&, sl::io::span<const char> data, std::chrono::milliseconds timeout);

    sl::io::span<const char> read_some(wilton_socket&, uint32_t max_bytes_to_read, std::chrono::milliseconds timeout);

    void read(wilton_socket&, sl::io::span<char> buffer, std::chrono::milliseconds timeout);
};

} // namespace
}
#endif /* WILTON_NET_WILTON_SOCKET_IMPL_HPP */


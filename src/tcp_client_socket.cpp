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

#include "staticlib/pimpl/forward_macros.hpp"

#include "tcp_client_socket.hpp"
#include "wilton_socket_impl.hpp"

namespace wilton {
namespace net {

class tcp_client_socket::impl : public wilton_socket::impl {

public:
    impl(const std::string& ip_addr, uint16_t port, std::chrono::milliseconds timeout) {
        (void) ip_addr;
        (void) port;
        (void) timeout;
        // todo: connect socket to endpoint
    }

    virtual void write(wilton_socket&, sl::io::span<const char> data, std::chrono::milliseconds timeout) override {
        (void) data;
        (void) timeout;
        // todo
    }

    virtual sl::io::span<char> read_some(wilton_socket&, uint32_t max_bytes_to_read,
            std::chrono::milliseconds timeout) override {
        (void) max_bytes_to_read;
        (void) timeout;
        // todo
        return {nullptr, 0};

    }

};
PIMPL_FORWARD_CONSTRUCTOR(tcp_client_socket, (const std::string&)(uint16_t)(std::chrono::milliseconds),
        (), support::exception)

} // namespace
}

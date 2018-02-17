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
 * File:   tcp_server_socket.hpp
 * Author: alex
 *
 * Created on February 16, 2018, 12:07 PM
 */

#ifndef WILTON_NET_TCP_SERVER_SOCKET_HPP
#define WILTON_NET_TCP_SERVER_SOCKET_HPP

#include <cstdint>
#include <chrono>
#include <string>

#include "wilton_socket.hpp"

namespace wilton {
namespace net {

class tcp_server_socket : public wilton_socket {
protected:
    /**
     * implementation class
     */
    class impl;

    /**
     * PIMPL-specific constructor
     *
     * @param pimpl impl object
     */
    PIMPL_INHERIT_CONSTRUCTOR(tcp_server_socket, wilton_socket)

public:
    tcp_server_socket(const std::string& ip_addr, uint16_t port, std::chrono::milliseconds timeout);

};

} // namespace
}

#endif /* WILTON_NET_TCP_SERVER_SOCKET_HPP */

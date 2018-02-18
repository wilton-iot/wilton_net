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
 * File:   wilton_socket.hpp
 * Author: alex
 *
 * Created on February 16, 2018, 8:37 PM
 */

#ifndef WILTON_NET_WILTON_SOCKET_HPP
#define WILTON_NET_WILTON_SOCKET_HPP

#include <cstdint>
#include <chrono>

#include "staticlib/io.hpp"
#include "staticlib/pimpl.hpp"

#include "wilton/support/exception.hpp"

namespace wilton {
namespace net {

class wilton_socket : public sl::pimpl::object {
protected:
    /**
     * implementation class
     */
    class impl;

public:
    /**
     * PIMPL-specific constructor
     *
     * @param pimpl impl object
     */
    PIMPL_CONSTRUCTOR(wilton_socket)

    void write(sl::io::span<const char> data, std::chrono::milliseconds timeout);

    sl::io::span<char> read_some(uint32_t max_bytes_to_read, std::chrono::milliseconds timeout);

    sl::io::span<char> read(uint32_t bytes_to_read, std::chrono::milliseconds timeout);

};

} // namespace
}

#endif /* WILTON_NET_WILTON_SOCKET_HPP */


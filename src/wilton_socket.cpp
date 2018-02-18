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
 * File:   wilton_socket.cpp
 * Author: alex
 *
 * Created on February 17, 2018, 8:44 PM
 */

#include "wilton_socket_impl.hpp"

#include "staticlib/pimpl/forward_macros.hpp"

namespace wilton {
namespace net {

sl::io::span<char> wilton_socket::impl::read(wilton_socket&, uint32_t bytes_to_read, std::chrono::milliseconds timeout) {
    (void) bytes_to_read;
    (void) timeout;
    // todo loop over read_some
    return {nullptr, 0};
}
PIMPL_FORWARD_METHOD(wilton_socket, sl::io::span<char>, read, (uint32_t)(std::chrono::milliseconds), (), support::exception);
// forward pure virtual methods
PIMPL_FORWARD_METHOD(wilton_socket, void, write, (sl::io::span<const char>)(std::chrono::milliseconds), (), support::exception);
PIMPL_FORWARD_METHOD(wilton_socket, sl::io::span<char>, read_some, (uint32_t)(std::chrono::milliseconds), (), support::exception);

} // namespace
}

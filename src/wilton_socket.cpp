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

#include <cstring>
#include <vector>

#include "staticlib/pimpl/forward_macros.hpp"
#include "staticlib/utils.hpp"

namespace wilton {
namespace net {

void wilton_socket::impl::read(wilton_socket& facade, sl::io::span<char> buffer, std::chrono::milliseconds timeout) {
    uint64_t start = sl::utils::current_time_millis_steady();
    uint64_t finish = start + timeout.count();
    uint64_t cur = start;
    uint32_t read = 0;
    for (;;) {
        uint64_t passed = cur - start;
        auto tm = std::chrono::milliseconds(timeout.count() - passed);
        auto span = facade.read_some(buffer.size() - read, tm);
        std::memcpy(buffer.data() + read, span.data(), span.size());
        read += span.size();
        if (read >= buffer.size()) {
            break;
        }
        cur = sl::utils::current_time_millis_steady();
        if (cur >= finish) {
            break;
        }
    }
    if (read < buffer.size()) throw support::exception(TRACEMSG(
            "Short read read from socket, bytes requested: [" + sl::support::to_string(buffer.size()) + "],"
            " bytes read: [" + sl::support::to_string(read) + "],"
            " timeout millis: [" + sl::support::to_string(timeout.count()) + "]"));
}
PIMPL_FORWARD_METHOD(wilton_socket, void, read, (sl::io::span<char>)(std::chrono::milliseconds), (), support::exception);
// forward pure virtual methods
PIMPL_FORWARD_METHOD(wilton_socket, void, write, (sl::io::span<const char>)(std::chrono::milliseconds), (), support::exception);
PIMPL_FORWARD_METHOD(wilton_socket, sl::io::span<const char>, read_some, (uint32_t)(std::chrono::milliseconds), (), support::exception);

} // namespace
}

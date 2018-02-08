/*
 * Copyright 2017, alex at staticlibs.net
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
 * File:   wilton_net.cpp
 * Author: alex
 *
 * Created on October 17, 2017, 8:59 PM
 */

#include "wilton/wilton_net.h"

#include <cstdint>
#include <string>

#include "staticlib/config.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/alloc_copy.hpp"
#include "wilton/support/logging.hpp"

#include "tcp_connect_checker.hpp"

namespace { // anonymous

const std::string LOGGER = std::string("wilton.net");

} // namespace

char* wilton_net_wait_for_tcp_connection(const char* ip_addr, int ip_addr_len, 
        int tcp_port, int timeout_millis) /* noexcept */ {
    if (nullptr == ip_addr) return wilton::support::alloc_copy(TRACEMSG("Null 'ip_addr' parameter specified"));
    if (!sl::support::is_uint32(ip_addr_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'ip_addr_len' parameter specified: [" + sl::support::to_string(ip_addr_len) + "]"));
    if (!sl::support::is_uint16_positive(tcp_port)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'tcp_port' parameter specified: [" + sl::support::to_string(tcp_port) + "]"));
    if (!sl::support::is_uint32_positive(timeout_millis)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'timeout_millis' parameter specified: [" + sl::support::to_string(timeout_millis) + "]"));
    try {
        auto ip_addr_str = std::string(ip_addr, static_cast<uint32_t> (ip_addr_len));
        uint16_t tcp_port_u16 = static_cast<uint16_t> (tcp_port);
        uint32_t timeout_millis_u32 = static_cast<uint32_t> (timeout_millis);
        std::chrono::milliseconds timeout{timeout_millis_u32};
        wilton::support::log_debug(LOGGER, "Awaiting TCP connection, IP: [" + ip_addr_str + "]," +
                " port: [" + sl::support::to_string(tcp_port_u16) + "]," +
                " timeout: [" + sl::support::to_string(timeout_millis_u32) + "]...");
        std::string err = wilton::net::tcp_connect_checker::wait_for_connection(timeout, ip_addr_str, tcp_port_u16);
        wilton::support::log_debug(LOGGER, "TCP connection wait complete, result: [" + err + "]");
        if (err.empty()) {
            return nullptr;
        } else {
            return wilton::support::alloc_copy(err);
        }
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

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
#include <memory>

#include "asio.hpp"

#include "staticlib/config.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/alloc_copy.hpp"
#include "wilton/support/logging.hpp"
#include "wilton/support/buffer.hpp"
#include "wilton/support/handle_registry.hpp"

#include "tcp_connect_checker.hpp"
#include "socket_handler.h"

namespace { // anonymous

const std::string LOGGER = std::string("wilton.net");

} // namespace

struct wilton_socket_handler {
private:
    wilton::net::socket_handler socket;

public:
    wilton_socket_handler(wilton::net::socket_handler&& _socket) :
    socket(std::move(_socket)) { }

    wilton::net::socket_handler& impl() {
        return socket;
    }
};

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

char* wilton_net_socket_open(wilton_socket_handler** handler, const char* ip_addr,
        int ip_addr_len, int tcp_port, const char* type_str, int type_str_len) {
    // check params
    if (nullptr == handler) return wilton::support::alloc_copy(TRACEMSG("Null 'handler' parameter specified"));
    if (nullptr == ip_addr) return wilton::support::alloc_copy(TRACEMSG("Null 'ip_addr' parameter specified"));
    if (!sl::support::is_uint32(ip_addr_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'ip_addr_len' parameter specified: [" + sl::support::to_string(ip_addr_len) + "]"));
    if (!sl::support::is_uint16_positive(tcp_port)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'tcp_port' parameter specified: [" + sl::support::to_string(tcp_port) + "]"));
    if (nullptr == type_str) return wilton::support::alloc_copy(TRACEMSG("Null 'type_str' parameter specified"));
    if (!sl::support::is_uint32(type_str_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'type_str_len' parameter specified: [" + sl::support::to_string(type_str_len) + "]"));

    try {
        // check UDP/TCP type
        std::string type_literal(type_str, type_str_len);
        wilton::net::ip_protocol type;
        if (!type_literal.compare("TCP")) {
            type = wilton::net::ip_protocol::TCP;
        } else if (!type_literal.compare("UDP")) {
            type = wilton::net::ip_protocol::UDP;
        } else {
            return wilton::support::alloc_copy(TRACEMSG("Invalid 'protocolType' parameter specified: [" +
                    type_literal + "]. Should be TCP/UDP"));
        }

        std::string ip(ip_addr, ip_addr_len);

        wilton::net::socket_handler socket(type);
        wilton_socket_handler* socket_ptr = new wilton_socket_handler{std::move(socket)};

        *handler = socket_ptr; // setup pointer to socket for next use
        wilton::support::log_debug(LOGGER, "Awaiting " + type_literal + " connection, IP: [" + ip + "]," +
                " port: [" + sl::support::to_string(tcp_port) + "] ...");

        std::error_code err = socket_ptr->impl().open(ip, tcp_port);

        wilton::support::log_debug(LOGGER, type_literal + " connection wait complete, result: [" + err.message() + "]");
        if (!err) { // if error code is 0
            return nullptr;
        } else {
            return wilton::support::alloc_copy(err.message());
        }
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_net_socket_close(wilton_socket_handler* handler) {
    if (nullptr == handler) return wilton::support::alloc_copy(TRACEMSG("Null 'handler' parameter specified"));
    try {
        wilton::support::log_debug(LOGGER, "Closing connection, handle: [" + wilton::support::strhandle(handler) + "] ...");

        std::error_code err = handler->impl().close();
        delete handler;

        wilton::support::log_debug(LOGGER, "Connection closed, result: [" + err.message() + "]");
        if (!err) { // if error code is 0
            return nullptr;
        } else {
            return wilton::support::alloc_copy(err.message());
        }
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_net_socket_write(wilton_socket_handler* handler, const char* data, int data_len){
    if (nullptr == handler) return wilton::support::alloc_copy(TRACEMSG("Null 'handler' parameter specified"));
    if (nullptr == data) return wilton::support::alloc_copy(TRACEMSG("Null 'data' parameter specified"));
    if (!sl::support::is_uint32(data_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'data_len' parameter specified: [" + sl::support::to_string(data_len) + "]"));
    // try to send data
    try {
        wilton::support::log_debug(LOGGER, "Write data to socket, handle: [" + wilton::support::strhandle(handler) + "]" +
                "\n[" + std::string(data, data_len) +  " ]");

        std::error_code err = handler->impl().write(data, data_len);

        wilton::support::log_debug(LOGGER, "Write operation complete, result: [" + err.message() + "]");
        if (!err) { // if error code is 0
            return nullptr;
        } else {
            return wilton::support::alloc_copy(err.message());
        }
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_net_socket_read(wilton_socket_handler* handler, char** out_data, int& data_len) {
    if (nullptr == handler) return wilton::support::alloc_copy(TRACEMSG("Null 'handler' parameter specified"));
    if (nullptr == out_data) return wilton::support::alloc_copy(TRACEMSG("Null 'out_data' parameter specified"));
    if (!sl::support::is_uint32(data_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'data_len' parameter specified: [" + sl::support::to_string(data_len) + "]"));

    // try to read data
    try {
        wilton::support::log_debug(LOGGER, "Read data from socket, handle: [" +
                wilton::support::strhandle(handler) + "] ...");

        std::error_code err = handler->impl().read(out_data, data_len);

        wilton::support::log_debug(LOGGER, "Write operation complete. Data: \n[" +
                std::string(*out_data, data_len) + " ], result: [" + err.message() + "]");
        if (!err) { // if error code is 0
            return nullptr;
        } else {
            return wilton::support::alloc_copy(err.message());
        }
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

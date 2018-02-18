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
#include <array>
#include <chrono>
#include <limits>
#include <string>
#include <memory>

#include "staticlib/config.hpp"
#include "staticlib/ranges.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/alloc_copy.hpp"
#include "wilton/support/logging.hpp"
#include "wilton/support/buffer.hpp"
#include "wilton/support/handle_registry.hpp"

#include "tcp_client_socket.hpp"
#include "tcp_operations.hpp"
#include "tcp_server_socket.hpp"

namespace { // anonymous

const std::string LOGGER = std::string("wilton.net");

wilton::net::wilton_socket create_socket(const std::string& ip_addr, uint16_t tcp_port,
        const std::string& protocol, const std::string& role, std::chrono::milliseconds timeout) {
    if ("TCP" == protocol) {
        if ("server" == role) {
            return wilton::net::tcp_server_socket(ip_addr, tcp_port, timeout);
        } else if("client" == role) {
            return wilton::net::tcp_client_socket(ip_addr, tcp_port, timeout);
        } else {
            throw wilton::support::exception(TRACEMSG("Invalid 'role' parameter" +
                    " specified: [" + role + "], must be one of: [server, client]"));
        }
//        } else if ("UDP" == protocol_str) {
    } else {
        throw wilton::support::exception(TRACEMSG("Invalid 'protocol' parameter" +
                " specified: [" + protocol + "], must be one of: [TCP, UDP]"));
    }
}

} // namespace

struct wilton_Socket {
private:
    wilton::net::wilton_socket socket;

public:
    wilton_Socket(wilton::net::wilton_socket&& socket) :
    socket(std::move(socket)) { }

    wilton::net::wilton_socket& impl() {
        return socket;
    }
};

char* wilton_net_socket_open(wilton_Socket** socket_out,
        const char* ip_addr, int ip_addr_len, int tcp_port,
        const char* protocol, int protocol_len, const char* role, int role_len,
        int timeout_millis) /* noexcept */ {
    if (nullptr == socket_out) return wilton::support::alloc_copy(TRACEMSG("Null 'socket_out' parameter specified"));
    if (nullptr == ip_addr) return wilton::support::alloc_copy(TRACEMSG("Null 'ip_addr' parameter specified"));
    if (!sl::support::is_uint16_positive(ip_addr_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'ip_addr_len' parameter specified: [" + sl::support::to_string(ip_addr_len) + "]"));
    if (!sl::support::is_uint16_positive(tcp_port)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'tcp_port' parameter specified: [" + sl::support::to_string(tcp_port) + "]"));
    if (nullptr == protocol) return wilton::support::alloc_copy(TRACEMSG("Null 'protocol' parameter specified"));
    if (!sl::support::is_uint16_positive(protocol_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'protocol_len' parameter specified: [" + sl::support::to_string(protocol_len) + "]"));
    if (nullptr == role) return wilton::support::alloc_copy(TRACEMSG("Null 'role' parameter specified"));
    if (!sl::support::is_uint16_positive(role_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'role_len' parameter specified: [" + sl::support::to_string(role_len) + "]"));
    if (!sl::support::is_uint32_positive(timeout_millis)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'timeout_millis' parameter specified: [" + sl::support::to_string(timeout_millis) + "]"));
    try {
        auto ip_addr_str = std::string(ip_addr, static_cast<size_t>(ip_addr_len));
        auto protocol_str = std::string(protocol, static_cast<size_t>(protocol_len));
        auto role_str = std::string(role, static_cast<size_t>(role_len));
        auto timeout = std::chrono::milliseconds(timeout_millis);
        wilton::support::log_debug(LOGGER, "Opening socket, ip: [" + ip_addr_str + "]," +
                " port: [" + sl::support::to_string(tcp_port) + "]," +
                " protocol: [" + protocol_str + "], role: [" + role_str + "]," +
                " timeout: [" + sl::support::to_string(timeout_millis) + "] ...");
        auto socket = create_socket(ip_addr_str, static_cast<uint16_t>(tcp_port), protocol_str, role_str, timeout);
        wilton_Socket* socket_ptr = new wilton_Socket(std::move(socket));
        *socket_out = socket_ptr;
        wilton::support::log_debug(LOGGER, "Socket created, handle: [" + wilton::support::strhandle(socket_ptr) + "]");
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_net_socket_close(wilton_Socket* socket) /* noexcept */ {
    if (nullptr == socket) return wilton::support::alloc_copy(TRACEMSG("Null 'socket' parameter specified"));
    try {
        wilton::support::log_debug(LOGGER, "Closing socket, handle: [" + wilton::support::strhandle(socket) + "] ...");
        delete socket;
        wilton::support::log_debug(LOGGER, "Socket closed");
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_net_socket_write(wilton_Socket* socket, const char* data, int data_len,
            int timeout_millis) /* noexcept */ {
    if (nullptr == socket) return wilton::support::alloc_copy(TRACEMSG("Null 'socket' parameter specified"));
    if (nullptr == data) return wilton::support::alloc_copy(TRACEMSG("Null 'data' parameter specified"));
    if (!sl::support::is_uint32_positive(data_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'data_len' parameter specified: [" + sl::support::to_string(data_len) + "]"));
    if (!sl::support::is_uint32_positive(timeout_millis)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'timeout_millis' parameter specified: [" + sl::support::to_string(timeout_millis) + "]"));
    try {
        wilton::support::log_debug(LOGGER, std::string("Writing data to socket,") +
                " handle: [" + wilton::support::strhandle(socket) + "]," +
                " data_len: [" + sl::support::to_string(data_len) +  "],"
                " timeout: [" + sl::support::to_string(timeout_millis) + "] ...");
        socket->impl().write({data, data_len}, std::chrono::milliseconds(timeout_millis));
        wilton::support::log_debug(LOGGER, "Write operation complete");
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_net_socket_read_some(wilton_Socket* socket, int timeout_millis,
        char** data_out, int* data_len_out) {
    if (nullptr == socket) return wilton::support::alloc_copy(TRACEMSG("Null 'socket' parameter specified"));
    if (!sl::support::is_uint32_positive(timeout_millis)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'timeout_millis' parameter specified: [" + sl::support::to_string(timeout_millis) + "]"));
    if (nullptr == data_out) return wilton::support::alloc_copy(TRACEMSG("Null 'data_out' parameter specified"));
    if (nullptr == data_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'data_len_out' parameter specified"));
    try {
        wilton::support::log_debug(LOGGER, std::string("Reading some data from socket,") +
                " handle: [" + wilton::support::strhandle(socket) + "]," +
                " timeout: [" + sl::support::to_string(timeout_millis) + "] ...");
        auto span = socket->impl().read_some(std::numeric_limits<uint32_t>::max(),
                std::chrono::milliseconds(timeout_millis));
        wilton::support::log_debug(LOGGER, std::string("Read-some operation complete,") +
                " bytes read: [" + sl::support::to_string(span.size()) + "]");
        auto buf = wilton::support::make_span_buffer(span);
        if (buf.has_value()) {
            *data_out = buf.value().data();
            *data_len_out = static_cast<int>(buf.value().size());
        } else {
            *data_out = nullptr;
            *data_len_out = 0;
        }
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_net_socket_read(wilton_Socket* socket, int bytes_to_read, int timeout_millis,
        char** data_out, int* data_len_out) /* noexcept */ {
    if (nullptr == socket) return wilton::support::alloc_copy(TRACEMSG("Null 'socket' parameter specified"));
    if (!sl::support::is_uint32_positive(bytes_to_read)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'bytes_to_read' parameter specified: [" + sl::support::to_string(bytes_to_read) + "]"));
    if (!sl::support::is_uint32_positive(timeout_millis)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'timeout_millis' parameter specified: [" + sl::support::to_string(timeout_millis) + "]"));
    if (nullptr == data_out) return wilton::support::alloc_copy(TRACEMSG("Null 'data_out' parameter specified"));
    if (nullptr == data_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'data_len_out' parameter specified"));
    try {
        wilton::support::log_debug(LOGGER, std::string("Reading data from socket,") +
                " handle: [" + wilton::support::strhandle(socket) + "]," +
                " bytes_to_read: [" + sl::support::to_string(bytes_to_read) + "]," +
                " timeout: [" + sl::support::to_string(timeout_millis) + "] ...");
        auto span = socket->impl().read(
                static_cast<uint32_t>(bytes_to_read), std::chrono::milliseconds(timeout_millis));
        wilton::support::log_debug(LOGGER, std::string("Read operation complete,") +
                " bytes read: [" + sl::support::to_string(span.size()) + "]");
        auto buf = wilton::support::make_span_buffer(span);
        if (buf.has_value()) {
            *data_out = buf.value().data();
            *data_len_out = static_cast<int>(buf.value().size());
        } else {
            *data_out = nullptr;
            *data_len_out = 0;
        }
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_net_resolve_hostname(const char* hostname, int hostname_len,
        int timeout_millis, char** ip_addr_out, int* ip_addr_len_out) /* noexcept */ {
    if (nullptr == hostname) return wilton::support::alloc_copy(TRACEMSG("Null 'hostname' parameter specified"));
    if (!sl::support::is_uint16_positive(hostname_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'hostname_len' parameter specified: [" + sl::support::to_string(hostname_len) + "]"));
    if (!sl::support::is_uint32_positive(timeout_millis)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'timeout_millis' parameter specified: [" + sl::support::to_string(timeout_millis) + "]"));
    if (nullptr == ip_addr_out) return wilton::support::alloc_copy(TRACEMSG("Null 'ip_addr_out' parameter specified"));
    if (nullptr == ip_addr_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'ip_addr_len_out' parameter specified"));
    try {
        auto hostname_str = std::string(hostname, static_cast<size_t>(hostname_len));
        wilton::support::log_debug(LOGGER, std::string("Resolving IP address,") +
                " hostname: [" + hostname_str + "]," +
                " timeout: [" + sl::support::to_string(timeout_millis) + "] ...");
        auto addr_list = wilton::net::tcp_operations::resolve_hostname(
                hostname_str, std::chrono::milliseconds(timeout_millis));
        if (addr_list.empty()) {
            return wilton::support::alloc_copy(TRACEMSG(
                    "Cannot resolve IP address, hostname: [" + hostname + "]"));
        }
        auto ra = sl::ranges::transform(std::move(addr_list), [](std::string st) {
            return sl::json::value(std::move(st));
        });
        auto buf = wilton::support::make_json_buffer(ra.to_vector());
        *ip_addr_out = buf.value().data();
        *ip_addr_len_out = static_cast<int>(buf.value().size());
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

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
        wilton::support::log_debug(LOGGER, "Awaiting TCP connection, IP: [" + ip_addr_str + "]," +
                " port: [" + sl::support::to_string(tcp_port) + "]," +
                " timeout: [" + sl::support::to_string(timeout_millis) + "]...");
        std::string err = wilton::net::tcp_operations::wait_for_connection(
                ip_addr_str, static_cast<uint16_t>(tcp_port), std::chrono::milliseconds(timeout_millis));
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

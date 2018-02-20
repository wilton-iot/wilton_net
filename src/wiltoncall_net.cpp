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
 * File:   wiltoncall_net.cpp
 * Author: alex
 *
 * Created on October 17, 2017, 8:59 PM
 */

#include "wilton/wilton_net.h"

#include "staticlib/config.hpp"
#include "staticlib/io.hpp"
#include "staticlib/json.hpp"
#include "staticlib/utils.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/handle_registry.hpp"
#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/registrar.hpp"


namespace wilton {
namespace net {

namespace { //anonymous

std::shared_ptr<support::handle_registry<wilton_Socket>> shared_socket_registry() {
    static auto registry = std::make_shared<support::handle_registry<wilton_Socket>>(
        [] (wilton_Socket* socket) STATICLIB_NOEXCEPT {
            wilton_net_Socket_close(socket);
        });
    return registry;
}

} // namespace

support::buffer socket_open(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rip = std::ref(sl::utils::empty_string()); // ref to ip string
    int64_t port = -1;
    auto rprotocol = std::ref(sl::utils::empty_string()); // ref to protocol string
    auto rrole = std::ref(sl::utils::empty_string()); // ref to protocol string
    int64_t timeout = -1;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("ipAddress" == name) {
            rip = fi.as_string_nonempty_or_throw(name);
        } else if ("tcpPort" == name || "udpPort" == name) {
            port = fi.as_int64_or_throw(name);
        } else if ("protocol" == name) {
            rprotocol = fi.as_string_nonempty_or_throw(name);
        } else if ("role" == name) {
            rrole = fi.as_string_nonempty_or_throw(name);
        } else if ("timeoutMillis" == name) {
            timeout = fi.as_int64_or_throw(name);
        }  else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    // check json data
    if (rip.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'ipAddress' not specified"));
    if (-1 == port) throw support::exception(TRACEMSG(
            "Required parameter 'tcpPort' (or 'udpPort') not specified"));
    if (rprotocol.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'protocol' not specified"));
    if (rrole.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'role' not specified"));
    if (-1 == timeout) throw support::exception(TRACEMSG(
            "Required parameter 'timeoutMillis' not specified"));
    // get handle
    const std::string& ip = rip.get();
    const std::string& protocol = rprotocol.get();
    const std::string& role = rrole.get();
    // call wilton
    wilton_Socket* socket = nullptr;
    char* err = wilton_net_Socket_open(std::addressof(socket),
            ip.c_str(), static_cast<int>(ip.length()), static_cast<int> (port),
            protocol.c_str(), static_cast<int>(protocol.length()),
            role.c_str(), static_cast<int>(role.length()),
            static_cast<int>(timeout));
    if (nullptr != err) {
        support::throw_wilton_error(err, TRACEMSG(err));
    }
    auto reg = shared_socket_registry();
    int64_t handle = reg->put(socket);
    return support::make_json_buffer({
        { "socketHandle", handle}
    });
} 


support::buffer socket_close(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("socketHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    // check json data
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'socketHandle' not specified"));
    // get handle
    auto reg = shared_socket_registry();
    wilton_Socket* socket = reg->remove(handle);
    if (nullptr == socket) throw support::exception(TRACEMSG(
            "Invalid 'socketHandle' parameter specified"));
    char* err = wilton_net_Socket_close(socket);
    if (nullptr != err) {
        reg->put(socket);
        support::throw_wilton_error(err, TRACEMSG(err));
    }
    return support::make_empty_buffer();
}

support::buffer socket_write(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    auto rpayload = std::ref(sl::utils::empty_string());
    int64_t timeout = -1;
    auto hex = false;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("socketHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else if ("data" == name) {
            rpayload = fi.as_string_nonempty_or_throw(name);
        } else if ("timeoutMillis" == name) {
            timeout = fi.as_int64_or_throw(name);
        } else if ("hex" == name) {
            hex = fi.as_bool_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    // check json data, 'hex' is optional
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'socketHandle' not specified"));
    if (rpayload.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'data' not specified"));
    if (-1 == timeout) throw support::exception(TRACEMSG(
            "Required parameter 'timeoutMillis' not specified"));
    const std::string& payload = rpayload.get();
    // get handle
    auto reg = shared_socket_registry();
    wilton_Socket* socket = reg->remove(handle);
    if (nullptr == socket) throw support::exception(TRACEMSG(
            "Invalid 'socketHandle' parameter specified"));
    // convert hex and call wilton
    char* err = nullptr;
    if (hex) {
        auto src = sl::io::array_source(payload.data(), payload.size());
        auto sink = sl::io::string_sink();
        sl::io::copy_from_hex(src, sink);
        err = wilton_net_Socket_write(socket, sink.get_string().c_str(),
                static_cast<int>(sink.get_string().length()),
                static_cast<int>(timeout));
    } else {
        err = wilton_net_Socket_write(socket, payload.c_str(),
                static_cast<int>(payload.length()),
                static_cast<int>(timeout));
    }
    reg->put(socket);
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::make_empty_buffer();
}

support::buffer socket_read(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int64_t handle = -1;
    int64_t bytes_to_read = -1;
    int64_t timeout = -1;
    auto hex = false;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("socketHandle" == name) {
            handle = fi.as_int64_or_throw(name);
        } else if ("bytesToRead" == name) {
            bytes_to_read = fi.as_int64_or_throw(name);
        } else if ("timeoutMillis" == name) {
            timeout = fi.as_int64_or_throw(name);
        } else if ("hex" == name) {
            hex = fi.as_bool_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    // check json data, 'bytesToRead' and 'hex' are optional
    if (-1 == handle) throw support::exception(TRACEMSG(
            "Required parameter 'socketHandle' not specified"));
    if (-1 == timeout) throw support::exception(TRACEMSG(
            "Required parameter 'timeoutMillis' not specified"));
    // get handle
    auto reg = shared_socket_registry();
    wilton_Socket* socket = reg->remove(handle);
    if (nullptr == socket) throw support::exception(TRACEMSG(
            "Invalid 'socketHandle' parameter specified"));
    // call wilton
    char* out = nullptr;
    int out_len = 0;
    char* err = nullptr;
    if (-1 != bytes_to_read) {
        err = wilton_net_Socket_read(socket, static_cast<int>(bytes_to_read), static_cast<int> (timeout),
                std::addressof(out), std::addressof(out_len));
    } else {
        err = wilton_net_Socket_read_some(socket, static_cast<int> (timeout),
                std::addressof(out), std::addressof(out_len));
    }
    reg->put(socket);
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    if (0 == out_len)  {
        if (-1 == bytes_to_read) {
            return support::make_empty_buffer();
        }
        throw support::exception(TRACEMSG(
            "Invalid empty 'read' result"));
    }
    if (!hex) {
        return support::wrap_wilton_buffer(out, out_len);
    }
    auto src = sl::io::array_source(out, out_len);
    return support::make_hex_buffer(src);
}

support::buffer resolve_hostname(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rhostname = std::ref(sl::utils::empty_string());
    int64_t timeout = -1;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("hostname" == name) {
            rhostname = fi.as_string_nonempty_or_throw(name);
        } else if ("timeoutMillis" == name) {
            timeout = fi.as_int64_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rhostname.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'hostname' not specified"));
    if (-1 == timeout) throw support::exception(TRACEMSG(
            "Required parameter 'timeoutMillis' not specified"));
    const std::string& hostname = rhostname.get();
    // call wilton
    char* out = nullptr;
    int out_len = 0;
    auto err = wilton_net_resolve_hostname(hostname.c_str(), static_cast<int>(hostname.length()),
            static_cast<int>(timeout), std::addressof(out), std::addressof(out_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::wrap_wilton_buffer(out, out_len);
}

support::buffer wait_for_tcp_connection(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rip = std::ref(sl::utils::empty_string());
    int64_t port = -1;
    int64_t timeout = -1;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("ipAddress" == name) {
            rip = fi.as_string_nonempty_or_throw(name);
        } else if ("tcpPort" == name) {
            port = fi.as_int64_or_throw(name);
        } else if ("timeoutMillis" == name) {
            timeout = fi.as_int64_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rip.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'ipAddress' not specified"));
    if (-1 == port) throw support::exception(TRACEMSG(
            "Required parameter 'tcpPort' not specified"));
    if (-1 == timeout) throw support::exception(TRACEMSG(
            "Required parameter 'timeoutMillis' not specified"));
    const std::string& ip = rip.get();
    // call wilton
    char* err = wilton_net_wait_for_tcp_connection(ip.c_str(), static_cast<int>(ip.length()),
            static_cast<int> (port), static_cast<int> (timeout));
    if (nullptr != err) {
        support::throw_wilton_error(err, TRACEMSG(err));
    }
    return support::make_empty_buffer();
}


} // namespace
}

extern "C" char* wilton_module_init() {
    try {
        wilton::support::register_wiltoncall("net_socket_open",  wilton::net::socket_open);
        wilton::support::register_wiltoncall("net_socket_close", wilton::net::socket_close);
        wilton::support::register_wiltoncall("net_socket_write", wilton::net::socket_write);
        wilton::support::register_wiltoncall("net_socket_read",  wilton::net::socket_read);
        wilton::support::register_wiltoncall("net_wait_for_tcp_connection", wilton::net::wait_for_tcp_connection);
        wilton::support::register_wiltoncall("net_resolve_hostname", wilton::net::resolve_hostname);

        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

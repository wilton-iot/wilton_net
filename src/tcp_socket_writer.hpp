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
 * File:   tcp_socket_writer.hpp
 * Author: alex
 *
 * Created on February 20, 2018, 11:19 AM
 */

#ifndef WILTON_NET_TCP_SOCKET_WRITER_HPP
#define WILTON_NET_TCP_SOCKET_WRITER_HPP

#include <cstdint>
#include <string>

#include "asio.hpp"

#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

namespace wilton {
namespace net {

class tcp_socket_writer {
    // captured state
    asio::ip::tcp::socket& socket;
    asio::steady_timer& timer;
    bool& write_canceled;
    bool& timer_canceled;
    std::string& error;
    
    // write state
    sl::io::span<const char> data;
    size_t written_total;

public:
    tcp_socket_writer(asio::ip::tcp::socket& socket, asio::steady_timer& timer, 
            bool& write_canceled, bool& timer_canceled, std::string& error,
            sl::io::span<const char> data, size_t written_total) :
    socket(socket),
    timer(timer),
    write_canceled(write_canceled),
    timer_canceled(timer_canceled),
    error(error),
    data(data),
    written_total(written_total) { }

    tcp_socket_writer(const tcp_socket_writer& other) :
    socket(other.socket),
    timer(other.timer),
    write_canceled(other.write_canceled),
    timer_canceled(other.timer_canceled),
    error(other.error),
    data(other.data),
    written_total(other.written_total) { }

    tcp_socket_writer& operator=(const tcp_socket_writer& other) {
        // only write state may be changed
        data = other.data;
        written_total = other.written_total;
        return *this;
    }

    void operator()(const std::error_code& ec, size_t bytes_written) {
        if (write_canceled) return;
        if(ec) {
            error = "Write error, bytes total to write: [" + sl::support::to_string(data.size() + written_total) + "]" +
                    " bytes written: [" + sl::support::to_string(written_total) + "]," +
                    " message: [" + ec.message() + "]," +
                    " code: [" + sl::support::to_string(ec.value()) + "]";
            return;
        }
        auto to_write = data.size() - bytes_written;
        if (0 == to_write) {
            timer_canceled = true;
            timer.cancel();
            return;
        }
        auto data_pass = sl::io::make_span(data.data() + bytes_written, to_write);
        auto writer = tcp_socket_writer(socket, timer, write_canceled, timer_canceled,
                error, data_pass, written_total + bytes_written);
        socket.async_write_some(asio::buffer(data_pass.data(), data_pass.size()), writer);
    }
};

} // namespace
}


#endif /* WILTON_NET_TCP_SOCKET_WRITER_HPP */


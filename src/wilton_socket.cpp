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

void wilton_socket::impl::write(wilton_socket&, sl::io::span<const char> data, std::chrono::milliseconds timeout) {

    // prepare state
    service.reset();
    asio::steady_timer timer{service};
    auto write_canceled = false;
    auto timer_canceled = false;
    size_t written_total;
    auto error = std::string();

    // start timer
    timer.expires_from_now(timeout);

    // write callback
    std::function<void(const std::error_code&, size_t)> writer;
    writer = [&](const std::error_code& ec, size_t bytes_written) {
        if (write_canceled) return;
        if(ec) {
            error = "Write error, bytes total to write: [" + sl::support::to_string(data.size() + written_total) + "]" +
                    " bytes written: [" + sl::support::to_string(written_total) + "]," +
                    " message: [" + ec.message() + "]," +
                    " code: [" + sl::support::to_string(ec.value()) + "]";
            timer_canceled = true;
            timer.cancel();
            return;
        }
        auto to_write = data.size() - bytes_written;
        if (0 == to_write) {
            timer_canceled = true;
            timer.cancel();
            return;
        }
        auto data_pass = sl::io::make_span(data.data() + bytes_written, to_write);
        this->async_write_some(data_pass, writer);
    };
    this->async_write_some(data, writer);

    // timeout callback
    timer.async_wait([&](const std::error_code&) {
        if (timer_canceled) return;
        write_canceled = true;
        this->cancel();
        error = "Operation timed out, timeout millis: [" + sl::support::to_string(timeout.count()) + "]";
    });

    // perform connection, callbacks will be called only from the current thread
    service.run();

    // check results
    if (!error.empty()) throw support::exception(TRACEMSG(error));
}

sl::io::span<const char> wilton_socket::impl::read_some(wilton_socket&, uint32_t max_bytes_to_read,
        std::chrono::milliseconds timeout) {

    // prepare state
    read_buffer.resize(0);
    service.reset();
    asio::steady_timer timer{service};
    auto read_canceled = false;
    auto timer_canceled = false;
    auto error = std::string();

    // start timer
    timer.expires_from_now(timeout);

    // read callback, see: http://think-async.com/Asio/asio-1.10.6/doc/asio/overview/core/reactor.html
    this->async_read_some([&](const std::error_code& ec) {
        if (read_canceled) return;
        timer_canceled = true;
        timer.cancel();
        if(ec) {
            error = "Read error, IP: [" + ip_address + "]," +
                    " port: [" + sl::support::to_string(protocol_port) + "]," +
                    " message: [" + ec.message() + "]," +
                    " code: [" + sl::support::to_string(ec.value()) + "]";
            return;
        }
        auto avail = this->available();
        if (avail > 0) {
            auto to_read = avail < max_bytes_to_read ? avail : max_bytes_to_read;
            read_buffer.resize(to_read);
            auto dest = sl::io::make_span(read_buffer.data(), read_buffer.size());
            auto read = this->sync_read_some(dest);
            if (0 == read) throw support::exception(TRACEMSG(
                    "Invalid empty read, IP: [" + ip_address + "]," +
                    " port: [" + sl::support::to_string(protocol_port) + "]," +
                    " max bytes to read: [" + sl::support::to_string(max_bytes_to_read) + "]," +
                    " bytes available: [" + sl::support::to_string(avail) + "]"));
            if (read < to_read) {
                read_buffer.resize(read);
            }
        }
    });

    // timeout callback
    timer.async_wait([&](const std::error_code&) {
        if (timer_canceled) return;
        read_canceled = true;
        this->cancel();
        // empty response is returned on timeout
    });

    // perform connection, callbacks will be called only from the current thread
    service.run();

    // check results
    if (!error.empty()) throw support::exception(TRACEMSG(error));

    // return view to internal buffer
    if (read_buffer.size() > 0 ) {
        return sl::io::make_span(const_cast<const char*>(read_buffer.data()), read_buffer.size());
    } else {
        return sl::io::span<const char>(sl::utils::empty_string().c_str(), 0);
    }
}

void wilton_socket::impl::read(wilton_socket& facade, sl::io::span<char> buffer, std::chrono::milliseconds timeout) {
    uint64_t start = sl::utils::current_time_millis_steady();
    uint64_t finish = start + timeout.count();
    uint64_t cur = start;
    size_t read = 0;
    for (;;) {
        uint64_t passed = cur - start;
        auto tm = std::chrono::milliseconds(timeout.count() - passed);
        auto span = facade.read_some(static_cast<uint32_t>(buffer.size() - read), tm);
        if (span.size() > 0) {
            std::memcpy(buffer.data() + read, span.data(), span.size());
            read += span.size();
            if (read >= buffer.size()) {
                break;
            }
        }
        cur = sl::utils::current_time_millis_steady();
        if (cur >= finish) {
            break;
        }
    }
    if (read < buffer.size()) throw support::exception(TRACEMSG(
            "Short read from socket, bytes requested: [" + sl::support::to_string(buffer.size()) + "],"
            " bytes read: [" + sl::support::to_string(read) + "],"
            " timeout millis: [" + sl::support::to_string(timeout.count()) + "]"));
}
PIMPL_FORWARD_METHOD(wilton_socket, void, read, (sl::io::span<char>)(std::chrono::milliseconds), (), support::exception);
// forward pure virtual methods
PIMPL_FORWARD_METHOD(wilton_socket, void, write, (sl::io::span<const char>)(std::chrono::milliseconds), (), support::exception);
PIMPL_FORWARD_METHOD(wilton_socket, sl::io::span<const char>, read_some, (uint32_t)(std::chrono::milliseconds), (), support::exception);

} // namespace
}

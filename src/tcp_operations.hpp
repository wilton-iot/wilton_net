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
 * File:   tcp_connect_checker.hpp
 * Author: alex
 *
 * Created on October 18, 2016, 12:21 PM
 */

#ifndef WILTON_NET_TCP_OPERATIONS
#define WILTON_NET_TCP_OPERATIONS

#include <cstdint>
#include <chrono>
#include <string>
#include <vector>

#include "staticlib/pimpl.hpp"

#include "wilton/support/exception.hpp"

namespace wilton {
namespace net {

class tcp_operations : public sl::pimpl::object {
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
    PIMPL_CONSTRUCTOR(tcp_operations)

    static std::vector<std::string> resolve_hostname(const std::string& hostname,
            std::chrono::milliseconds timeout);

    static std::string wait_for_connection(const std::string& ip_addr, uint16_t tcp_port,
            std::chrono::milliseconds timeout);

};

} // namespace
}

#endif /* WILTON_NET_TCP_OPERATIONS */


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

#ifndef WILTON_MISC_TCP_CONNECT_CHECKER_HPP
#define WILTON_MISC_TCP_CONNECT_CHECKER_HPP

#include <cstdint>
#include <chrono>
#include <string>

#include "staticlib/pimpl.hpp"

#include "wilton/support/exception.hpp"

namespace wilton {
namespace net {

class tcp_connect_checker : public sl::pimpl::object {
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
    PIMPL_CONSTRUCTOR(tcp_connect_checker)

    static std::string wait_for_connection(std::chrono::milliseconds timeout, 
            const std::string& ip_addr, uint16_t tcp_port);

};

} // namespace
}

#endif /* WILTON_MISC_TCP_CONNECT_CHECKER_HPP */


/*
 * File:   socket_handler.h
 * Author: iskinmike
 *
 * Created on January 25, 2018, 12:21 PM
 */

#ifndef WILTON_MISC_TCP_SOCKET_HANDLER_H
#define WILTON_MISC_TCP_SOCKET_HANDLER_H

#include <cstdint>
#include <string>
#include <system_error>

#include "staticlib/pimpl.hpp"

#include "wilton/support/exception.hpp"

namespace wilton {
namespace net {

enum ip_protocol{
    TCP = 1, UDP =2
};

class socket_handler : public sl::pimpl::object
{
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
    PIMPL_CONSTRUCTOR(socket_handler)
    socket_handler(ip_protocol type);
    std::error_code open(std::string ip, uint16_t port);
    std::error_code close();
    std::error_code write(const char* buffer, const int& buffer_len);
    std::error_code read(char** out, int& out_len);
};

}

}


#endif // WILTON_MISC_TCP_SOCKET_HANDLER_H

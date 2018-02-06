/*
 * File:   socket_handler.h
 * Author: iskinmike
 *
 * Created on January 25, 2018, 12:21 PM
 */

#ifndef WILTON_MISC_TCP_SOCKET_HANDLER_H
#define WILTON_MISC_TCP_SOCKET_HANDLER_H

#include <cstdint>
#include <chrono>
#include <string>

#include "staticlib/pimpl.hpp"

#include "wilton/support/exception.hpp"

namespace wilton {
namespace net {

enum ip_protocol{
    IP_TCP = 1, IP_UDP =2
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
// //    void socket_create();
//     void socket_connect(std::string ip, uint16_t port);
//     std::string socket_read();
//     void socket_write(std::string data);
//     void socket_close();
    void open(std::string ip, uint16_t port);
    void close();
    std::string write(const char* buffer, const int& buffer_len);
    std::string read(char** out, int& out_len);
};

}

}


#endif // WILTON_MISC_TCP_SOCKET_HANDLER_H

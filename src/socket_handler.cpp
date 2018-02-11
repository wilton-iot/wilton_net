/*
 * File:   socket_handler.h
 * Author: iskinmike
 *
 * Created on January 25, 2018, 12:21 PM
 */


#include "socket_handler.h"

//#include <mutex>
//#include <atomic>
#include <thread>
#include <stdint.h>
#include <memory>
#include <iostream>

#include "asio.hpp"

#include "staticlib/config.hpp"
#include "staticlib/support.hpp"
#include "staticlib/pimpl/forward_macros.hpp"

#include "wilton/support/buffer.hpp"
#include "wilton/support/logging.hpp"

namespace wilton {
namespace net {

namespace {
    const int no_flag = 0;
}

class socket_handler::impl : public staticlib::pimpl::object::impl {
private:
    asio::io_service service{};
    asio::ip::tcp::socket tcp_socket;
    asio::ip::udp::socket udp_socket;
    ip_protocol current_type;
public:
    impl(ip_protocol type) :
    tcp_socket(service, asio::ip::tcp::v4()),
    udp_socket(service, asio::ip::udp::v4()),
    current_type(type) {
    }

    std::error_code open(socket_handler&, std::string ip, uint16_t port){
        asio::error_code ec;

        switch (current_type){
            case ip_protocol::TCP: {
                asio::ip::tcp::endpoint end_point(asio::ip::address_v4::from_string(ip), port);
                tcp_socket.connect(end_point, ec);
                break;
            }
            case ip_protocol::UDP:{
                asio::ip::udp::endpoint end_point(asio::ip::address_v4::from_string(ip), port);
                udp_socket.connect(end_point, ec);
                break;
            }
        }

        return ec;
    }
    std::error_code close(socket_handler&){
        asio::error_code ec;
        switch (current_type){
            case ip_protocol::TCP: {
                tcp_socket.close(ec);
                break;
            }
            case ip_protocol::UDP:{
                udp_socket.close(ec);
                break;
            }
        }
        return ec;
    }
    std::error_code write(socket_handler&, const char* buffer, const int& buffer_len){ // returns error message
        std::string error_message = "";
        asio::error_code ec;

        auto data = asio::buffer((buffer), buffer_len);
        switch (current_type){
            case ip_protocol::TCP: {
                tcp_socket.send(data, no_flag, ec);
                break;
            }
            case ip_protocol::UDP:{
                udp_socket.send(data, no_flag, ec);
                break;
            }
        }
        if (ec) {
            error_message.assign(ec.message());
            std::cout << error_message << std::endl;
        }

        return ec;
    }
    std::error_code read(socket_handler&, char** out, int& out_len){ // TODO: правильное получение данных
        asio::error_code ec;
        uint16_t recv_bytes = 0;

        auto data = asio::buffer(*out, out_len);
        switch (current_type){
            case ip_protocol::TCP: {
                recv_bytes = tcp_socket.receive(data, no_flag, ec);
                break;
            }
            case ip_protocol::UDP:{
                recv_bytes = udp_socket.receive(data, no_flag, ec);
                break;
            }
        }

        out_len = recv_bytes;
        return ec;
    }

};


PIMPL_FORWARD_CONSTRUCTOR(socket_handler, (ip_protocol), (), support::exception)
PIMPL_FORWARD_METHOD(socket_handler, std::error_code, open, (std::string)(uint16_t), (), support::exception);
PIMPL_FORWARD_METHOD(socket_handler, std::error_code, close, (), (), support::exception);
PIMPL_FORWARD_METHOD(socket_handler, std::error_code, write, (const char*)(const int&), (), support::exception);
PIMPL_FORWARD_METHOD(socket_handler, std::error_code, read, (char**) (int&), (), support::exception);


}
}

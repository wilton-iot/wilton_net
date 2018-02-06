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

    void open(socket_handler&, std::string ip, uint16_t port){
        asio::error_code ec;

        std::cout << "open socket" <<std::endl;

        switch (current_type){
        case ip_protocol::IP_TCP: {
            asio::ip::tcp::endpoint end_point(asio::ip::address_v4::from_string(ip), port);
            std::cout << "ecndpoint created" <<std::endl;
            tcp_socket.connect(end_point, ec);
            std::cout << "socket connect" <<std::endl;
            break;
        }
        case ip_protocol::IP_UDP:{
            asio::ip::udp::endpoint end_point(asio::ip::address_v4::from_string(ip), port);
            udp_socket.connect(end_point, ec);
            break;
        }
        }
        std::cout << "opened socket" <<std::endl;
        std::cout << "ec: [" << ec.message() << "]" <<std::endl;
    }
    void close(socket_handler&){
        switch (current_type){
        case ip_protocol::IP_TCP: {
            tcp_socket.close();
            break;
        }
        case ip_protocol::IP_UDP:{
            udp_socket.close();
            break;
        }
        }
    }
    std::string write(socket_handler&, const char* buffer, const int& buffer_len){ // returns error message
        std::string error_message = "";
        asio::error_code ec;

        auto data = asio::buffer((buffer), buffer_len);
        switch (current_type){
        case ip_protocol::IP_TCP: {
            tcp_socket.send(data, 0, ec);
            break;
        }
        case ip_protocol::IP_UDP:{
            udp_socket.send(data, 0, ec);
            break;
        }
        }
        if (ec) {
            error_message.assign(ec.message());
            std::cout << error_message << std::endl;
        }

        return error_message;
    }
    std::string read(socket_handler&, char** out, int& out_len){ // TODO: правильное получение данных
        std::string error_message = "";
        asio::error_code ec;
        std::cout << "max buffer length " << out_len <<std::endl;
        uint16_t recv_bytes = 0;

        auto data = asio::buffer(*out, out_len);

        switch (current_type){
        case ip_protocol::IP_TCP: {
            if (tcp_socket.is_open()) {
                std::cout << "read socket open" <<std::endl;
            }
            recv_bytes = tcp_socket.read_some(data, ec);
            break;
        }
        case ip_protocol::IP_UDP:{
            recv_bytes = udp_socket.receive(data, 0, ec);
            break;
        }
        }
        if (ec) {
            error_message.assign(ec.message());
            std::cout << "read socket " << error_message <<std::endl;
        }

        out_len = recv_bytes;

        return error_message;
    }

};


PIMPL_FORWARD_CONSTRUCTOR(socket_handler, (ip_protocol), (), support::exception)
PIMPL_FORWARD_METHOD(socket_handler, void, open, (std::string)(uint16_t), (), support::exception);
PIMPL_FORWARD_METHOD(socket_handler, void, close, (), (), support::exception);
PIMPL_FORWARD_METHOD(socket_handler, std::string, write, (const char*)(const int&), (), support::exception);
PIMPL_FORWARD_METHOD(socket_handler, std::string, read, (char**) (int&), (), support::exception);


}
}

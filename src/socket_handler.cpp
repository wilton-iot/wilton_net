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
//    asio::ip::tcp::endpoint endpoint;
//    asio::ip::tcp::socket socket;
//    std::unique_ptr<asio::ip::tcp::endpoint> endpoint_ptr;
//    std::unique_ptr<asio::ip::tcp::socket> socket_ptr;
//    std::mutex mutex{};

    asio::ip::tcp::socket tcp_socket;
    asio::ip::udp::socket udp_socket;
    ip_protocol current_type;
public:
    // service, asio::ip::tcp::v4()
    impl(ip_protocol type) :
    tcp_socket(service, asio::ip::tcp::v4()),
    udp_socket(service, asio::ip::udp::v4()),
    current_type(type) {
//        socket_ptr(
//                std::unique_ptr<asio::ip::tcp::socket> (
//                        new asio::ip::tcp::socket(service, asio::ip::tcp::v4())));
    }

//    void socket_create(std::string ip, std::uint16_t port){
//        socket = new asio::ip::tcp::socket(service, asio::ip::tcp::v4());
//    }

//    void socket_connect(std::string ip, uint16_t port){
//        std::string error_message = "";
//        // создадим соответствующий endpoint
//        endpoint_ptr(
//                std::unique_ptr<asio::ip::tcp::endpoint> (
//                         new asio::ip::tcp::endpoint (asio::ip::address_v4::from_string(ip), port)));
//        // биндим endpoint к сокету.
//        socket_ptr->bind(*endpoint_ptr);

//        // Теперь запускаем подключение к endpoint
//        // Наверное все же надо сделать ограничение на время подключения
//        // Чтобы не заблокировать насовсем. По аналогии с wilton::net::tcp_connect_checker::wait_for_connection
//        std::atomic_bool connect_cancelled{false};
//        socket.async_connect(*endpoint_ptr, [&](const std::error_code& ec) {
//            std::lock_guard<std::mutex> guard{mutex};
//            if (connect_cancelled.load(std::memory_order_acquire)) return;
//            timer_cancelled.store(true, std::memory_order_release);
//            timer.cancel();
//            if(ec) {
//                error_message = "ERROR: " + ec.message() + " (" + sl::support::to_string(ec.value()) + ")";
//            }
//        });
//        service.run_one(); // Ждет пока выполнится 1 handler.
//        return error_message;
//    }

    // Запустим чтение сокета
//    std::string socket_read(){
//        std::string error_message = "";

//        socket.async_receive(*endpoint_ptr, [&](const std::error_code& ec) {
//            std::lock_guard<std::mutex> guard{mutex};
//            if(ec) {
//                error_message = "ERROR: " + ec.message() + " (" + sl::support::to_string(ec.value()) + ")";
//            }
//        });


//        service.run_one();
//        return error_message;
//    }

//    std::string socket_write(std::string data){
//        td::string error_message = "";

//        socket.async_send(asio::buffer(data), [&](const std::error_code& ec) {
//            std::lock_guard<std::mutex> guard{mutex};
//            if(ec) {
//                error_message = "ERROR: " + ec.message() + " (" + sl::support::to_string(ec.value()) + ")";
//            }
//        });


//        service.run_one();
//        return error_message;
//    }

//    void socket_close(){
//        socket.close();
//    }


    void open(socket_handler&, std::string ip, uint16_t port){
        // В конструкторе создали сокет.
        // Здесь создадим endpoint и подключение.
        switch (current_type){
        case ip_protocol::IP_TCP: {
            asio::ip::tcp::endpoint end_point(asio::ip::address_v4::from_string(ip), port);
            tcp_socket.connect(end_point);
            break;
        }
        case ip_protocol::IP_UDP:{
            asio::ip::udp::endpoint end_point(asio::ip::address_v4::from_string(ip), port);
            udp_socket.connect(end_point);
            break;
        }
        service.run_one();
        }
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

        auto data = asio::buffer((buffer), buffer_len);
        switch (current_type){
        case ip_protocol::IP_TCP: {
            tcp_socket.send(data/*, error_handler*/);
            break;
        }
        case ip_protocol::IP_UDP:{
            udp_socket.send(data/*, error_handler*/);
            break;
        }
        }

        service.run_one();
        return error_message;
    }
    std::string read(socket_handler&, char* out, int& out_len){ // TODO: правильное получение данных
        std::string error_message = "";
        asio::error_code ec;

        auto data = asio::buffer(out, out_len); // видимо этого достаточно чтобы получить данные в буффер.
        uint16_t recv_bytes = 0;

        switch (current_type){
        case ip_protocol::IP_TCP: {
            recv_bytes = tcp_socket.receive(data, 0, ec);
            break;
        }
        case ip_protocol::IP_UDP:{
            recv_bytes = udp_socket.receive(data, 0, ec);
            break;
        }
        }
        if (ec) {
//            wilton::support::log_error(LOGGER, "Socket read error, ec: [" + sl::support::to_string(ec.value()) +
//                    "], [" + ec.message() + "] ...");
            error_message.assign(ec.message());
        }

        out_len = recv_bytes;

        service.run_one();
        return error_message;
    }

};
//socket_handler::socket_handler()
//{

//}

PIMPL_FORWARD_CONSTRUCTOR(socket_handler, (ip_protocol), (), support::exception)
PIMPL_FORWARD_METHOD(socket_handler, void, open, (std::string)(uint16_t), (), support::exception);
PIMPL_FORWARD_METHOD(socket_handler, void, close, (), (), support::exception);
PIMPL_FORWARD_METHOD(socket_handler, std::string, write, (const char*)(const int&), (), support::exception);
PIMPL_FORWARD_METHOD(socket_handler, std::string, read, (char*) (int&), (), support::exception);


}
}

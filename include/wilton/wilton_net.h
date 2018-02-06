/* 
 * File:   wilton_net.h
 * Author: alex
 *
 * Created on October 17, 2017, 8:57 PM
 */

#ifndef WILTON_NET_H
#define WILTON_NET_H

#include "wilton/wilton.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wilton_socket_handler;
typedef struct wilton_socket_handler wilton_socket_handler;

char* wilton_net_wait_for_tcp_connection(
        const char* ip_addr,
        int ip_addr_len,
        int tcp_port,
        int timeout_millis);

char* wilton_net_socket_open(
        wilton_socket_handler** handler,
        const char* ip_addr,
        int ip_addr_len,
        int tcp_port);

char* wilton_net_socket_close(
        wilton_socket_handler* handler);

char* wilton_net_socket_write(
        wilton_socket_handler* handler,
        const char* data,
        int data_len);

char* wilton_net_socket_read(wilton_socket_handler* handler,
        char **out_data,
        int& data_len);

#ifdef __cplusplus
}
#endif

#endif /* WILTON_NET_H */


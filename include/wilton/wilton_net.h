/*
 * Copyright 2017, alex at staticlibs.net
 * Copyright 2018, myasnikov.mike at gmail.com
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

// sockets

struct wilton_Socket;
typedef struct wilton_Socket wilton_Socket;

char* wilton_net_Socket_open(
        wilton_Socket** socket_out,
        const char* ip_addr,
        int ip_addr_len,
        int tcp_port,
        const char* protocol,
        int protocol_len,
        const char* role,
        int role_len,
        int timeout_millis);

char* wilton_net_Socket_close(
        wilton_Socket* socket);

char* wilton_net_Socket_write(
        wilton_Socket* socket,
        const char* data,
        int data_len,
        int timeout_millis);

char* wilton_net_Socket_read_some(
        wilton_Socket* socket,
        int timeout_millis,
        char** data_out,
        int* data_len_out);

char* wilton_net_Socket_read(
        wilton_Socket* socket,
        int bytes_to_read,
        int timeout_millis,
        char** data_out,
        int* data_len_out);


// other operations

char* wilton_net_resolve_hostname(
        const char* hostname,
        int hostname_len,
        int timeout_millis,
        char** ip_addr_out,
        int* ip_addr_len_out);

char* wilton_net_wait_for_tcp_connection(
        const char* ip_addr,
        int ip_addr_len,
        int tcp_port,
        int timeout_millis);



#ifdef __cplusplus
}
#endif

#endif /* WILTON_NET_H */

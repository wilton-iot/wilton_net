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

char* wilton_net_wait_for_tcp_connection(
        const char* ip_addr,
        int ip_addr_len,
        int tcp_port,
        int timeout_millis);

#ifdef __cplusplus
}
#endif

#endif /* WILTON_NET_H */


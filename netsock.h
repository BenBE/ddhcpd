#ifndef _NETSOCK_H
#define _NETSOCK_H

#include "types.h"

#define DDHCP_MULTICAST_PORT 1234
#define DDHCP_UNICAST_PORT 1235

const struct in6_addr in6addr_localmast;

int control_open(ddhcp_config* state);
int control_connect(ddhcp_config* state);
int netsock_open(char* interface, char* interface_client, ddhcp_config* state);

#endif

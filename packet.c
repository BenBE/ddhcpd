#include "packet.h"

#include <endian.h>
#include <assert.h>
#include <errno.h>

#define copy_buf_to_var_inc(buf, type, var)             \
  do {                                                  \
    type* tmp = &(var);                                 \
    memcpy(tmp, (buf), sizeof(type));                   \
    buf = (typeof (buf))((char*)(buf) + sizeof(type));  \
  } while(0);

#define copy_var_to_buf_inc(buf, type, var)             \
  do {                                                  \
    type* tmp = &(var);                                 \
    memcpy((buf), tmp, sizeof(type));                   \
    buf = (typeof (buf))((char*)(buf) + sizeof(type));  \
  } while(0);

int _packet_size(int command, int payload_count) {
  int len = 0;

  switch (command) {
  case 1:
    len = 16 + payload_count * 7;
    break;

  case 2:
    len = 16 + payload_count * 4;
    break;

  default:
    printf("Error: unknown command: %i/%i \n", command, payload_count);
    return -1;
    break;
  }

  return len;
}

int ntoh_mcast_packet(uint8_t* buffer, int len, struct ddhcp_mcast_packet* packet) {

  // Header
  copy_buf_to_var_inc(buffer, ddhcp_node_id, packet->node_id);

  // The Python implementation prefixes with a node number?
  // prefix address
  copy_buf_to_var_inc(buffer, struct in_addr, packet->prefix);

  // prefix length
  copy_buf_to_var_inc(buffer, uint8_t, packet->prefix_len);
  // size of a block
  copy_buf_to_var_inc(buffer, uint8_t, packet->blocksize);
  // the command
  copy_buf_to_var_inc(buffer, uint8_t, packet->command);
  // count of payload entries
  copy_buf_to_var_inc(buffer, uint8_t, packet->count);

  int should_len = _packet_size(packet->command, packet->count);

  if (should_len != len) {
    printf("Wrong length: %i/%i", len, should_len);
    return 1;
  }

  char str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(packet->prefix), str, INET_ADDRSTRLEN);
  printf("NODE: %lu PREFIX: %s/%i BLOCKSIZE: %i COMMAND: %i ALLOCATIONS: %i\n",
         (long unsigned int) packet->node_id,
         str,
         packet->prefix_len,
         packet->blocksize,
         packet->command,
         packet->count
        );

  // Payload
  uint8_t  tmp8;
  uint16_t tmp16;
  uint32_t tmp32;
  struct ddhcp_payload* payload;

  switch (packet->command) {
  // UpdateClaim
  case 1:
    packet->payload = (struct ddhcp_payload*) calloc(sizeof(struct ddhcp_payload), packet->count);
    payload = packet->payload;

    for (int i = 0; i < packet->count; i++) {
      copy_buf_to_var_inc(buffer, uint32_t, tmp32);
      payload->block_index = ntohl(tmp32);

      copy_buf_to_var_inc(buffer, uint16_t, tmp16);
      payload->timeout = ntohs(tmp16);

      copy_buf_to_var_inc(buffer, uint8_t, tmp8);
      payload->reserved = tmp8;

      payload++;
    }

    break;

  // InquireBlock
  case 2:
    packet->payload = (struct ddhcp_payload*) calloc(sizeof(struct ddhcp_payload), packet->count);
    payload = packet->payload;

    for (int i = 0; i < packet->count; i++) {
      copy_buf_to_var_inc(buffer, uint32_t, tmp32);
      payload->block_index = ntohl(tmp32);

      payload++;
    }

    break;

  // ReNEWLease
  case 16:
    packet->payload = (struct ddhcp_payload*) calloc(sizeof(struct ddhcp_payload), packet->count);

  default:
    return 2;
    break;
  }

  printf("\n");

  return 0;
}

int send_packet_mcast(struct ddhcp_mcast_packet* packet, int mulitcast_socket, uint32_t scope_id) {
  int len = _packet_size(packet->command, packet->count);

  char* buffer = (char*) calloc(1, len);

  errno = 0;

  // Header
  copy_var_to_buf_inc(buffer, ddhcp_node_id, packet->node_id);

  // The Python implementation prefixes with a node number?
  // prefix address
  copy_var_to_buf_inc(buffer, struct in_addr, packet->prefix);

  // prefix length
  copy_var_to_buf_inc(buffer, uint8_t, packet->prefix_len);
  // size of a block
  copy_var_to_buf_inc(buffer, uint8_t, packet->blocksize);
  // the command
  copy_var_to_buf_inc(buffer, uint8_t, packet->command);
  // count of payload entries
  copy_var_to_buf_inc(buffer, uint8_t, packet->count);

  uint8_t tmp8;
  uint16_t tmp16;
  uint32_t tmp32;
  struct ddhcp_payload* payload;

  switch (packet->command) {
  case 1:
    payload = packet->payload;

    for (unsigned int index = 0; index < packet->count; index++) {
      tmp32 = htonl(payload->block_index);
      copy_var_to_buf_inc(buffer, uint32_t, tmp32);

      tmp16 = htons(payload->timeout);
      copy_var_to_buf_inc(buffer, uint16_t, tmp16);

      tmp8 = payload->reserved;
      copy_var_to_buf_inc(buffer, uint8_t, tmp8);

      payload++;
    }

    break;

  case 2:
    payload = packet->payload;

    for (unsigned int index = 0; index < packet->count; index++) {
      tmp32 = htonl(payload->block_index);
      copy_var_to_buf_inc(buffer, uint32_t, tmp32);

      payload++;
    }

    break;
  }

  struct sockaddr_in6 dest_addr = {
    .sin6_family = AF_INET6,
    .sin6_port = htons(1234),
    .sin6_scope_id = scope_id
  };

  const struct in6_addr dest =
  {
    {
      {
        0xff, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x12, 0x34
      }
    }
  };

  memcpy(&dest_addr.sin6_addr, &dest, sizeof(dest));

  sendto(mulitcast_socket, buffer, len, 0, (struct sockaddr*) &dest_addr, sizeof(dest_addr));

  free(buffer);

  return 0;
}

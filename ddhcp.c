#include <arpa/inet.h>
#include <assert.h>
#include <getopt.h>
#include <math.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "block.h"
#include "ddhcp.h"
#include "dhcp.h"
#include "dhcp_packet.h"
#include "logger.h"
#include "netsock.h"
#include "packet.h"
#include "tools.h"
#include "dhcp_options.h"

const int NET = 0;
const int NET_LEN = 10;

struct ddhcp_block* blocks;

int ddhcp_block_init(struct ddhcp_block **blocks, ddhcp_config *config) {
  DEBUG("ddhcp_block_init( blocks, config)\n");
  *blocks = (struct ddhcp_block*) malloc( sizeof(struct ddhcp_block) * config->number_of_blocks);

  if ( *blocks == 0 ) {
    FATAL("ddhcp_block_init(...)-> Can't allocate memory for block structure\n");
    return 1;
  }

  int now = time(NULL);

  // TODO Maybe we should allocate number_of_blocks dhcp_lease_blocks previous
  //      and assign one here instead of NULL. Performance boost, Memory defrag?
  struct ddhcp_block *block = (*blocks);

  for ( uint32_t index = 0; index < config->number_of_blocks; index++ ) {
    block->index = index;
    block->state = DDHCP_FREE;
    addr_add(&config->prefix,&block->subnet,index * config->block_size);
    block->subnet_len = config->block_size;
    block->address = 0;
    block->timeout = now + config->block_timeout;
    block->claiming_counts = 0;
    block->addresses = NULL;
    block++;
  }

  return 0;
}

void ddhcp_block_process_claims( struct ddhcp_block *blocks , struct ddhcp_mcast_packet *packet ,ddhcp_config *config) {
  DEBUG("ddhcp_block_process_claims( blocks, packet, config )\n");
  assert(packet->command == 1);
  time_t now = time(NULL);

  for ( unsigned int i = 0 ; i < packet->count ; i++ ) {
    struct ddhcp_payload *claim = ((struct ddhcp_payload*) packet->payload)+i;
    uint32_t block_index = claim->block_index;

    if ( block_index >= config->number_of_blocks ) {
      WARNING("ddhcp_block_process_claims(...): Malformed block number\n");
    }

    if ( blocks[block_index].state == DDHCP_OURS ) {
      INFO("ddhcp_block_process_claims(...): node %lu claims our block %i\n", packet->node_id, block_index);
      // TODO Decide when and if we reclaim this block
      //      Which node has more leases in this block, ... , how has the better node_id.
    } else {
      blocks[block_index].state = DDHCP_CLAIMED;
      blocks[block_index].timeout = now + claim->timeout;
      INFO("ddhcp_block_process_claims(...): node %lu claims block %i with ttl: %i\n",packet->node_id,block_index,claim->timeout);
    }
  }
}

void ddhcp_block_process_inquire( struct ddhcp_block *blocks , struct ddhcp_mcast_packet *packet ,ddhcp_config *config) {
  DEBUG("ddhcp_block_process_inquire( blocks, packet, config )\n");
  assert(packet->command == 2);
  time_t now = time(NULL);

  for ( unsigned int i = 0 ; i < packet->count ; i++ ) {
    struct ddhcp_payload *tmp = ((struct ddhcp_payload*) packet->payload)+i;

    if ( tmp->block_index >= config->number_of_blocks ) {
      WARNING("ddhcp_block_process_inquire(...): Malformed block number\n");
      continue;
    }

    INFO("ddhcp_block_process_inquire(...): node %lu inquires block %i\n",packet->node_id,tmp->block_index);

    if ( blocks[tmp->block_index].state == DDHCP_OURS ) {
      // Update Claims
      INFO("ddhcp_block_process_inquire(...): block %i is ours notify network", tmp->block_index);
      blocks[tmp->block_index].timeout = 0;
      block_update_claims( blocks, 0, config );
    } else if ( blocks[tmp->block_index].state == DDHCP_CLAIMING ) {
      INFO("ddhcp_block_process_inquire(...): we are interested in block %i also\n",tmp->block_index);

      // QUESTION Why do we need multiple states for the same process?
      if ( packet->node_id > config->node_id ) {
        INFO("ddhcp_block_process_inquire(...): .. but other node wins.\n");
        blocks[tmp->block_index].state = DDHCP_TENTATIVE;
        blocks[tmp->block_index].timeout = now + config->tentative_timeout;
      }

      // otherwise keep inquiring, the other node should see our inquires and step back.
    } else {
      INFO("ddhcp_block_process_inquire(...): set block %i to tentative \n",tmp->block_index);
      blocks[tmp->block_index].state = DDHCP_TENTATIVE;
      blocks[tmp->block_index].timeout = now + config->tentative_timeout;
    }
  }
}

/**
 * House Keeping
 *
 * - Free timed-out DHCP leases.
 * - Refresh timed-out blocks.
 * + Claim new blocks if we are low on spare leases.
 * + Update our claims.
 */
void house_keeping( ddhcp_block *blocks, ddhcp_config *config ) {
  DEBUG("house_keeping( blocks, config )\n");
  block_check_timeouts( blocks, config );
  int spares = block_num_free_leases( blocks, config );
  int spare_blocks = ceil( (double) spares / (double) config->block_size );
  int blocks_needed = config->spare_blocks_needed - spare_blocks;
  block_claim( blocks, blocks_needed, config );
  block_update_claims( blocks, blocks_needed, config );
}

/**
 * Initialize DHCP options
 */
void init_dhcp_options( ddhcp_config *config ) {
  dhcp_option* option;
  // subnet mask
  option = (dhcp_option*) calloc(sizeof(dhcp_option),1);
  option->code = DHCP_CODE_SUBNET_MASK;
  option->len = 4;
  option->payload = (uint8_t*)  malloc(sizeof(uint8_t) * 4 );
  // TODO Check interface for address
  option->payload[0] = 255;
  option->payload[1] = 255;
  option->payload[2] = 255;
  option->payload[3] = 0;

  set_option_in_store( &config->options, option );

  option = (dhcp_option*) malloc(sizeof(dhcp_option));
  option->code = DHCP_CODE_TIME_OFFSET;
  option->len = 4;
  option->payload = (uint8_t*)  malloc(sizeof(uint8_t) * 4 );
  option->payload[0] = 0;
  option->payload[1] = 0;
  option->payload[2] = 0;
  option->payload[3] = 0;

  set_option_in_store( &config->options, option );

  option = (dhcp_option*) malloc(sizeof(dhcp_option));
  option->code = DHCP_CODE_ROUTER;
  option->len = 4;
  option->payload = (uint8_t*)  malloc(sizeof(uint8_t) * 4 );
  // TODO Configure this throught socket
  option->payload[0] = 10;
  option->payload[1] = 0;
  option->payload[2] = 0;
  option->payload[3] = 1;

  set_option_in_store( &config->options, option );

  option = (dhcp_option*) malloc(sizeof(dhcp_option));
  option->code = DHCP_CODE_BROADCAST_ADDRESS;
  option->len = 4;
  option->payload = (uint8_t*)  malloc(sizeof(uint8_t) * 4 );
  // TODO Check interface for address
  option->payload[0] = 10;
  option->payload[1] = 0;
  option->payload[2] = 0;
  option->payload[3] = 255;

  set_option_in_store( &config->options, option );

  option = (dhcp_option*) malloc(sizeof(dhcp_option));
  option->code = DHCP_CODE_SERVER_IDENTIFIER;
  option->len = 4;
  option->payload = (uint8_t*)  malloc(sizeof(uint8_t) * 4 );
  // TODO Check interface for address
  option->payload[0] = 10;
  option->payload[1] = 0;
  option->payload[2] = 0;
  option->payload[3] = 1;

  set_option_in_store( &config->options, option );
}

void add_fd(int efd, int fd, uint32_t events) {
  struct epoll_event event = { 0 };
  event.data.fd = fd;
  event.events = events;

  int s = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);

  if (s == -1) {
    exit(1);  //("epoll_ctl");
  }
}

int main(int argc, char **argv) {

  srand(time(NULL));

  ddhcp_config *config = (ddhcp_config*) malloc( sizeof(ddhcp_config) );
  config->node_id = 0xffffffffffffffff;
  config->block_size = 32;
  config->spare_blocks_needed = 1;
  config->claiming_blocks_amount = 0;

  inet_aton("10.116.128.0",&config->prefix);
  config->prefix_len = 18;
  config->number_of_blocks = pow(2, (32 - config->prefix_len - ceil(log2(config->block_size))));
  config->spare_blocks_needed = 1;
  config->block_timeout = 30;
  config->tentative_timeout = 15;

  // DHCP
  config->dhcp_port = 67;
  INIT_LIST_HEAD(&(config->options).list);

  INIT_LIST_HEAD(&(config->claiming_blocks).list);

  char* interface = "server0";
  char* interface_client = "client0";

  int c;
  int show_usage = 0;

  while (( c = getopt(argc,argv,"c:i:t:h")) != -1 ) {
    switch(c) {
    case 'i':
      interface = optarg;
      break;

    case 'c':
      interface_client = optarg;
      break;

    case 't':
      config->tentative_timeout = atoi(optarg);
      break;

    case 'h':
      show_usage = 1;
      break;

    default:
      printf("ARGC: %i\n",argc);
      show_usage = 1;
      break;
    }
  }

  if(show_usage) {
      printf("Usage: ddhcp [-h] [-c CLT-IFACE] [-i SRV-IFACE] [-t TENTATIVE-TIMEOUT]\n");
      printf("\n");
      printf("-h              This usage information.\n");
      printf("-c CLT-IFACE    Interface on which requests from clients are handled\n");
      printf("-i SRV-IFACE    Interface on which different servers communicate\n");
      printf("-t TENTATIVE    Time required for a block to be claimed\n");
      exit (0);
  }

  INFO("CONFIG: network=%s/%i\n", inet_ntoa(config->prefix),config->prefix_len);
  INFO("CONFIG: block_size=%i\n", config->block_size);
  INFO("CONFIG: #blocks=%i\n", config->number_of_blocks);
  INFO("CONFIG: #spare_blocks=%i\n", config->spare_blocks_needed);
  INFO("CONFIG: timeout=%i\n", config->block_timeout);
  INFO("CONFIG: tentative_timeout=%i\n", config->tentative_timeout);
  INFO("CONFIG: client_interface=%s\n",interface_client);
  INFO("CONFIG: group_interface=%s\n",interface);

  // init block stucture
  ddhcp_block_init(&blocks,config);
  init_dhcp_options( config );

  // init network and event loops
  // TODO
  if ( netsock_open(interface,interface_client,config) == -1 ) {
    return 1;
  }

  uint8_t* buffer = (uint8_t*) malloc( sizeof(uint8_t) * 1500 );
  struct ddhcp_mcast_packet packet;
  struct dhcp_packet dhcp_packet;
  int ret = 0, bytes = 0;

  int efd;
  int maxevents = 64;
  struct epoll_event *events;

  efd = epoll_create1(0);

  if (efd == -1) {
    perror("epoll_create");
    abort();
  }

  add_fd(efd, config->mcast_socket, EPOLLIN | EPOLLET);
  add_fd(efd, config->client_socket, EPOLLIN | EPOLLET);

  /* Buffer where events are returned */
  events = calloc(maxevents, sizeof(struct epoll_event));

  uint8_t need_house_keeping;
  uint32_t loop_timeout = floor( config->tentative_timeout / 2 * 1000 );
  INFO("loop timeout: %i msecs\n", loop_timeout);

  // TODO wait loop_timeout before first time housekeeping
  while(1) {
    int n;
    n = epoll_wait(efd, events, maxevents, loop_timeout );
    need_house_keeping = 1;

    for( int i = 0; i < n; i++ ) {
      if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
        fprintf(stderr, "epoll error\n");
        close(events[i].data.fd);
      } else if (config->mcast_socket == events[i].data.fd) {
        bytes = read(config->mcast_socket, buffer, 1500);
        // TODO Error Handling
        ret = ntoh_mcast_packet(buffer,bytes, &packet);

        if ( ret == 0 ) {
          switch(packet.command) {
          case DHCPDISCOVER:
            ddhcp_block_process_claims(blocks,&packet,config);
            break;

          case 2:
            ddhcp_block_process_inquire(blocks,&packet,config);

          default:
            break;
          }

          free(packet.payload);
        } else {
          printf("%i\n",ret);
        }

        house_keeping( blocks, config );
        need_house_keeping = 0;
      } else if ( config->client_socket == events[i].data.fd) {
        bytes = read(config->client_socket,buffer, 1500);

        // TODO Error Handling
        ret = ntoh_dhcp_packet(&dhcp_packet,buffer,bytes);

        if ( ret == 0 ) {
          int message_type = dhcp_packet_message_type(&dhcp_packet);

          switch( message_type ) {
          case DHCPDISCOVER:
            ret = dhcp_discover( config->client_socket, &dhcp_packet, blocks, config);

            if ( ret == 1 ) {
              INFO("we need to inquire new blocks\n");
              need_house_keeping = 1;
            }

            break;

          case DHCPREQUEST:
            dhcp_request( config->client_socket, &dhcp_packet, blocks, config);
            break;

          default:
            WARNING("Unknown DHCP message of type: %i\n",message_type);
            break;
          }

          if( dhcp_packet.options_len > 0 ) {
            free(dhcp_packet.options);
          }
        }
      }
    }

    if( need_house_keeping ) {
      house_keeping( blocks, config );
    }
  }

  // TODO free dhcp_leases
  free(events);
  ddhcp_block *block = blocks;

  for ( uint32_t i = 0; i < config->number_of_blocks; i++ ) {
    block_free(block++);
  }

  free(blocks);
  free(buffer);
  free(config);
  return 0;
}

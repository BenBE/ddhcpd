#ifndef _BLOCK_H
#define _BLOCK_H

#include "types.h"
#include "packet.h"

/**
 * Allocate block.
 * This will also malloc and prepare a dhcp_lease_block inside the given block.
 */
int block_alloc(ddhcp_block* block);

/**
 * Own a block, possibly after you have claimed it an amount of times.
 * This will also malloc and prepare a dhcp_lease_block inside the given block.
 */
int block_own(ddhcp_block* block, ddhcp_config* config);

/**
 * Free a block and release dhcp_lease_block when allocated.
 */
void block_free(ddhcp_block* block);

/**
 * Find a free block and return it or otherwise NULL.
 * A block is called free, when no other node claims it.
 */
ddhcp_block* block_find_free(ddhcp_config* config);

/**
 * Claim a block! A block is only claimable when it is free.
 * Returns a value greater 0 if something goes sideways.
 */
int block_claim(int32_t num_blocks, ddhcp_config* config);

/**
 * Sum the number of free leases in blocks you own.
 */
uint32_t block_num_free_leases(ddhcp_config* config);

/**
 * Find and return claimed block with free leases. Try to
 * reduce fragmentation of lease usage by returning already
 * used blocks.
 */
ddhcp_block* block_find_free_leases(ddhcp_config* config);

/**
 *  Update the timeout of claimed blocks and send packets to
 *  distribute the continuations of that claim.
 *
 *  Due to fragmented timeouts this packet may send 2 times more packets
 *  than optimal. TODO fixthis
 */
void block_update_claims(int32_t blocks_needed, ddhcp_config* config);

/**
 * Check the timeout of all blocks, and mark timed out once as FREE.
 * Blocks which are marked as BLOCKED are ignored in this process.
 */
void block_check_timeouts(ddhcp_config* config);

/**
 * Free block claim list structure.
 */
#define block_free_claims(config) \
  INIT_LIST_HEAD(&(config)->claiming_blocks);

/**
 * Show Block Status
 */
void block_show_status(int fd, ddhcp_config* config);

#endif

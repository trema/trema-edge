/*
 * Copyright (C) 2012-2013 NEC Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#ifndef ETHER_DEVICE_H
#define ETHER_DEVICE_H


#include <net/if.h>
#include <stdint.h>
#if WITH_PCAP
#include <pcap.h>
#endif
#include "ofdp_common.h"
#include "packet_buffer.h"


typedef void ( *frame_received_handler )( buffer *frame, void *user_data );

typedef struct {
  char name[ IFNAMSIZ ];
  int ifindex;
  uint8_t hw_addr[ ETH_ADDRLEN ];
  struct timespec created_at;
  short int original_flags;
  struct {
    bool up;
    bool can_retrieve_link_status;
    bool can_retrieve_pause;
    uint32_t curr;
    uint32_t advertised;
    uint32_t supported;
    uint32_t peer;
    uint32_t curr_speed;
    uint32_t max_speed;
  } status;
  struct {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
    uint64_t rx_errors;
    uint64_t tx_errors;
    uint64_t rx_frame_err;
    uint64_t rx_over_err;
    uint64_t rx_crc_err;
    uint64_t collisions;
  } stats;
#if WITH_PCAP
  pcap_t *pcap;
#endif
  int fd;
  packet_buffers *send_queue;
  packet_buffers *recv_queue;
  size_t mtu;
  buffer *recv_buffer;
  frame_received_handler received_callback;
  void *received_user_data;
} ether_device;


ether_device *create_ether_device( const char *name, const size_t max_send_queue, const size_t max_recv_queue );
void delete_ether_device( ether_device *device );
bool up_ether_device( ether_device *devive );
bool down_ether_device( ether_device *device );
bool send_frame( ether_device *device, buffer *frame );
bool set_frame_received_handler( ether_device *device, frame_received_handler callback, void *user_data );
bool update_device_status( ether_device *device );
bool update_device_stats( ether_device *device );
short int get_device_flags( const char *name );
bool set_device_flags( const char *name, short int flags );
struct timespec get_device_uptime( ether_device *device );


#endif // ETHER_DEVICE_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

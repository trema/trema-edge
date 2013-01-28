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


#ifndef ASYNC_EVENT_NOTIFIER_H
#define ASYNC_EVENT_NOTIFIER_H


#include "ofdp_common.h"
#include "flow_entry.h"
#include "match.h"
#include "port_manager.h"
#include "switch_port.h"


typedef enum {
  ASYNC_EVENT_TYPE_PACKET_IN,
  ASYNC_EVENT_TYPE_FLOW_REMOVED,
  ASYNC_EVENT_TYPE_PORT_STATUS,
} async_event_type;


typedef struct {
  uint8_t reason;
  port_description desc;
} port_status_event;

typedef struct {
  uint32_t buffer_id;
  uint8_t reason;
  uint8_t table_id;
  uint64_t cookie;
  match match;
  uint16_t total_len;
  uint16_t max_len;
  buffer *packet;
} packet_in_event;

typedef struct {
  uint64_t cookie;
  uint16_t priority;
  uint8_t reason;
  uint8_t table_id;
  uint32_t duration_sec;
  uint32_t duration_nsec;
  uint16_t idle_timeout;
  uint16_t hard_timeout;
  uint64_t packet_count;
  uint64_t byte_count;
  match match;
} flow_removed_event;

typedef void ( *async_event_handler )( void *data, void *user_data );


OFDPE init_async_event_notifier( const unsigned int n_packet_buffers );
OFDPE finalize_async_event_notifier( void );
void notify_port_status( const switch_port *port, const uint8_t reason );
void notify_packet_in( const uint8_t reason, const uint8_t table_id, const uint64_t cookie, const match *match,
                       buffer *packet, const uint16_t max_len );
void notify_flow_removed( const uint8_t reason, const flow_entry *entry );
OFDPE set_async_event_handler( async_event_type type, async_event_handler handler, void *user_data );
buffer *get_packet_from_packet_in_buffer( const uint32_t buffer_id );


#endif // ASYNC_EVENT_NOTIFIER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/

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


#include "async_event_notifier.h"
#include "flow_table.h"
#include "meter_executor.h"
#include "mutex.h"
#include "openflow_helper.h"


typedef struct {
  async_event_handler packet_in;
  void *packet_in_user_data;
  async_event_handler flow_removed;
  void *flow_removed_user_data;
  async_event_handler port_status;
  void *port_status_user_data;
} event_handlers;

typedef struct {
  buffer *packet;
  struct timespec saved_at;
} packet_in_buffer;


static event_handlers callbacks = { NULL, NULL, NULL, NULL, NULL, NULL };
static packet_in_buffer *packet_in_buffers = NULL;
static unsigned int n_buffers = 0;
static unsigned int next_buffer_id = 0;
static pthread_mutex_t buffer_mutex;


OFDPE
init_async_event_notifier( const unsigned int n_packet_buffers ) {
  assert( packet_in_buffers == NULL );
  assert( next_buffer_id == 0 );

  n_buffers = n_packet_buffers;

  if ( n_buffers > 0 ) {
    packet_in_buffers = xmalloc( sizeof( packet_in_buffer ) * n_buffers );
    memset( packet_in_buffers, 0, sizeof( packet_in_buffer ) * n_buffers );
  }

  init_mutex( &buffer_mutex );

  return OFDPE_SUCCESS;
}


OFDPE
finalize_async_event_notifier() {
  next_buffer_id = 0;
  callbacks.packet_in = NULL;
  callbacks.packet_in_user_data = NULL;
  callbacks.flow_removed = NULL;
  callbacks.flow_removed_user_data = NULL;
  callbacks.port_status = NULL;
  callbacks.port_status_user_data = NULL;

  if ( packet_in_buffers != NULL ) {
    if ( !lock_mutex( &buffer_mutex ) ) {
      return ERROR_LOCK;
    }

    for ( unsigned int i = 0; i < n_buffers; i++ ) {
      if ( packet_in_buffers[ i ].packet != NULL ) {
        free_buffer( packet_in_buffers[ i ].packet );
      }
    }

    xfree( packet_in_buffers );

    if ( !unlock_mutex( &buffer_mutex ) ) {
      return ERROR_UNLOCK;
    }
  }

  n_buffers = 0;

  finalize_mutex( &buffer_mutex );

  return OFDPE_SUCCESS;
}


void
notify_port_status( const switch_port *port, const uint8_t reason ) {
  assert( port != NULL );
  assert( reason <= OFPPR_MODIFY );

  if ( callbacks.port_status == NULL ) {
    return;
  }

  port_status_event *event = xmalloc( sizeof( port_status_event ) );
  memset( event, 0, sizeof( port_status_event ) );
  event->reason = reason;
  switch_port_to_ofp_port( &event->desc, port );

  callbacks.port_status( event, callbacks.port_status_user_data );

  xfree( event );
}


static uint32_t
get_buffer_id() {
  if ( n_buffers == 0 || packet_in_buffers == NULL ) {
    return UINT32_MAX;
  }

  assert( next_buffer_id < n_buffers );

  uint32_t buffer_id = UINT32_MAX;
  if ( packet_in_buffers[ next_buffer_id ].packet == NULL ) {
    buffer_id = next_buffer_id++;
  }
  else {
    struct timespec now = { 0, 0 };
    time_now( &now );
    struct timespec diff = { 0, 0 };
    timespec_diff( packet_in_buffers[ next_buffer_id ].saved_at, now, &diff );
    if ( diff.tv_sec > 0 ) {
      free_buffer( packet_in_buffers[ next_buffer_id ].packet );
      packet_in_buffers[ next_buffer_id ].packet = NULL;
      packet_in_buffers[ next_buffer_id ].saved_at.tv_sec = 0;
      packet_in_buffers[ next_buffer_id ].saved_at.tv_nsec = 0;
      buffer_id = next_buffer_id++;
    }
  }

  if ( next_buffer_id == n_buffers ) {
    next_buffer_id = 0;
  }

  return buffer_id;
}


static uint32_t
save_packet( const buffer *packet ) {
  assert( packet != NULL );

  if ( !lock_mutex( &buffer_mutex ) ) {
    return UINT32_MAX;
  }

  uint32_t buffer_id = get_buffer_id();
  if ( buffer_id != UINT32_MAX ) {
    packet_in_buffers[ buffer_id ].packet = duplicate_buffer( packet );
    // duplicate_buffer() copies user_data, which points to old packet addresses
    copy_packet_info( packet_in_buffers[ buffer_id ].packet, packet );
    time_now( &packet_in_buffers[ buffer_id ].saved_at );
  }

  unlock_mutex( &buffer_mutex );

  return buffer_id;
}


void
notify_packet_in( const uint8_t reason, const uint8_t table_id, const uint64_t cookie, const match *match,
                  buffer *packet, const uint16_t max_len ) {
  assert( reason <= OFPR_INVALID_TTL );
  assert( table_id <= FLOW_TABLE_ID_MAX );
  assert( match != NULL );
  assert( packet != NULL );

  if ( callbacks.packet_in == NULL ) {
    return;
  }
  if ( ERROR_DROP_PACKET == execute_meter( OFPM_CONTROLLER, packet ) ) {
    return;
  }

  packet_in_event *event = xmalloc( sizeof( packet_in_event ) );
  memset( event, 0, sizeof( packet_in_event ) );
  event->buffer_id = save_packet( packet );
  event->reason = reason;
  event->table_id = table_id;
  event->cookie = cookie;
  event->match = *match;
  event->packet = packet;
  event->total_len = ( uint16_t ) event->packet->length;
  event->max_len = max_len;

  callbacks.packet_in( event, callbacks.packet_in_user_data );

  xfree( event );
}


void
notify_flow_removed( const uint8_t reason, const flow_entry *entry ) {
  assert( reason <= OFPRR_GROUP_DELETE );
  assert( entry != NULL );
  assert( entry->match != NULL );

  if ( callbacks.flow_removed == NULL ) {
    return;
  }

  flow_removed_event *event = xmalloc( sizeof( flow_removed_event ) );
  memset( event, 0, sizeof( flow_removed_event ) );
  event->cookie = entry->cookie;
  event->priority = entry->priority;
  event->reason = reason;
  event->table_id = entry->table_id;
  event->duration_sec = entry->duration_sec;
  event->duration_nsec = entry->duration_nsec;
  event->idle_timeout = entry->idle_timeout;
  event->hard_timeout = entry->hard_timeout;
  event->packet_count = entry->packet_count;
  event->byte_count = entry->byte_count;
  event->match = *entry->match;

  callbacks.flow_removed( event, callbacks.flow_removed_user_data );

  xfree( event );
}


OFDPE
set_async_event_handler( async_event_type type, async_event_handler handler, void *user_data ) {
  OFDPE ret = OFDPE_SUCCESS;

  switch ( type ) {
    case ASYNC_EVENT_TYPE_PACKET_IN:
    {
      callbacks.packet_in = handler;
      callbacks.packet_in_user_data = user_data;
    }
    break;

    case ASYNC_EVENT_TYPE_FLOW_REMOVED:
    {
      callbacks.flow_removed = handler;
      callbacks.flow_removed_user_data = user_data;
    }
    break;

    case ASYNC_EVENT_TYPE_PORT_STATUS:
    {
      callbacks.port_status = handler;
      callbacks.port_status_user_data = user_data;
    }
    break;

    default:
    {
      error( "Undefined async event type ( %#x ).", type );
      ret = OFDPE_FAILED;
    }
    break;
  }

  return ret;
}


buffer *
get_packet_from_packet_in_buffer( const uint32_t buffer_id ) {
  if ( buffer_id == UINT32_MAX || buffer_id >= n_buffers ) {
    return NULL;
  }

  buffer *packet = packet_in_buffers[ buffer_id ].packet;
  packet_in_buffers[ buffer_id ].packet = NULL;
  packet_in_buffers[ buffer_id ].saved_at.tv_sec = 0;
  packet_in_buffers[ buffer_id ].saved_at.tv_nsec = 0;

  return packet;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

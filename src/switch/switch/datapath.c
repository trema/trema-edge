/*
 * Copyright (C) 2008-2013 NEC Corporation
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


#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include "ofdp.h"
#include "datapath.h"
#include "oxm_match.h"
#include "parse-options.h"
#include "protocol.h"
#include "switch.h"


void
notify_protocol( int fd, void *user_data ) {
  assert( fd >= 0 );
  struct datapath *datapath = user_data;
  assert( datapath != NULL );

  ssize_t ret = write( datapath->peer_efd, &datapath->send_count, sizeof( datapath->send_count ) );
  if ( ret < 0 ) {
    if ( ret == EAGAIN || errno == EINTR ) {
      return;
    }
    char buf[ 256 ];
    memset( buf, '\0', sizeof( buf ) );
    char *error_string = strerror_r( errno, buf, sizeof( buf ) - 1 );    
    error( "Failed to notify protocol count= " PRIu64 ", ret = %d errno %s [%d]", datapath->send_count, ret, error_string, errno );
    return;
  }
  else if ( ret != sizeof( datapath->send_count ) ) {
    error( "Failed to notify protocol count= " PRIu64 ",ret = %d", datapath->send_count, ret );
  }
  datapath->send_count = 0;
  set_writable_safe( fd, false );
}


static void
push_datapath_message_to_peer( buffer *packet, struct datapath *datapath ) {
  if ( is_datapath() ) {
    enqueue_message( datapath->peer_queue, packet );
    datapath->send_count++;
    set_writable_safe( datapath->peer_efd, true );
  } else if ( is_protocol() ) {
    handle_datapath_packet( packet, get_protocol() );
  }
}


static void
post_datapath_status( struct datapath *datapath ) {
  uint32_t buffer_len = sizeof( struct datapath_ctrl );

  buffer *buffer = alloc_buffer_with_length( buffer_len );
  append_back_buffer( buffer, buffer_len );
  struct datapath_ctrl *ctrl = buffer->data;
  ctrl->status = datapath->running;
  push_datapath_message_to_peer( buffer, datapath );
}


static void
wakened( int fd, void *user_data ) {
  assert( fd >= 0 );
  assert( user_data != NULL );

  uint64_t count = 0;

  ssize_t ret = read( fd, &count, sizeof( uint64_t ) );
  if ( ret < 0 ) {
    if ( ret != EAGAIN || errno == EINTR ) {
      return;
    }
    char buf[ 256 ];
    memset( buf, '\0', sizeof( buf ) );
    char *error_string = strerror_r( errno, buf, sizeof( buf ) - 1 );    
    error( "Failed to retrieve notify count from protocol errno %s [%d]", error_string, errno );
    count = 0;
  }
}


typedef struct {
  uint32_t port_no;
  char device_name[ IFNAMSIZ ];
} device_info;


static list_element *
parse_argument_device_option( const char *datapath_ports ) {
  char *optarg = strdup( datapath_ports );  
  list_element *head = NULL;

  char *save_ptr = NULL;
  char *p = strtok_r( optarg, ",", &save_ptr );

  while ( p != NULL ) {
    char *p_port = NULL;
    char *p_dev = strtok_r( p, "/", &p_port );

    device_info *dev_info = ( device_info * ) xcalloc( 1, sizeof( device_info ) );
    strncpy( dev_info->device_name, p_dev, IFNAMSIZ - 1 );
    if ( p_port != NULL ) {
      dev_info->port_no = ( uint32_t ) strtoul( p_port, NULL, 0 );
    }
    else {
      dev_info->port_no = 0;
    }

    append_to_tail( &head, dev_info );

    p = strtok_r( NULL, ",", &save_ptr );
  }
  xfree( optarg );
  return head;
}


static void 
datapath_packet_in( void *event, void *user_data ) {
  packet_in_event *pin = event;
  assert( user_data );
  struct datapath *datapath = user_data;

  uint32_t notifier_len = ( uint32_t ) ( sizeof( struct ofp_header ) + sizeof( packet_in_event ) );
  buffer *notifier = alloc_buffer_with_length( notifier_len );
  append_back_buffer( notifier, notifier_len );

  struct ofp_header *hdr = notifier->data;
  hdr->length = ( uint16_t ) notifier_len;
  hdr->type = OFPT_PACKET_IN; 

  packet_in_event *pin_event = ( packet_in_event * ) ( ( char * ) notifier->data + sizeof( *hdr ) );
  memcpy( pin_event, pin, sizeof( packet_in_event ) );
  if ( pin->packet->length > 0 ) {
    pin_event->packet = duplicate_buffer( pin->packet );
  }

  push_datapath_message_to_peer( notifier, datapath );
}


static void
datapath_flow_removed( void *event, void *user_data ) {
  flow_removed_event *frm = event;
  assert( user_data );
  struct datapath *datapath = user_data;

  uint32_t notifier_len = sizeof( struct ofp_header ) + sizeof( flow_removed_event );
  buffer *notifier = alloc_buffer_with_length( notifier_len );
  append_back_buffer( notifier, notifier_len );

  struct ofp_header *hdr = notifier->data;
  hdr->length = ( uint16_t ) notifier_len;
  hdr->type = OFPT_FLOW_REMOVED;

  flow_removed_event *frm_event = ( flow_removed_event * ) ( ( char * ) notifier->data + sizeof( *hdr ) );
  memcpy( frm_event, frm, sizeof( flow_removed_event ) );

  push_datapath_message_to_peer( notifier, datapath );
}


static void
datapath_port_status( void *event, void *user_data ) {
  port_status_event *ps = event;
  assert( user_data );
  struct datapath *datapath = user_data;

  uint32_t notifier_len = sizeof( struct ofp_header ) + sizeof( port_status_event );
  buffer *notifier = alloc_buffer_with_length( notifier_len );
  append_back_buffer( notifier, notifier_len );

  struct ofp_header *hdr = notifier->data;
  hdr->length = ( uint16_t ) notifier_len;
  hdr->type = OFPT_PORT_STATUS;

  port_status_event *ps_event = ( port_status_event * ) ( ( char * ) notifier->data + sizeof( *hdr ) );
  memcpy( ps_event, ps, sizeof( port_status_event ) );

  push_datapath_message_to_peer( notifier, datapath );
}


static 
void set_event_handlers( void *user_data ) {
  set_async_event_handler( ASYNC_EVENT_TYPE_PACKET_IN, datapath_packet_in, user_data );
  set_async_event_handler( ASYNC_EVENT_TYPE_FLOW_REMOVED, datapath_flow_removed, user_data );
  set_async_event_handler( ASYNC_EVENT_TYPE_PORT_STATUS, datapath_port_status, user_data );
}


static void
dump_flows_actually() {
  dump_flow_tables( info );
}


static void
dump_flows( int signum ) {
  UNUSED( signum );

  set_external_callback_safe( dump_flows_actually );
}


static void
dump_group_actually() {
  dump_group_table( info );
}


static void
dump_group( int signum ) {
  UNUSED( signum );

  set_external_callback_safe( dump_group_actually );
}


static void
set_signal_handlers() {
  sigset_t signals;
  sigemptyset( &signals );
  sigaddset( &signals, SIGUSR1 );
  sigaddset( &signals, SIGUSR2 );
  pthread_sigmask( SIG_UNBLOCK, &signals, NULL );

  struct sigaction signal_dump_table;
  memset( &signal_dump_table, 0, sizeof( struct sigaction ) );
  signal_dump_table.sa_handler = dump_flows;
  sigaction( SIGUSR1, &signal_dump_table, NULL );

  signal_dump_table.sa_handler = dump_group;
  sigaction( SIGUSR2, &signal_dump_table, NULL );
}


static int
serve_datapath( void *data ) {
  struct datapath *datapath = data;
  const struct switch_arguments *args = datapath->args;

  set_signal_handlers();

  OFDPE ret = init_datapath( args->datapath_id, NUM_CONTROLLER_BUFFER, MAX_SEND_QUEUE, MAX_RECV_QUEUE, args->max_flow_entries );
  if ( ret != OFDPE_SUCCESS ) {
    error( "Failed to initialize datapath ( ret = %d ).", ret );
    return -1;
  }
  datapath->running = OFDPE_SUCCESS;

  datapath->own_efd = args->efd[ 1 ];
  datapath->peer_efd = args->efd[ 0 ];
  datapath->peer_queue = args->to_protocol_queue;
  datapath->send_count = 0;
  
  set_fd_handler_safe( datapath->peer_efd, NULL, NULL, notify_protocol, datapath );
  set_writable_safe( datapath->peer_efd, false );
  set_fd_handler_safe( datapath->own_efd, wakened, datapath, NULL, NULL );
  set_readable_safe( datapath->own_efd, true );

  list_element *datapath_ports = parse_argument_device_option( args->datapath_ports );
  for( list_element *e = datapath_ports; e != NULL; e = e->next ) {
    device_info *dev = e->data;
    if ( dev->port_no > OFPP_MAX ) {
      error( "Invalid port number ( port_no = %u ).", dev->port_no );
      return -1;
    }
    ret = add_port( dev->port_no, dev->device_name );
    if ( ret != OFDPE_SUCCESS ) {
      return -1;
    }
    xfree( dev );
  }
  delete_list( datapath_ports );

  set_event_handlers( datapath );
  post_datapath_status( datapath );

  ret = start_datapath();
  if ( ret != OFDPE_SUCCESS ) {
    error( "Failed to start datapath ( ret = %d ).", ret );
    return -1;
  }

  ret = finalize_datapath();
  if ( ret != OFDPE_SUCCESS ) {
    error( "Failed to finalize datapath ( ret = %d ).", ret );
    return -1;
  }

  return 0;
}


pthread_t
start_async_datapath( struct switch_arguments *args ) {
  int ret;

  struct datapath *datapath = ( struct datapath * ) xmalloc( sizeof( *datapath ) );
  datapath->thread.proc = serve_datapath;
  datapath->args = args;
  datapath->thread.data = datapath;
  ret = start_async( &datapath->thread );
  if ( ret < 0 ) {
    error( "Failed to start the datapath thread" );
    return 0;
  }
  return datapath->thread.tid;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

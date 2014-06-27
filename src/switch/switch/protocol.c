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
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "trema.h"
#include "ofdp.h"
#include "action-tlv.h"
#include "oxm-helper.h"
#include "oxm.h"
#include "parse-options.h"
#include "protocol-handler.h"
#include "protocol.h"


static void
notify_datapath( int fd, void *user_data ) {
  assert( fd >= 0 );
  struct protocol *protocol = user_data;
  assert( protocol != NULL );

  ssize_t ret = write( protocol->peer_efd, &protocol->send_count, sizeof( protocol->send_count ) );
  if ( ret < 0 ) {
    if ( ret == EAGAIN || errno == EINTR ) {
      return;
    }
    char buf[ 256 ];
    memset( buf, '\0', sizeof( buf ) );
    char *error_string = strerror_r( errno, buf, sizeof( buf ) - 1 );    
    error( "Failed to notify datapath count= " PRIu64 ", ret = %d errno %s [%d]", protocol->send_count, ret, error_string, errno );
    return;
  }
  else if ( ret != sizeof( protocol->send_count ) ) {
    error( "Failed to notify datapath count= " PRIu64 ",ret = %d", protocol->send_count, ret );
  }
  protocol->send_count = 0;
  set_writable_safe( fd, false );
}


void
wakeup_datapath( struct protocol *protocol ) {
  protocol->send_count++;
  set_writable_safe( protocol->peer_efd, true );
}


static void
handle_datapath_packet_in( buffer *datapath_pkt, struct protocol *protocol ) {
  UNUSED( protocol );

  packet_in_event *pin = ( packet_in_event * )( ( char * ) datapath_pkt->data + sizeof( struct ofp_header ) );
  oxm_matches *oxm_match = create_oxm_matches();
  construct_oxm( oxm_match, &pin->match );
  if ( pin->packet->length > pin->max_len ) {
    pin->packet->length = pin->max_len;
  }
  buffer *packet_in = create_packet_in( 0, pin->buffer_id, ( uint16_t ) pin->packet->length, pin->reason, pin->table_id,
                                        pin->cookie, oxm_match, pin->packet );
  delete_oxm_matches( oxm_match );
  switch_send_openflow_message( packet_in );
  free_buffer( packet_in );
  if ( pin->packet && pin->packet->length > 0 ){
    free_buffer( pin->packet );
  }
  free_buffer( datapath_pkt );
}


static void
handle_datapath_port_status( buffer *datapath_pkt, const struct protocol *protocol ) {
  UNUSED( protocol );
  port_status_event *ps = ( port_status_event * )( ( char * ) datapath_pkt->data + sizeof( struct ofp_header ) );

  buffer *port_status = create_port_status( 0, ps->reason, ps->desc );
  switch_send_openflow_message( port_status );
  free_buffer( port_status );
  free_buffer( datapath_pkt );
}


static void
handle_datapath_flow_removed( buffer *datapath_pkt, const struct protocol *protocol ) {
  UNUSED( protocol );
  flow_removed_event *frm = ( flow_removed_event * )( ( char * ) datapath_pkt->data + sizeof( struct ofp_header ) );

  oxm_matches *oxm_match = create_oxm_matches();
  construct_oxm( oxm_match, &frm->match );
  buffer *flow_removed = create_flow_removed( 0, frm->cookie, frm->priority, frm->reason, frm->table_id,
                                              frm->duration_sec, frm->duration_nsec, frm->idle_timeout,
                                              frm->hard_timeout, frm->packet_count, frm->byte_count, oxm_match );
  switch_send_openflow_message( flow_removed );
  delete_oxm_matches( oxm_match );
  free_buffer( flow_removed );
  free_buffer( datapath_pkt );
}


static void
handle_datapath_opf_packet( buffer *packet, struct protocol *protocol ) {
  struct ofp_header *header = packet->data;

  switch( header->type ) {
    case OFPT_PACKET_IN:
      handle_datapath_packet_in( packet, protocol );
    break;
    case OFPT_PORT_STATUS:
      handle_datapath_port_status( packet, protocol );
    break;
    case OFPT_FLOW_REMOVED:
      handle_datapath_flow_removed( packet, protocol );
    break;
    default:
      warn( "Unhandled datapath packet %d", header->type );
    break;
  }
}


static struct protocol *active_protocol = NULL;


static void
handle_controller_connected( void *user_data ) {
  set_hello_handler( handle_hello, user_data );
  set_features_request_handler( handle_features_request, user_data );
  set_set_config_handler( handle_set_config, user_data );
  set_echo_request_handler( handle_echo_request, user_data );
  set_flow_mod_handler( handle_flow_mod, user_data );
  set_packet_out_handler( handle_packet_out, user_data );
  set_port_mod_handler( handle_port_mod, user_data );
  set_table_mod_handler( handle_table_mod, user_data );
  set_group_mod_handler( handle_group_mod, user_data );
  set_meter_mod_handler( handle_meter_mod, user_data );
  set_multipart_request_handler( handle_multipart_request, user_data );
  set_barrier_request_handler( handle_barrier_request, user_data );
  set_get_config_request_handler( handle_get_config_request, user_data );

  active_protocol = user_data;
}


struct protocol* get_protocol() {
  return active_protocol;
}


static void 
handle_datapath_ctrl_packet( buffer *packet, struct protocol *protocol ) {
  free_buffer( packet );
  /*
   * At the moment don't care what the status is from datapath
   * just that the initialization is completed and should be only one.
   */

  int ret;

  const struct switch_arguments *args = protocol->args;
  ret = init_openflow_switch_interface( args->datapath_id, args->server_ip, args->server_port );
  if ( ret == false ) {
    finish_async( &protocol->thread );
  }
  set_controller_connected_handler( handle_controller_connected, protocol );
}


void
handle_datapath_packet( buffer *packet, struct protocol *protocol ) {
  if ( packet->length > sizeof( struct ofp_header ) ) {
    // if not connected to controller discard packet_in
    if ( protocol->ctrl.controller_connected == true ) {
      handle_datapath_opf_packet(packet, protocol);
    }
  }
  else {
    handle_datapath_ctrl_packet( packet, protocol );
  }
}


void
retrieve_packet_from_datapath( int fd, void *user_data ) {
  assert( fd >= 0 );
  assert( user_data != NULL );
  struct protocol *protocol = user_data;

  uint64_t count = 0;

  ssize_t ret = read( fd, &count, sizeof( uint64_t ) );
  if ( ret < 0 ) {
    if ( ret != EAGAIN || errno == EINTR ) {
      return;
    }
    char buf[ 256 ];
    memset( buf, '\0', sizeof( buf ) );
    char *error_string = strerror_r( errno, buf, sizeof( buf ) - 1 );    
    error( "Failed to retrieve packet from datapath errno %s [%d]", error_string, errno );
    count = 0;
  }
  for ( uint64_t i = 0; i < count; i++ ) {
    buffer *packet = dequeue_message( protocol->input_queue );
    assert( packet != NULL );
    handle_datapath_packet( packet, protocol );
  }
}


static int
serve_protocol( void *data ) {
  struct protocol *protocol = data;

  add_thread();
  init_timer_safe();
  init_event_handler_safe();
  init_actions();
  init_oxm();

  const struct switch_arguments *args = protocol->args;
  protocol->own_efd = args->efd[ 0 ];
  protocol->peer_efd = args->efd[ 1 ];
  protocol->input_queue = args->to_protocol_queue;
  protocol->send_count = 0;

  set_fd_handler_safe( protocol->own_efd, retrieve_packet_from_datapath, protocol, NULL, NULL );
  set_readable_safe( protocol->own_efd, true );
  set_fd_handler_safe( protocol->peer_efd, NULL, NULL, notify_datapath, protocol );
  set_writable_safe( protocol->peer_efd, false );

  return start_event_handler_safe();
}


pthread_t
start_async_protocol( struct switch_arguments *args ) {
  struct protocol *protocol;
  int ret;

  protocol = ( struct protocol * )xcalloc( 1, sizeof( *protocol ) );  
  protocol->thread.proc = serve_protocol;
  protocol->args = args;
  protocol->thread.data = protocol;
  protocol->ctrl.controller_connected = false;
  ret = start_async( &protocol->thread );
  if ( ret < 0 ) {
    error( "Failed to start the protocol thread" );
    return EXIT_FAILURE;
  }
  return ( protocol->thread.tid );  
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

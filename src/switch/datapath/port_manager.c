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
#include "ether_device.h"
#include "mutex.h"
#include "ofdp_private.h"
#include "openflow_helper.h"
#include "pipeline.h"
#include "port_manager.h"
#include "switch_port.h"
#include "table_manager.h"


typedef struct {
  size_t max_send_queue_length;
  size_t max_recv_queue_length;
} port_manager_config;


static port_manager_config config = { 0, 0 };
static pthread_mutex_t mutex;
static const time_t PORT_STATUS_UPDATE_INTERVAL = 1;


static void
update_switch_port_status_and_stats_walker( switch_port *port, void *user_data ) {
  assert( port != NULL );
  UNUSED( user_data );

  bool updated = update_switch_port_status( port );
  if ( updated ) {
    notify_port_status( port, OFPPR_MODIFY );
  }
  assert( port->device != NULL );
  update_device_stats( port->device );
}


static void
update_switch_port_status_and_stats( void *user_data ) {
  if ( !lock_mutex( &mutex ) ) {
    return;
  }

  foreach_switch_port( update_switch_port_status_and_stats_walker, user_data );

  unlock_mutex( &mutex );
}


OFDPE
init_port_manager( const size_t max_send_queue_length, const size_t max_recv_queue_length ) {
  if ( max_send_queue_length == 0 || max_recv_queue_length == 0 ) {
    error( "Failed to initialize port manager. Maximum queue length must be greater than zero "
           "( max_send_queue = %u, max_recv_queue = %u ).", max_send_queue_length, max_recv_queue_length );
    return ERROR_INVALID_PARAMETER;
  }

  bool ret = init_mutex( &mutex );
  if ( !ret ) {
    return ERROR_INIT_MUTEX;
  }

  ret = lock_mutex( &mutex );
  if ( !ret ) {
    return ERROR_LOCK;
  }

  config.max_send_queue_length = max_send_queue_length;
  config.max_recv_queue_length = max_recv_queue_length;

  init_switch_port();

  add_periodic_event_callback_safe( PORT_STATUS_UPDATE_INTERVAL, update_switch_port_status_and_stats, NULL );

  ret = unlock_mutex( &mutex );
  if ( !ret ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
finalize_port_manager() {
  bool ret = lock_mutex( &mutex );
  if ( !ret ) {
    return ERROR_LOCK;
  }

  delete_timer_event_safe( update_switch_port_status_and_stats, NULL );

  finalize_switch_port();

  config.max_send_queue_length = 0;
  config.max_recv_queue_length = 0;

  ret = unlock_mutex( &mutex );
  if ( !ret ) {
    return ERROR_UNLOCK;
  }

  ret = finalize_mutex( &mutex );
  if ( !ret ) {
    return ERROR_FINALIZE_MUTEX;
  }

  return OFDPE_SUCCESS;
}


static void
handle_frame_received_on_switch_port( buffer *frame, void *user_data ) {
  assert( frame != NULL );
  assert( user_data != NULL );

  switch_port *port = user_data;

  if ( !lock_mutex( &mutex ) ) {
    return;
  }

  if ( ( port->config & ( OFPPC_PORT_DOWN | OFPPC_NO_RECV ) ) != 0 ) {
    unlock_mutex( &mutex );
    return;
  }

  if ( frame->length + ETH_FCS_LENGTH < ETH_MINIMUM_LENGTH ) {
    fill_ether_padding( frame );
  }

  handle_received_frame( port, frame );

  unlock_mutex( &mutex );
}


static OFDPE
add_ether_device_as_switch_port( const char *device, uint32_t port_no ) {
  assert( device != NULL );
  assert( port_no <= OFPP_MAX );

  if ( !lock_mutex( &mutex ) ) {
    return ERROR_LOCK;
  }

  if ( port_no == 0 ) {
    bool ret = get_free_switch_port_no( &port_no );
    if ( !ret ) {
      error( "No switch port number available ( device = %s ).", device );
      return unlock_mutex( &mutex ) ? ERROR_OFDPE_PORT_MOD_FAILED_BAD_PORT : ERROR_UNLOCK;
    }
  }

  bool ret = switch_port_exists( port_no );
  if ( ret ) {
    error( "Specified port already exists ( device = %s, port_no = %u ).", device, port_no );
    return unlock_mutex( &mutex ) ? ERROR_OFDPE_PORT_MOD_FAILED_BAD_PORT : ERROR_UNLOCK;
  }

  info( "Adding an Ethernet device as a switch port ( device = %s, port_no = %u ).", device, port_no );

  switch_port *port = add_switch_port( device, port_no, config.max_send_queue_length, config.max_recv_queue_length );
  if ( port == NULL ) {
    error( "Failed to add an Ethernet device as a switch port ( device = %s, port_no = %u ).", device, port_no );
    return unlock_mutex( &mutex ) ? ERROR_OFDPE_PORT_MOD_FAILED_EPERM : ERROR_UNLOCK;
  }

  set_frame_received_handler( port->device, handle_frame_received_on_switch_port, port );

  notify_port_status( port, OFPPR_ADD );

  if ( !unlock_mutex( &mutex ) ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


static OFDPE
delete_ether_device_from_switch( const uint32_t port_no ) {
  assert( port_no > 0 && port_no <= OFPP_MAX );

  if ( !lock_mutex( &mutex ) ) {
    return ERROR_LOCK;
  }

  switch_port *port = delete_switch_port( port_no );
  if ( port == NULL ) {
    return unlock_mutex( &mutex ) ? ERROR_INVALID_PARAMETER : ERROR_UNLOCK;
  }

  notify_port_status( port, OFPPR_DELETE );

  if ( port->device != NULL ) {
    delete_ether_device( port->device );
  }
  xfree( port );

  if ( !unlock_mutex( &mutex ) ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
add_port( const uint32_t port_no, const char *device_name ) {
  assert( port_no <= OFPP_MAX );
  assert( device_name != NULL );

  if ( datapath_is_running() && !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  OFDPE ret = add_ether_device_as_switch_port( device_name, port_no );
  if ( ret != OFDPE_SUCCESS ) {
    error( "Failed to add an Ethernet port as a switch port ( ret = %d, port_no = %u, device_name = %s ).",
           ret, port_no, device_name );
  }

  if ( datapath_is_running() && !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return ret;
}


OFDPE
delete_port( const uint32_t port_no ) {
  assert( port_no > 0 && port_no <= OFPP_MAX );

  if ( datapath_is_running() && !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  OFDPE ret = delete_ether_device_from_switch( port_no );
  if ( ret != OFDPE_SUCCESS ) {
    error( "Failed to delete an Ethernet port from a switch ( ret = %d, port_no = %u ).",
           ret, port_no );
  }

  if ( datapath_is_running() && !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return ret;
}


OFDPE
update_port( const uint32_t port_no, uint32_t config, uint32_t mask ) {
  assert( port_no > 0 && port_no <= OFPP_MAX );

  if ( datapath_is_running() && !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  switch_port *port = lookup_switch_port( port_no );
  if ( port == NULL ) {
    return ERROR_OFDPE_PORT_MOD_FAILED_BAD_PORT;
  }

  bool ret = update_switch_port_config( port, config, mask );
  if ( !ret ) {
    error( "Failed to update switch port config ( port_no = %u, config = %#x, mask = %#x ).",
           port_no, config, mask );
  }

  if ( datapath_is_running() && !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return ret ? OFDPE_SUCCESS : ERROR_OFDPE_PORT_MOD_FAILED_BAD_CONFIG;
}


typedef struct {
  list_element *list;
  uint32_t in_port;
} switch_port_list;


static void
append_switch_port_to_list( switch_port *port, void *user_data ) {
  assert( port != NULL );
  assert( user_data != NULL );

  switch_port_list *ports = user_data;
  if ( ports->in_port != port->port_no ) {
    append_to_tail( &ports->list, port );
  }
}


static list_element *
get_switch_ports_to_output( const uint32_t port_no, const uint32_t in_port ) {
  assert( port_no > 0 );
  assert( in_port <= OFPP_MAX || in_port == OFPP_CONTROLLER );

  switch_port_list ports;
  create_list( &ports.list );
  ports.in_port = in_port;

  switch ( port_no ) {
    case OFPP_IN_PORT:
    {
      switch_port *port = lookup_switch_port( in_port );
      if ( port != NULL ) {
        append_to_tail( &ports.list, port );
      }
    }
    break;

    case OFPP_FLOOD: // Openflow-hybrid
    case OFPP_ALL:
    {
      foreach_switch_port( append_switch_port_to_list, &ports );
    }
    break;

    case OFPP_TABLE:
    case OFPP_NORMAL: // Openflow-hybrid
    case OFPP_CONTROLLER:
    case OFPP_LOCAL:
    case OFPP_ANY:
    {
      warn( "Invalid port number ( port_no = %u, in_port = %u ).", port_no, in_port );
    }
    break;

    default:
    {
      if ( port_no != in_port ) {
        switch_port *port = lookup_switch_port( port_no );
        if ( port != NULL ) {
          append_to_tail( &ports.list, port );
        }
      }
    }
    break;
  }

  return ports.list;
}


OFDPE
send_frame_from_switch_port( const uint32_t port_no, buffer *frame ) {
  assert( port_no > 0 );
  assert( frame != NULL );

  if ( port_no > OFPP_MAX && port_no != OFPP_IN_PORT && port_no != OFPP_NORMAL && port_no != OFPP_FLOOD && port_no != OFPP_ALL && port_no != OFPP_LOCAL ) {
    error( "Output port number is not targeted to switch port ( port_no = %u, frame = %p ).", port_no, frame );
    return OFDPE_FAILED;
  }

  if ( frame->length + ETH_FCS_LENGTH < ETH_MINIMUM_LENGTH ) {
    fill_ether_padding( frame );
  }

  if ( frame->user_data == NULL ) {
    warn( "Ethernet frame is not parsed yet."
          "require eth_in_port to find actual output ports ( port_no = %u, frame = %p ).", port_no, frame );
    return OFDPE_FAILED;
  }
  uint32_t in_port = ( ( packet_info * ) frame->user_data )->eth_in_port;
  if ( in_port == 0 || ( in_port > OFPP_MAX && in_port != OFPP_CONTROLLER ) ) {
    warn( "Invalid eth_in_port found in a parsed frame ( frame = %p, eth_in_port = %u ).", frame, in_port );
    return OFDPE_FAILED;
  }

  if ( !lock_mutex( &mutex ) ) {
    return ERROR_LOCK;
  }

  list_element *ports = get_switch_ports_to_output( port_no, in_port );
  for ( list_element *e = ports; e != NULL;  e = e->next ) {
    assert( e->data != NULL );
    switch_port *port = e->data;
    if ( ( port->config & ( OFPPC_PORT_DOWN | OFPPC_NO_FWD ) ) != 0 ) {
      continue;
    }
    assert( port->device != NULL );
    send_frame( port->device, frame );
  }

  if ( ports != NULL ) {
    delete_list( ports );
  }

  if ( !unlock_mutex( &mutex ) ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
get_port_stats( const uint32_t port_no, port_stats **stats, uint32_t *n_ports ) {
  assert( ( port_no > 0 && port_no <= OFPP_MAX ) || port_no == OFPP_ANY );
  assert( stats != NULL );
  assert( n_ports != NULL );

  if ( !lock_mutex( &mutex ) ) {
    return ERROR_LOCK;
  }

  list_element *ports = NULL;
  *n_ports = 0;
  *stats = NULL;
  if ( port_no != OFPP_ANY ) {
    switch_port *port = lookup_switch_port( port_no );
    if ( port == NULL ) {
      if ( unlock_mutex( &mutex ) !=  OFDPE_SUCCESS ) {
        return ERROR_UNLOCK;
      }
      return ERROR_OFDPE_BAD_REQUEST_BAD_PORT;
    }
    create_list( &ports );
    append_to_tail( &ports, port );
  }
  else {
    ports = get_all_switch_ports();
    if ( ports == NULL ) {
      return unlock_mutex( &mutex ) ? OFDPE_SUCCESS : ERROR_UNLOCK;
    }
  }


  *n_ports = ( uint32_t ) list_length_of( ports );
  size_t length = ( *n_ports ) * sizeof( port_stats );
  *stats = xmalloc( length );
  memset( *stats, 0, length );

  port_stats *stat = *stats;
  for ( list_element *e = ports; e != NULL; e = e->next ) {
    assert( e->data != NULL );
    switch_port *port = e->data;
    stat->port_no = port->port_no;
    assert( port->device != NULL );
    stat->rx_packets = port->device->stats.rx_packets;
    stat->tx_packets = port->device->stats.tx_packets;
    stat->rx_bytes = port->device->stats.rx_bytes;
    stat->tx_bytes = port->device->stats.tx_bytes;
    stat->rx_dropped = port->device->stats.rx_dropped;
    stat->tx_dropped = port->device->stats.tx_dropped;
    stat->rx_errors = port->device->stats.rx_errors;
    stat->tx_errors = port->device->stats.tx_errors;
    stat->rx_frame_err = port->device->stats.rx_frame_err;
    stat->rx_over_err = port->device->stats.rx_over_err;
    stat->rx_crc_err = port->device->stats.rx_crc_err;
    stat->collisions = port->device->stats.collisions;
    struct timespec duration = get_switch_port_uptime( port );
    stat->duration_sec = ( uint32_t ) duration.tv_sec;
    stat->duration_nsec = ( uint32_t ) duration.tv_nsec;
    stat++;
  }

  delete_list( ports );

  if ( !unlock_mutex( &mutex ) ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
get_port_description( const uint32_t port_no, port_description **descriptions, uint32_t *n_ports ) {
  assert( port_no > 0 || port_no == OFPP_ALL );
  assert( descriptions != NULL );
  assert( n_ports != NULL );

  if ( !lock_mutex( &mutex ) ) {
    return ERROR_LOCK;
  }

  *n_ports = 0;
  *descriptions = NULL;

  list_element *ports = NULL;
  if ( port_no != OFPP_ALL ) {
    switch_port *port = lookup_switch_port( port_no );
    if ( ports == NULL ) {
      return unlock_mutex( &mutex ) ? OFDPE_SUCCESS : ERROR_UNLOCK;
    }
    create_list( &ports );
    append_to_tail( &ports, port );
  }
  else {
    ports = get_all_switch_ports();
    if ( ports == NULL ) {
      return unlock_mutex( &mutex ) ? OFDPE_SUCCESS : ERROR_UNLOCK;
    }
  }

  *n_ports = ( uint32_t ) list_length_of( ports );
  size_t length = ( *n_ports ) * sizeof( port_description );
  *descriptions = xmalloc( length );
  memset( *descriptions, 0, length );

  port_description *description = *descriptions;
  for ( list_element *e = ports; e != NULL; e = e->next ) {
    assert( e->data != NULL );
    switch_port *port = e->data;
    assert( port->device != NULL );
    // FIXME: we assume that "port_description" is the same structure as "struct ofp_port".
    switch_port_to_ofp_port( description, port );
    description++;
  }

  delete_list( ports );

  if ( !unlock_mutex( &mutex ) ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


void
dump_port_description( const port_description *description, void dump_function( const char *format, ... ) ) {
  assert( description != NULL );
  assert( dump_function != NULL );

  ( *dump_function )( "port_no: %u", description->port_no );
  ( *dump_function )( "hw_addr: %02x:%02x:%02x:%02x:%02x:%02x",
                      description->hw_addr[ 0 ], description->hw_addr[ 1 ], description->hw_addr[ 2 ],
                      description->hw_addr[ 3 ], description->hw_addr[ 4 ], description->hw_addr[ 5 ] );
  ( *dump_function )( "name: %s", description->name );
  ( *dump_function )( "config: %#x", description->config );
  ( *dump_function )( "state: %#x", description->state );
  ( *dump_function )( "curr: %#x", description->curr );
  ( *dump_function )( "advertised: %#x", description->advertised );
  ( *dump_function )( "supported: %#x", description->supported );
  ( *dump_function )( "peer: %#x", description->peer );
  ( *dump_function )( "curr_speed: %u", description->curr_speed );
  ( *dump_function )( "max_speed: %u", description->max_speed );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/

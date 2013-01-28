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


#include "switch_port.h"


static hash_table *switch_ports = NULL;


static bool
compare_switch_port( const void *x, const void *y ) {
  return ( *( const uint32_t * ) x == *( const uint32_t * ) y ) ? true : false;
}


static unsigned int
hash_switch_port( const void *key ) {
  return *( const uint32_t * ) key;
}


void
init_switch_port() {
  assert( switch_ports == NULL );

  switch_ports = create_hash_with_size( compare_switch_port, hash_switch_port, 64 );
}


void
finalize_switch_port() {
  assert( switch_ports != NULL );

  hash_iterator iter;
  hash_entry *e;
  init_hash_iterator( switch_ports, &iter );
  while ( ( e = iterate_hash_next( &iter ) ) != NULL ) {
    switch_port *port = delete_hash_entry( switch_ports, e->key );
    if ( port == NULL ) {
      continue;
    }

    if ( port->device != NULL ) {
      delete_ether_device( port->device );
    }
    xfree( port );
  }
  delete_hash( switch_ports );
  switch_ports = NULL;
}


switch_port *
lookup_switch_port( uint32_t port_no ) {
  assert( switch_ports != NULL );

  return lookup_hash_entry( switch_ports, &port_no );
}


switch_port *
delete_switch_port( uint32_t port_no ) {
  assert( switch_ports != NULL );

  return delete_hash_entry( switch_ports, &port_no );
}


void
foreach_switch_port( switch_port_walker callback, void *user_data ) {
  hash_iterator iter;
  hash_entry *e;

  init_hash_iterator( switch_ports, &iter );
  while ( ( e = iterate_hash_next( &iter ) ) != NULL ) {
    if ( e->value != NULL ) {
      callback( e->value, user_data );
    }
  }
}


switch_port *
add_switch_port( const char *interface, uint32_t port_no,
                 const size_t max_send_queue, const size_t max_recv_queue ) {
  assert( interface != NULL );
  assert( switch_ports != NULL );

  switch_port *port = ( switch_port * ) xmalloc( sizeof( switch_port ) );
  memset( port, 0, sizeof( switch_port ) );
  port->port_no = port_no;
  port->device = create_ether_device( interface, max_send_queue, max_recv_queue );
  if ( port->device == NULL ) {
    xfree( port );
    return NULL;
  }

  insert_hash_entry( switch_ports, &port->port_no, port );

  return port;
}


bool
update_switch_port_status( switch_port *port ) {
  assert( port != NULL );
  assert( port->device != NULL );

  bool ret = update_device_status( port->device );
  if ( ret == false ) {
    return false;
  }

  bool updated = false;
  if ( ( ( port->status.state & OFPPS_LINK_DOWN ) != 0 ) && ( port->device->status.up == true ) ) {
    updated = true;
    port->status.state &= ~( ( uint32_t ) OFPPS_LINK_DOWN );
  }
  else if ( ( ( port->status.state & OFPPS_LINK_DOWN ) == 0 ) && ( port->device->status.up == false ) ) {
    updated = true;
    port->status.state |= OFPPS_LINK_DOWN;
  }
  if ( port->status.curr != port->device->status.curr ) {
    updated = true;
    port->status.curr = port->device->status.curr;
  }
  if ( port->status.advertised != port->device->status.advertised ) {
    updated = true;
    port->status.advertised = port->device->status.advertised;
  }
  if ( port->status.supported != port->device->status.supported ) {
    updated = true;
    port->status.supported = port->device->status.supported;
  }
  if ( port->status.peer != port->device->status.peer ) {
    updated = true;
    port->status.peer = port->device->status.peer;
  }

  return updated;
}


bool
update_switch_port_config( switch_port *port, uint32_t config, uint32_t mask ) {
  assert( port != NULL );

  if ( ( mask & ~( ( uint32_t ) ( OFPPC_PORT_DOWN | OFPPC_NO_RECV | OFPPC_NO_FWD | OFPPC_NO_PACKET_IN ) ) ) != 0 ) {
    error( "Unsupported/undefined port config mask ( port_no = %u, config = %#x, mask = %#x ).",
           port->port_no, config, mask );
    return false;
  }

  if ( ( config & ~( ( uint32_t ) ( OFPPC_PORT_DOWN | OFPPC_NO_RECV | OFPPC_NO_FWD | OFPPC_NO_PACKET_IN ) ) ) != 0 ) {
    error( "Unsupported/undefined port config flags ( port_no = %u, config = %#x, mask = %#x ).",
           port->port_no, config, mask );
    return false;
  }

  mask = mask & ( config ^ port->config );

  if ( mask & OFPPC_PORT_DOWN ) {
    if ( config & OFPPC_PORT_DOWN ) {
      if ( down_ether_device( port->device ) ) {
        port->config |= OFPPC_PORT_DOWN;
      }
      else {
        error( "Failed to down a switch port ( port_no = %u ).", port->port_no );
        return false;
      }
    }
    else {
      if ( up_ether_device( port->device ) ) {
        port->config &= ( uint32_t ) ~OFPPC_PORT_DOWN;
      }
      else {
        error( "Failed to up a switch port ( port_no = %u ).", port->port_no );
        return false;
      }
    }
  }

  if ( mask & OFPPC_NO_RECV ) {
    if ( config & OFPPC_NO_RECV ) {
      port->config |= OFPPC_NO_RECV;
    }
    else {
      port->config &= ( uint32_t ) ~OFPPC_NO_RECV;
    }
  }

  if ( mask & OFPPC_NO_FWD ) {
    if ( config & OFPPC_NO_FWD ) {
      port->config |= OFPPC_NO_FWD;
    }
    else {
      port->config &= ( uint32_t ) ~OFPPC_NO_FWD;
    }
  }

  if ( mask & OFPPC_NO_PACKET_IN ) {
    if ( config & OFPPC_NO_PACKET_IN ) {
      port->config |= OFPPC_NO_PACKET_IN;
    }
    else {
      port->config &= ( uint32_t ) ~OFPPC_NO_PACKET_IN;
    }
  }

  return true;
}


struct timespec
get_switch_port_uptime( switch_port *port ) {
  assert( port != NULL );
  assert( port->device != NULL );

  return get_device_uptime( port->device );
}


bool
get_free_switch_port_no( uint32_t *port_no ) {
  assert( port_no != NULL );

  *port_no = 0;
  for ( uint32_t i = 1; i <= OFPP_MAX; i++ ) {
    switch_port *port = lookup_switch_port( i );
    if ( port == NULL ) {
      *port_no = i;
      break;
    }
  }

  return *port_no != 0 ? true : false;
}


bool
switch_port_is_up( const uint32_t port_no ) {
  assert( port_no > 0 && port_no <= OFPP_MAX );

  switch_port *port = lookup_switch_port( port_no );
  if ( port == NULL ) {
    return false;
  }

  bool up = false;
  if ( ( port->status.state & OFPPS_LINK_DOWN ) == 0 ) {
    up = true;
  }

  return up;
}


bool
switch_port_exists( const uint32_t port_no ) {
  assert( port_no > 0 && port_no <= OFPP_MAX );

  switch_port *port = lookup_switch_port( port_no );
 
  return port != NULL ? true : false;
}


static void
append_switch_port_to_list( switch_port *port, void *user_data ) {
  assert( port != NULL );
  assert( user_data != NULL );

  list_element **ports = user_data;

  append_to_tail( ports, port );
}


list_element *
get_all_switch_ports() {
  list_element *ports = NULL;
  create_list( &ports );

  foreach_switch_port( append_switch_port_to_list, &ports );

  return ports;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

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


#ifndef SWITCH_PORT_H
#define SWITCH_PORT_H


#include "ether_device.h"


typedef struct {
  uint32_t port_no;
  struct {
    uint32_t state;
    uint32_t curr;
    uint32_t advertised;
    uint32_t supported;
    uint32_t peer;
  } status;
  uint32_t config;
  ether_device *device;
} switch_port;

typedef void ( *switch_port_walker )( switch_port *port, void *user_data );


void init_switch_port( void );
void finalize_switch_port( void );
switch_port *lookup_switch_port( uint32_t port_no );
switch_port *delete_switch_port( uint32_t port_no );
void foreach_switch_port( switch_port_walker callback, void *user_data );
switch_port *add_switch_port( const char *interface, uint32_t port_no, const size_t max_send_queue, const size_t max_recv_queue );
bool update_switch_port_status( switch_port *port );
bool update_switch_port_config( switch_port *port, uint32_t config, uint32_t mask );
struct timespec get_switch_port_uptime( switch_port *port );
bool get_free_switch_port_no( uint32_t *port_no );
bool switch_port_is_up( const uint32_t port_no );
bool switch_port_exists( const uint32_t port_no );
list_element *get_all_switch_ports( void );
size_t get_switch_mtu( void );


#endif // SWITCH_PORT_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

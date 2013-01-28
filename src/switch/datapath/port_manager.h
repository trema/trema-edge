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


#ifndef PORT_MANAGER_H
#define PORT_MANAGER_H


#include "ofdp_common.h"


typedef struct ofp_port_stats port_stats;
typedef struct ofp_port port_description;


OFDPE init_port_manager( const size_t max_send_queue, const size_t max_recv_queue );
OFDPE finalize_port_manager( void );
OFDPE add_port( const uint32_t port_no, const char *device_name );
OFDPE delete_port( const uint32_t port_no );
OFDPE update_port( const uint32_t port_no, uint32_t config, uint32_t mask );
OFDPE send_frame_from_switch_port( const uint32_t port_no, buffer *frame );
OFDPE get_port_stats( const uint32_t port_no, port_stats **stats, uint32_t *n_ports );
OFDPE get_port_description( const uint32_t port_no, port_description **descriptions, uint32_t *n_ports );
void dump_port_description( const port_description *description, void dump_function( const char *format, ... ) );


#endif // PORT_MANAGER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/

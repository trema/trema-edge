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


#ifndef OFDP_H
#define OFDP_H


#include "action.h"
#include "action_executor.h"
#include "async_event_notifier.h"
#include "flow_entry.h"
#include "flow_table.h"
#include "group_entry.h"
#include "group_table.h"
#include "meter_entry.h"
#include "meter_table.h"
#include "instruction.h"
#include "match.h"
#include "ofdp_error.h"
#include "openflow_helper.h"
#include "port_manager.h"


typedef struct {
  uint64_t datapath_id;
  uint32_t n_buffers;
  uint8_t n_tables;
  uint8_t auxiliary_id;
  uint32_t capabilities;
} switch_features;

typedef struct {
  uint16_t flags;
  uint16_t miss_send_len;
} switch_config;


OFDPE init_datapath( uint64_t datapath_id, unsigned int n_packet_buffers,
                     size_t max_send_queue, size_t max_recv_queue, uint32_t max_flow_entries );
OFDPE start_datapath( void );
OFDPE stop_datapath( void );
OFDPE finalize_datapath( void );
OFDPE get_switch_features( switch_features *features );
OFDPE get_switch_config( switch_config *config );
OFDPE set_switch_config( switch_config *config );
bool datapath_is_running( void );


#endif // OFDP_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/

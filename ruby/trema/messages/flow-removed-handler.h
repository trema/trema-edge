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


#ifndef FLOW_REMOVED_HANDLER_H
#define FLOW_REMOVED_HANDLER_H


void handle_flow_removed( uint64_t datapath_id, uint32_t transaction_id, uint64_t cookie,
                          uint16_t priority, uint8_t reason, uint8_t table_id,
                          uint32_t duration_sec, uint32_t duration_nsec, uint16_t idle_timeout,
                          uint16_t hard_timeout, uint64_t packet_count, uint64_t byte_count,
                          const oxm_matches *match, void *controller );


#endif // FLOW_REMOVED_HANDLER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

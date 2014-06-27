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


#ifndef ACTION_EXECUTOR_H
#define ACTION_EXECUTOR_H


#include "ofdp_common.h"
#include "action.h"
#include "instruction.h"
#include "match.h"
#include "table_manager.h"


enum {
  SUPPORTED_ACTIONS = ( ACTION_OUTPUT | ACTION_COPY_TTL_OUT | ACTION_COPY_TTL_IN |
                        ACTION_SET_MPLS_TTL | ACTION_DEC_MPLS_TTL | ACTION_PUSH_VLAN |
                        ACTION_POP_VLAN | ACTION_PUSH_MPLS | ACTION_POP_MPLS |
                        ACTION_GROUP | ACTION_SET_NW_TTL | ACTION_DEC_NW_TTL |
                        ACTION_SET_FIELD ),
  SUPPORTED_INSTRUCTIONS = ( INSTRUCTION_GOTO_TABLE | INSTRUCTION_WRITE_METADATA |
                             INSTRUCTION_WRITE_ACTIONS | INSTRUCTION_APPLY_ACTIONS |
                             INSTRUCTION_CLEAR_ACTIONS ),
  SUPPORTED_SET_FIELDS = ( MATCH_ETH_DST | MATCH_ETH_SRC |
                           MATCH_ETH_TYPE | MATCH_VLAN_VID | MATCH_VLAN_PCP | MATCH_IP_DSCP |
                           MATCH_IP_ECN | MATCH_IP_PROTO | MATCH_IPV4_SRC | MATCH_IPV4_DST |
                           MATCH_TCP_SRC | MATCH_TCP_DST | MATCH_UDP_SRC | MATCH_UDP_DST |
                           MATCH_ICMPV4_TYPE | MATCH_ICMPV4_CODE | MATCH_ARP_OP | MATCH_ARP_SPA |
                           MATCH_ARP_TPA | MATCH_ARP_SHA | MATCH_ARP_THA | MATCH_IPV6_SRC |
                           MATCH_IPV6_DST | MATCH_IPV6_FLABEL | MATCH_ICMPV6_TYPE |
                           MATCH_ICMPV6_CODE | MATCH_IPV6_ND_TARGET | MATCH_IPV6_ND_SLL |
                           MATCH_IPV6_ND_TLL | MATCH_MPLS_LABEL | MATCH_MPLS_TC | MATCH_MPLS_BOS ),
};


OFDPE init_action_executor( void );
OFDPE finalize_action_executor( void );
OFDPE execute_action_list( action_list *list, buffer *frame );
OFDPE execute_action_set( action_set *aset, buffer *frame );
OFDPE execute_packet_out( uint32_t buffer_id, uint32_t in_port, action_list *list, buffer *frame );

// meter_executor use this
bool set_nw_dscp( buffer *frame, uint8_t value );

#endif // ACTION_EXECUTOR_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/

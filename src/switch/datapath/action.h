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


#ifndef ACTION_H
#define ACTION_H


#include "ofdp_common.h"
#include "match.h"


enum {
  ACTION_OUTPUT = 1ULL << OFPAT_OUTPUT,
  ACTION_COPY_TTL_OUT = 1ULL << OFPAT_COPY_TTL_OUT,
  ACTION_COPY_TTL_IN = 1ULL << OFPAT_COPY_TTL_IN,
  ACTION_SET_MPLS_TTL = 1ULL << OFPAT_SET_MPLS_TTL,
  ACTION_DEC_MPLS_TTL = 1ULL << OFPAT_DEC_MPLS_TTL,
  ACTION_PUSH_VLAN = 1ULL << OFPAT_PUSH_VLAN,
  ACTION_POP_VLAN = 1ULL << OFPAT_POP_VLAN,
  ACTION_PUSH_MPLS = 1ULL << OFPAT_PUSH_MPLS,
  ACTION_POP_MPLS = 1ULL << OFPAT_POP_MPLS,
  ACTION_SET_QUEUE = 1ULL << OFPAT_SET_QUEUE,
  ACTION_GROUP = 1ULL << OFPAT_GROUP,
  ACTION_SET_NW_TTL = 1ULL << OFPAT_SET_NW_TTL,
  ACTION_DEC_NW_TTL = 1ULL << OFPAT_DEC_NW_TTL,
  ACTION_SET_FIELD = 1ULL << OFPAT_SET_FIELD,
  ACTION_PUSH_PBB = 1ULL << OFPAT_PUSH_PBB,
  ACTION_POP_PBB = 1ULL << OFPAT_POP_PBB,
  ACTION_EXPERIMENTER = 1ULL << 63, // OFPAT_EXPERIMENTER is 0xffff
};

typedef uint64_t action_capabilities;

struct _flow_entry; // FIXME: defined in flow_entry.h. this definition should be eliminated.

typedef struct {
  uint16_t type;
  uint32_t port;
  uint16_t max_len;
  uint32_t group_id;
  uint32_t queue_id;
  uint8_t mpls_ttl;
  uint8_t nw_ttl;
  uint16_t ethertype;
  match *match;
  struct _flow_entry *entry;
} action;

typedef dlist_element action_list;

typedef struct {
  action *copy_ttl_in;
  action *pop_mpls;
  action *pop_pbb;
  action *pop_vlan;
  action *push_mpls;
  action *push_pbb;
  action *push_vlan;
  action *copy_ttl_out;
  action *dec_mpls_ttl;
  action *dec_nw_ttl;
  action *set_mpls_ttl;
  action *set_nw_ttl;
  action *set_field;
  action *set_queue;
  action *group;
  action *output;
} action_set;


action *create_action_output( const uint32_t port, const uint16_t max_len );
action *create_action_group( const uint32_t group_id );
action *create_action_set_queue( const uint32_t queue_id );
action *create_action_set_mpls_ttl( const uint8_t mpls_ttl );
action *create_action_dec_mpls_ttl( void );
action *create_action_set_ipv4_ttl( const uint8_t nw_ttl );
action *create_action_dec_ipv4_ttl( void );
action *create_action_copy_ttl_out( void );
action *create_action_copy_ttl_in( void );
action *create_action_push_vlan( const uint16_t ethertype );
action *create_action_push_mpls( const uint16_t ethertype );
action *create_action_push_pbb( const uint16_t ethertype );
action *create_action_pop_vlan( void );
action *create_action_pop_mpls( const uint16_t ethertype );
action *create_action_pop_pbb( void );
action *create_action_set_field( match *match );
void delete_action( action *action );
action *duplicate_action( const action *action );

action_list *create_action_list( void );
void delete_action_list( action_list *list );
OFDPE append_action( action_list *list, action *action );
OFDPE remove_action( action_list *list, action *action );
action_list *duplicate_action_list( action_list *list );
#define duplicate_actions duplicate_action_list
bool validate_action_set( action_list *list );
OFDPE validate_action_list( action_list *list );
void clear_action_set( action_set *set );
OFDPE write_action_set( action_list *list, action_set *set );

void dump_action_capabilities( const action_capabilities capabilities );
void dump_action( const action *action, void dump_function( const char *format, ... ) );
void dump_action_list( action_list *list, void dump_function( const char *format, ... ) );


#endif // ACTION_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

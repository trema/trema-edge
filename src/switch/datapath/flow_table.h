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


#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H


#include "ofdp_common.h"
#include "action.h"
#include "flow_entry.h"
#include "instruction.h"
#include "match.h"


enum {
  N_FLOW_TABLES = 255,
  FLOW_TABLE_ID_MAX = OFPTT_MAX,
  FLOW_TABLE_ALL = OFPTT_ALL,
};


typedef struct {
  uint8_t table_id;
  char name[ OFP_MAX_TABLE_NAME_LEN ];
  uint64_t metadata_match;
  uint64_t metadata_write;
  uint32_t config;
  uint32_t max_entries;
  instruction_capabilities instructions;
  instruction_capabilities instructions_miss;
  bool next_table_ids[ N_FLOW_TABLES ];
  bool next_table_ids_miss[ N_FLOW_TABLES ];
  action_capabilities write_actions;
  action_capabilities write_actions_miss;
  action_capabilities apply_actions;
  action_capabilities apply_actions_miss;
  match_capabilities matches;
  match_capabilities wildcards;
  match_capabilities write_setfield;
  match_capabilities write_setfield_miss;
  match_capabilities apply_setfield;
  match_capabilities apply_setfield_miss;
} flow_table_features;

typedef struct {
  uint32_t active_count;
  uint64_t lookup_count;
  uint64_t matched_count;
} flow_table_stats;

typedef struct {
  bool initialized;
  list_element *entries;
  flow_table_stats counters;
  flow_table_features features;
} flow_table;

typedef struct ofp_table_stats table_stats;

typedef struct {
  uint8_t table_id;
  uint32_t duration_sec;
  uint32_t duration_nsec;
  uint16_t priority;
  uint16_t idle_timeout;
  uint16_t hard_timeout;
  uint16_t flags;
  uint64_t cookie;
  uint64_t packet_count;
  uint64_t byte_count;
  match match;
  instruction_set instructions;
} flow_stats;


void init_flow_tables( const uint32_t max_flow_entries );
void finalize_flow_tables( void );
OFDPE init_flow_table( const uint8_t table_id, const uint32_t max_flow_entries );
OFDPE finalize_flow_table( const uint8_t table_id );
list_element *lookup_flow_entries( const uint8_t table_id, const match *match );
flow_entry *lookup_flow_entry( const uint8_t table_id, const match *match );
flow_entry *lookup_flow_entry_strict( const uint8_t table_id, const match *match, const uint16_t priority );
OFDPE add_flow_entry( const uint8_t table_id, flow_entry *entry, const uint16_t flags );
OFDPE update_flow_entries( const uint8_t table_id, const match *match, const uint64_t cookie, const uint64_t cookie_mask,
                           const uint16_t flags, instruction_set *instructions );
OFDPE update_flow_entry_strict( const uint8_t table_id, const match *match,
                                const uint64_t cookie, const uint64_t cookie_mask,
                                const uint16_t priority, const uint16_t flags, instruction_set *instructions );
OFDPE update_or_add_flow_entry( const uint8_t table_id, const match *match,
                                const uint64_t cookie, const uint64_t cookie_mask,
                                const uint16_t priority, const uint16_t idle_timeout, const uint16_t hard_timeout,
                                const uint16_t flags, const bool strict, instruction_set *instructions );
OFDPE delete_flow_entries( const uint8_t table_id, const match *match, const uint64_t cookie, const uint64_t cookie_mask,
                           uint32_t out_port, uint32_t out_group );
OFDPE delete_flow_entry_strict( const uint8_t table_id, const match *match, const uint64_t cookie, const uint64_t cookie_mask, 
                                const uint16_t priority, uint32_t out_port, uint32_t out_group );
OFDPE delete_flow_entries_by_group_id( const uint32_t group_id );
OFDPE delete_flow_entries_by_meter_id( const uint32_t meter_id );
OFDPE get_table_stats( table_stats **stats, uint8_t *n_tables );
OFDPE get_flow_stats( const uint8_t table_id, const match *match, const uint64_t cookie, const uint64_t cookie_mask,
                      const uint32_t out_port, const uint32_t out_group, flow_stats **stats, uint32_t *n_entries );
OFDPE set_flow_table_features( const uint8_t table_id, const flow_table_features *features );
OFDPE get_flow_table_features( const uint8_t table_id, flow_table_features *stats );
OFDPE set_flow_table_config( const uint8_t table_id, const uint32_t config );
OFDPE get_flow_table_config( const uint8_t table_id, uint32_t *config );
bool valid_table_id( const uint8_t table_id );
void dump_flow_table( const uint8_t table_id, void dump_function( const char *format, ... ) );
void dump_flow_tables( void dump_function( const char *format, ... ) );


#endif // FLOW_TABLE_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

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


#ifndef GROUP_TABLE_H
#define GROUP_TABLE_H


#include "ofdp_common.h"
#include "action.h"
#include "action_bucket.h"
#include "group_entry.h"
#include "switch_port.h"


enum {
  GROUP_TYPE_ALL = 1 << OFPGT_ALL,
  GROUP_TYPE_SELECT = 1 << OFPGT_SELECT,
  GROUP_TYPE_INDIRECT = 1 << OFPGT_INDIRECT,
  GROUP_TYPE_FF = 1 << OFPGT_FF,
};


typedef struct {
  uint32_t types;
  uint32_t capabilities;
  uint32_t max_groups[ 4 ];
  action_capabilities actions[ 4 ];
} group_table_features;

typedef struct {
  bool initialized;
  list_element *entries;
  group_table_features features;
} group_table;

typedef struct {
  uint32_t group_id;
  uint32_t ref_count;
  uint64_t packet_count;
  uint64_t byte_count;
  uint32_t duration_sec;
  uint32_t duration_nsec;
  list_element *bucket_stats;
} group_stats;

typedef struct {
  uint8_t type;
  uint32_t group_id;
  bucket_list *buckets;
} group_desc;


void init_group_table( void );
void finalize_group_table( void );
group_entry *lookup_group_entry( const uint32_t group_id );
OFDPE add_group_entry( group_entry *entry );
OFDPE update_group_entry( const uint32_t group_id, const uint8_t type, bucket_list *buckets );
OFDPE delete_group_entry( const uint32_t group_id );
bool group_exists( const uint32_t group_id );
OFDPE get_group_stats( const uint32_t group_id, group_stats **stats, uint32_t *n_groups );
OFDPE get_group_desc( group_desc **stats, uint16_t *n_groups );
OFDPE get_group_features( group_table_features *features );
OFDPE set_group_features( group_table_features *features );
void increment_reference_count( const uint32_t group_id );
void decrement_reference_count( const uint32_t group_id );
void dump_group_table( void dump_function( const char *format, ... ) );


#endif // GROUP_TABLE_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/

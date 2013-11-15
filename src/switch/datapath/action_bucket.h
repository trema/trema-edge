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


#ifndef ACTION_BUCKET_H
#define ACTION_BUCKET_H


#include "ofdp_common.h"
#include "action.h"


typedef struct bucket {
  uint16_t weight;
  uint32_t watch_port;
  uint32_t watch_group;
  uint64_t packet_count;
  uint64_t byte_count;
  action_list *actions;
} bucket;

typedef dlist_element bucket_list;
typedef struct ofp_bucket_counter bucket_counter;


bucket *create_action_bucket( const uint16_t weight, const uint32_t watch_port, const uint32_t watch_group, action_list *actions );
void delete_action_bucket( bucket *bucket );
bucket_list *create_action_bucket_list( void );
void delete_action_bucket_list( bucket_list *list );
OFDPE append_action_bucket( bucket_list *list, bucket *bucket );
OFDPE remove_action_bucket( bucket_list *list, bucket *bucket );
OFDPE validate_action_bucket( const bucket *bucket );
OFDPE validate_action_bucket_list( bucket_list *buckets );
uint32_t get_bucket_count( bucket_list *list );
#define get_action_bucket_count get_bucket_count
bucket *duplicate_bucket( const bucket *src );
#define duplicate_action_bucket duplicate_bucket
bucket_list *duplicate_bucket_list( bucket_list *buckets );
#define duplicate_buckets duplicate_bucket_list
#define duplicate_action_buckets duplicate_bucket_list
#define duplicate_action_bucket_list duplicate_bucket_list
void dump_buckets( bucket_list *buckets, void dump_function( const char *format, ... ) );


#endif // ACTION_BUCKET_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/

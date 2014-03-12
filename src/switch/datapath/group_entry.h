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


#ifndef GROUP_ENTRY_H
#define GROUP_ENTRY_H


#include "ofdp_common.h"
#include "action_bucket.h"


typedef struct {
  uint8_t type;
  uint32_t group_id;
  uint32_t ref_count;
  uint64_t packet_count;
  uint64_t byte_count;
  uint32_t duration_sec;
  uint32_t duration_nsec;
  bucket_list *buckets;
  struct timespec created_at;
} group_entry;


group_entry *alloc_group_entry( const uint8_t type, const uint32_t group_id, bucket_list *buckets );
void free_group_entry( group_entry *entry );
bool valid_group_id( const uint32_t id );
bool valid_group_type( const uint8_t type );
void dump_group_entry( const group_entry *entry, void dump_function( const char *format, ... ) );


#endif // GROUP_ENTRY_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/

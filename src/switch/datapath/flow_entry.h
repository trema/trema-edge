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


#ifndef FLOW_ENTRY_H
#define FLOW_ENTRY_H


#include "ofdp_common.h"
#include "instruction.h"
#include "match.h"


typedef struct _flow_entry {
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
  match *match;
  instruction_set *instructions;
  struct timespec created_at;
  struct timespec last_seen;
  bool table_miss;
} flow_entry;


flow_entry *alloc_flow_entry( match *match, instruction_set *instructions,
                              const uint16_t priority, const uint16_t idle_timeout, const uint16_t hard_timeout,
                              const uint16_t flags, const uint64_t cookie );
void free_flow_entry( flow_entry *entry );
void dump_flow_entry( const flow_entry *entry, void dump_function( const char *format, ... ) );


#endif // FLOW_ENTRY_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

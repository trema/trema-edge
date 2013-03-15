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


#include "trema.h"
#include "ruby.h"
#include "action-common.h"
#include "conversion-util.h"
#include "hash-util.h"


buffer *
pack_flow_mod( VALUE options ) {
  uint32_t xid = get_transaction_id();
  VALUE r_xid = HASH_REF( options, transaction_id );
  if ( !NIL_P( r_xid ) ) {
    xid = NUM2UINT( r_xid );
  }

  uint64_t cookie = get_cookie();
  VALUE r_cookie = HASH_REF( options, cookie );
  if ( !NIL_P( r_cookie ) ) {
    cookie = ( uint64_t ) NUM2ULL( r_cookie );
  }

  uint64_t cookie_mask = 0;
  VALUE r_cookie_mask = HASH_REF( options, cookie_mask );
  if ( !NIL_P( r_cookie_mask ) ) {
    cookie_mask = ( uint64_t ) NUM2ULL( r_cookie_mask );
  }

  uint8_t table_id = 0;
  VALUE r_table_id = HASH_REF( options, table_id );
  if ( !NIL_P( r_table_id ) ) {
    table_id = ( uint8_t ) NUM2UINT( r_table_id );
  }

  uint8_t command = OFPFC_ADD;
  VALUE r_command = HASH_REF( options, command );
  if ( !NIL_P( r_command ) ) {
    command = ( uint8_t ) NUM2UINT( r_command );
  }

  uint16_t idle_timeout = 0;
  VALUE r_idle_timeout = HASH_REF( options, idle_timeout );
  if ( !NIL_P( r_idle_timeout ) ) {
    idle_timeout = ( uint16_t ) NUM2UINT( r_idle_timeout );
  }

  uint16_t hard_timeout = 0;
  VALUE r_hard_timeout = HASH_REF( options, hard_timeout );
  if ( !NIL_P( r_hard_timeout ) ) {
    hard_timeout = ( uint16_t ) NUM2UINT( r_hard_timeout );
  }

  uint16_t priority = 0;
  VALUE r_priority = HASH_REF( options, priority );
  if ( !NIL_P( r_priority ) ) {
    priority = ( uint16_t ) NUM2UINT( r_priority );
  }

  uint32_t buffer_id = OFP_NO_BUFFER;
  VALUE r_buffer_id = HASH_REF( options, buffer_id );
  if ( !NIL_P( r_buffer_id ) ) {
    buffer_id = NUM2UINT( r_buffer_id );
  }

  uint32_t out_port = 0;
  VALUE r_out_port = HASH_REF( options, out_port );
  if ( !NIL_P( r_out_port ) ) {
    out_port = NUM2UINT( r_out_port );
  }

  uint32_t out_group = 0;
  VALUE r_out_group = HASH_REF( options, out_group );
  if ( !NIL_P( r_out_group ) ) {
    out_group = NUM2UINT( r_out_group );
  }

  uint16_t flags = 0;
  VALUE r_flags = HASH_REF( options, flags );
  if ( !NIL_P( r_flags ) ) {
    flags = ( uint16_t ) NUM2UINT( r_flags );
  }

  VALUE r_match = HASH_REF( options, match );
  oxm_matches *oxm_match = NULL;
  if ( !NIL_P( r_match ) ) {
    oxm_match = create_oxm_matches();
    r_match_to_oxm_match( r_match, oxm_match );
  }
  
  openflow_instructions *instructions = NULL;
	VALUE r_instructions = HASH_REF( options, instructions );
  if ( !NIL_P( r_instructions ) ) {
    instructions = pack_instruction( r_instructions );
  }
  buffer *flow_mod = create_flow_mod( xid, cookie, cookie_mask,
                                      table_id, command, idle_timeout,
                                      hard_timeout, priority, buffer_id,
                                      out_port, out_group, flags,
                                      oxm_match, instructions );
  if ( instructions != NULL ) {
    delete_instructions( instructions );
  }
  if (oxm_match != NULL ) {
    delete_oxm_matches( oxm_match );
  }

  return flow_mod;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

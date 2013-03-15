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
#include "hash-util.h"
#include "conversion-util.h"


buffer *
pack_aggregate_multipart_request( VALUE options ) {
  uint32_t xid = get_transaction_id();
  VALUE r_xid = HASH_REF( options, transaction_id );
  if ( !NIL_P( r_xid ) ) {
    xid = NUM2UINT( r_xid );
  }
  
  uint16_t flags = 0;
  VALUE r_flags = HASH_REF( options, flags );
  if ( !NIL_P( r_flags )  ) {
    flags = ( uint16_t ) NUM2UINT( r_flags );
  }

  uint8_t table_id = OFPTT_ALL;
  VALUE r_table_id = HASH_REF( options, table_id );
  if ( !NIL_P( r_table_id ) ) {
    table_id = ( uint8_t ) NUM2UINT( r_table_id );
  }
  
  uint32_t out_port = OFPP_ANY;
  VALUE r_out_port = HASH_REF( options, out_port );
  if ( !NIL_P( r_out_port ) ) {
    out_port = NUM2UINT( r_out_port );
  }

  uint32_t out_group = OFPG_ANY;
  VALUE r_out_group = HASH_REF( options, out_group );
  if ( !NIL_P( r_out_group ) ) {
    out_group = NUM2UINT( r_out_group );
  }

  uint64_t cookie = 0;
  VALUE r_cookie = HASH_REF( options, cookie );
  if ( !NIL_P( r_cookie ) ) {
    cookie = ( uint64_t ) NUM2ULL( r_cookie );
  }

  uint64_t cookie_mask = 0;
  VALUE r_cookie_mask = HASH_REF( options, cookie_mask );
  if ( !NIL_P( r_cookie_mask ) ) {
    cookie_mask = ( uint64_t ) NUM2ULL( r_cookie_mask );
  }

  
  VALUE r_match = HASH_REF( options, match );
  oxm_matches *oxm_match = NULL;
  if ( !NIL_P( r_match ) ) {
    oxm_match = create_oxm_matches();
    r_match_to_oxm_match( r_match, oxm_match );
  }

  buffer *aggregate_multipart_request = create_aggregate_multipart_request( xid, flags, table_id,
                                                                            out_port, out_group, cookie,
                                                                            cookie_mask, oxm_match );
  if ( oxm_match != NULL ) {
    delete_oxm_matches( oxm_match );
  }

  return aggregate_multipart_request;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

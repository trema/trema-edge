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
#include "bucket-helper.h"
#include "hash-util.h"


buffer *
pack_group_mod( VALUE options ) {
  uint32_t xid = get_transaction_id();
  VALUE r_xid = HASH_REF( options, transaction_id );
  if ( !NIL_P( r_xid ) ) {
    xid = NUM2UINT( r_xid );
  }

  uint8_t group_type = OFPGT_ALL;
  VALUE r_group_type = HASH_REF( options, type );
  if ( !NIL_P( r_group_type ) ) {
    group_type = ( uint8_t ) NUM2UINT( r_group_type );
  }

  uint32_t group_id = 0;
  VALUE r_group_id = HASH_REF( options, group_id );
  if ( !NIL_P( r_group_id ) ) {
    group_id = ( uint32_t ) NUM2UINT( r_group_id );
  }

  uint16_t command = OFPGC_ADD;
  VALUE r_command = HASH_REF( options, command );
  if ( !NIL_P( r_command ) ) {
    command = ( uint16_t ) NUM2UINT( r_command );
  }

  openflow_buckets *buckets = NULL;
  VALUE r_bucket = HASH_REF( options, buckets );
  if ( !NIL_P( r_bucket ) ) {
    buckets = pack_buckets( r_bucket );
  }
  buffer *group_mod = create_group_mod( xid, command, group_type,
                                        group_id, buckets );
  if ( buckets != NULL ) {
    delete_buckets( buckets );
  }
  return group_mod;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

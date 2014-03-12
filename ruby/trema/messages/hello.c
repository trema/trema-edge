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


buffer *
pack_hello( VALUE options ) {
  uint32_t xid = get_transaction_id();
  VALUE r_xid = HASH_REF( options, transaction_id );
  if ( !NIL_P( r_xid ) ) {
    xid = NUM2UINT( r_xid );
  }

  VALUE r_version = HASH_REF( options, version );
  uint8_t ofp_version[ 1 ];
  if ( !NIL_P( r_version ) ) {
    if ( rb_obj_is_kind_of( r_version, rb_cArray ) )  {
      if ( RARRAY_LEN( r_version ) > 1 ) {
        rb_raise(rb_eArgError, "Currently only a single version is supported" );
      }
      else {
        ofp_version[ 0 ] = ( uint8_t ) NUM2UINT( rb_ary_entry( r_version , 0 ) );
      }
    }
  }
  else {
    ofp_version[ 0 ] = OFP_VERSION;
  }

  buffer *element = create_hello_elem_versionbitmap( ofp_version, sizeof( ofp_version ) / sizeof( ofp_version[ 0 ] ) );
  buffer *hello = create_hello( xid, element );
  free_buffer( element );

  return hello;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

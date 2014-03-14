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
pack_experimenter_multipart_request( VALUE options ) {
  uint32_t xid = get_transaction_id();
  VALUE r_xid = HASH_REF( options, transaction_id );
  if ( !NIL_P( r_xid ) ) {
    xid = NUM2UINT( r_xid );
  }

  uint16_t flags = 0;
  VALUE r_flags = HASH_REF( options, flags );
  if ( !NIL_P( r_flags ) ) {
    flags = ( uint16_t ) NUM2UINT( r_flags );
  }

  uint32_t experimenter = 0;
  VALUE r_experimenter = HASH_REF( options, experimenter );
  if ( !NIL_P( r_experimenter ) ) {
    experimenter = NUM2UINT( r_experimenter );
  }

  uint32_t exp_type = 0;
  VALUE r_exp_type = HASH_REF( options, exp_type );
  if ( !NIL_P( r_exp_type ) ) {
    exp_type = NUM2UINT( r_exp_type );
  }

  VALUE r_body = HASH_REF( options, user_data );
  buffer *body = NULL;
  if ( !NIL_P( r_body ) ) {
    if ( TYPE( r_body ) == T_ARRAY ) {
      uint16_t buffer_len = ( uint16_t ) RARRAY_LEN( r_body );

      body = alloc_buffer_with_length( ( size_t ) RARRAY_LEN( r_body ) );
      append_back_buffer( body, buffer_len );
      uint8_t *buf = body->data;

        
      for ( int i = 0; i < buffer_len && i < RARRAY_LEN( r_body ); i++ ) {
        buf[ i ]= ( uint8_t ) FIX2INT( rb_ary_entry( r_body , i ) );
      }
    }
    else {
      rb_raise( rb_eTypeError, "experimenter user data must be specified as an array of bytes" );
    }
  }
  buffer *experimenter_multipart_request = create_experimenter_multipart_request( xid, flags, experimenter, exp_type, body );

  return experimenter_multipart_request;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

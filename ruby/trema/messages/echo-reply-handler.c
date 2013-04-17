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


void
handle_echo_reply( uint64_t datapath_id,
                   uint32_t transaction_id,
                   const buffer *data,
                   void *controller ) {
  if ( !rb_respond_to( ( VALUE ) controller, rb_intern( "echo_reply" ) ) ) {
    return;
  }
  VALUE attributes = rb_hash_new();
  HASH_SET( attributes, "transaction_id", UINT2NUM( transaction_id ) );
  VALUE r_user_data = buffer_to_r_array( data );
  if ( !NIL_P( r_user_data ) ) {
    HASH_SET( attributes, "user_data", r_user_data );
  }
  VALUE r_echo_reply = rb_funcall( rb_eval_string( "Messages::EchoReply" ), rb_intern( "new" ), 1, attributes );
  rb_funcall( ( VALUE ) controller, rb_intern( "echo_reply" ), 2, ULL2NUM( datapath_id ), r_echo_reply );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

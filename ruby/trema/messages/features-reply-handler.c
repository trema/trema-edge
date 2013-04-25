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


void
handle_features_reply( uint64_t datapath_id,
                       uint32_t transaction_id,
                       uint32_t n_buffers,
                       uint8_t n_tables,
                       uint8_t auxiliary_id,
                       uint32_t capabilities,
                       void *controller ) {
  if ( !rb_respond_to( ( VALUE ) controller, rb_intern( "features_reply" ) ) ) {
    return;
  }
  VALUE r_attributes = rb_hash_new();
  HASH_SET( r_attributes, "transaction_id", UINT2NUM( transaction_id ) );
  HASH_SET( r_attributes, "n_buffers", UINT2NUM( n_buffers ) );
  HASH_SET( r_attributes, "n_tables", UINT2NUM( n_tables ) );
  HASH_SET( r_attributes, "auxiliary_id", UINT2NUM( auxiliary_id ) );
  HASH_SET( r_attributes, "capabilities", UINT2NUM( capabilities ) );
  VALUE r_features_reply = rb_funcall( rb_eval_string( "Messages::FeaturesReply" ), rb_intern( "new" ), 1, r_attributes );
  rb_funcall( ( VALUE ) controller, rb_intern( "features_reply" ), 2, ULL2NUM( datapath_id ), r_features_reply );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

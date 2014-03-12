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


static bool
pack_bucket( VALUE r_bucket, openflow_buckets *buckets ) {
  VALUE r_actions = rb_iv_get( r_bucket, "@actions" );
  openflow_actions *actions = NULL;
  if ( !NIL_P( r_actions ) ) {
    actions = pack_basic_action( r_actions );
  }
  VALUE r_weight = rb_iv_get( r_bucket, "@weight" );
  uint16_t weight = 0;
  if ( !NIL_P( r_weight ) ) {
    weight = ( uint16_t ) NUM2UINT( r_weight );
  }

  VALUE r_watch_port = rb_iv_get( r_bucket, "@watch_port" );
  uint32_t watch_port = 0;
  if ( !NIL_P( r_watch_port ) ) {
    watch_port = ( uint32_t ) NUM2UINT( r_watch_port );
  }

  VALUE r_watch_group = rb_iv_get( r_bucket, "@watch_group" );
  uint32_t watch_group = 0;
  if ( !NIL_P( r_watch_group ) ) {
    watch_group = ( uint32_t ) NUM2UINT( r_watch_group );
  }

  return append_bucket( buckets, weight, watch_port, watch_group, actions );
}


openflow_buckets *
pack_buckets( VALUE r_bucket ) {
  openflow_buckets *buckets = create_buckets();

  if ( !NIL_P( r_bucket ) ) {
    switch ( TYPE( r_bucket ) ) {
      case T_ARRAY: {
        for ( int i = 0; i < RARRAY_LEN( r_bucket ); i++ ) {
          pack_bucket( rb_ary_entry( r_bucket, i ), buckets );
        }
      }
      break;
      case T_OBJECT:
        if ( rb_respond_to( rb_obj_class( r_bucket ), rb_intern( "pack_bucket" ) ) ) {
          pack_bucket( r_bucket, buckets );
        }
      break;
      default:
        rb_raise( rb_eTypeError, "Bucket argument must be either an Array or a Bucket object" );
      break;
    }
  }

  return buckets;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

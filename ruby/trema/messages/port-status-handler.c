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
#include "unpack-util.h"


void
handle_port_status( uint64_t datapath_id,
  uint32_t transaction_id,
  uint8_t reason,
  struct ofp_port port_desc,
  void *controller ) {
  if ( !rb_respond_to( ( VALUE ) controller, rb_intern( "port_status" ) ) ) {
    return;
  }
  VALUE r_attributes = rb_hash_new();
  HASH_SET( r_attributes, "datapath_id", ULL2NUM( datapath_id ) );
  HASH_SET( r_attributes, "transaction_id", UINT2NUM( transaction_id ) );
  HASH_SET( r_attributes, "reason", UINT2NUM( reason ) );
  
  unpack_port( &port_desc, r_attributes );
  VALUE cPortStatus = rb_funcall( rb_eval_string( "Messages::PortStatus" ), rb_intern( "new" ), 1, r_attributes );
  rb_funcall( ( VALUE ) controller, rb_intern( "port_status" ), 2, ULL2NUM( datapath_id ), cPortStatus );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

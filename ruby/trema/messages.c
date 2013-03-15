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
#include "messages/hello.h"
#include "messages/echo-request.h"
#include "messages/features-request.h"
#include "messages/get-config-request.h"
#include "messages/set-config.h"
#include "messages/flow-mod.h"
#include "messages/group-mod.h"
#include "messages/flow-multipart-request.h"
#include "messages/desc-multipart-request.h"
#include "messages/aggregate-multipart-request.h"
#include "messages/table-multipart-request.h"
#include "messages/port-multipart-request.h"
#include "messages/port-desc-multipart-request.h"
#include "messages/table-features-multipart-request.h"
#include "messages/group-multipart-request.h"
#include "messages/group-desc-multipart-request.h"
#include "messages/port-desc-multipart-request.h"
#include "messages/barrier-request.h"


extern VALUE mTrema;
VALUE mMessages;


static uint64_t
datapath_id( VALUE options ) {
  VALUE r_dpid = HASH_REF( options, datapath_id );
  return NUM2ULL( r_dpid );
}


#define PACK_MSG( type, self, options )      \
  do {                                       \
    buffer *msg = pack_##type( options );    \
    send_msg( datapath_id( options ), msg ); \
    return self;                             \
  } while( 0 )


static void
send_msg( uint64_t datapath_id, buffer *msg ) {
  send_openflow_message( datapath_id, msg );
  free_buffer( msg );
}


static VALUE
pack_hello_msg( VALUE self, VALUE options ) {
  PACK_MSG( hello, self, options );
}


static VALUE
pack_echo_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( echo_request, self, options );
}


static VALUE
pack_features_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( features_request, self, options );
  return self;
}


static VALUE
pack_get_config_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( get_config_request, self, options );
}


static VALUE
pack_set_config_msg( VALUE self, VALUE options ) {
  PACK_MSG( set_config, self, options );
}


static VALUE
pack_flow_mod_msg( VALUE self, VALUE options ) {
  PACK_MSG( flow_mod, self, options );
}


static VALUE
pack_group_mod_msg( VALUE self, VALUE options ) {
  PACK_MSG( group_mod, self, options );
}


static VALUE
pack_flow_multipart_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( flow_multipart_request, self, options );
}


static VALUE
pack_desc_multipart_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( desc_multipart_request, self, options );
}


static VALUE
pack_aggregate_multipart_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( aggregate_multipart_request, self, options );
}


static VALUE
pack_table_multipart_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( table_multipart_request, self, options );
}


static VALUE
pack_port_multipart_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( port_multipart_request, self, options );
}


static VALUE
pack_port_desc_multipart_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( port_desc_multipart_request, self, options );
}


static VALUE
pack_table_features_multipart_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( table_features_multipart_request, self, options );
}


static VALUE
pack_group_multipart_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( group_multipart_request, self, options );
}


static VALUE
pack_group_desc_multipart_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( group_desc_multipart_request, self, options );
}


static VALUE
pack_barrier_request_msg( VALUE self, VALUE options ) {
  PACK_MSG( barrier_request, self, options );
}


void
Init_messages( void ) {
  mMessages = rb_define_module_under( mTrema, "Messages" );
  rb_define_module_function( mMessages, "pack_hello_msg", pack_hello_msg, 1 );
  rb_define_module_function( mMessages, "pack_echo_request_msg", pack_echo_request_msg, 1 );
  rb_define_module_function( mMessages, "pack_features_request_msg", pack_features_request_msg, 1 );
  rb_define_module_function( mMessages, "pack_get_config_request_msg", pack_get_config_request_msg, 1 );
  rb_define_module_function( mMessages, "pack_set_config_msg", pack_set_config_msg, 1 );
  rb_define_module_function( mMessages, "pack_flow_mod_msg", pack_flow_mod_msg, 1 );
  rb_define_module_function( mMessages, "pack_group_mod_msg", pack_group_mod_msg, 1 );
  rb_define_module_function( mMessages, "pack_flow_multipart_request_msg", pack_flow_multipart_request_msg, 1 );
  rb_define_module_function( mMessages, "pack_desc_multipart_request_msg", pack_desc_multipart_request_msg, 1 );
  rb_define_module_function( mMessages, "pack_aggregate_multipart_request_msg", pack_aggregate_multipart_request_msg, 1 );
  rb_define_module_function( mMessages, "pack_table_multipart_request_msg", pack_table_multipart_request_msg, 1 );
  rb_define_module_function( mMessages, "pack_port_multipart_request_msg", pack_port_multipart_request_msg, 1 );
  rb_define_module_function( mMessages, "pack_port_desc_multipart_request_msg", pack_port_desc_multipart_request_msg, 1 );
  rb_define_module_function( mMessages, "pack_table_features_multipart_request_msg", pack_table_features_multipart_request_msg, 1 );
  rb_define_module_function( mMessages, "pack_group_multipart_request_msg", pack_group_multipart_request_msg, 1 );
  rb_define_module_function( mMessages, "pack_group_desc_multipart_request_msg", pack_group_desc_multipart_request_msg, 1 );
  rb_define_module_function( mMessages, "pack_barrier_request_msg", pack_barrier_request_msg, 1 );

  rb_require( "trema/messages" );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

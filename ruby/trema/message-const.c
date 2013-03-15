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


extern VALUE mTrema;
VALUE mMessageConst;


static VALUE
frag_normal( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPC_FRAG_NORMAL );
}


static VALUE
frag_drop( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPC_FRAG_DROP );
}


static VALUE
frag_reasm( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPC_FRAG_REASM );
}


static VALUE
frag_mask( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPC_FRAG_MASK );
}


static VALUE
controller_port( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPP_CONTROLLER );
}


static VALUE
max_port( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPP_MAX );
}


static VALUE
in_port( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPP_IN_PORT );
}


static VALUE
table_port( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPP_TABLE );
}


static VALUE
normal_port( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPP_NORMAL );
}


static VALUE
flood_port( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPP_FLOOD );
}


static VALUE
all_ports( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPP_ALL );
}


static VALUE
local_port( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPP_LOCAL );
}


static VALUE
any_port( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPP_ANY );
}


static VALUE
controller_max_len_max( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPCML_MAX );
}


static VALUE
controller_max_len_no_buffer( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPCML_NO_BUFFER );
}


static VALUE
no_buffer( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFP_NO_BUFFER );
}


static VALUE
default_priority( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFP_DEFAULT_PRIORITY );
}


static VALUE
high_priority( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFP_HIGH_PRIORITY );
}


static VALUE
low_priority( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFP_LOW_PRIORITY );
}


static VALUE
port_add( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPPR_ADD );
}


static VALUE
port_delete( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPPR_DELETE );
}


static VALUE
port_modify( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPPR_MODIFY );
}


static VALUE
experimenter_error( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPET_EXPERIMENTER );
}


static VALUE
experimenter_mp( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPMP_EXPERIMENTER );
}


static VALUE
at_output( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_OUTPUT );
}
  

static VALUE
at_copy_ttl_out( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_COPY_TTL_OUT );
}


static VALUE
at_copy_ttl_in( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_COPY_TTL_IN );
}


static VALUE
at_set_mpls_ttl( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_SET_MPLS_TTL );
}


static VALUE
at_dec_mpls_ttl( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_DEC_MPLS_TTL );
}


static VALUE
at_push_vlan( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_PUSH_VLAN );
}


static VALUE
at_pop_vlan( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_POP_VLAN );
}


static VALUE
at_push_mpls( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_PUSH_MPLS );
}


static VALUE
at_pop_mpls( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_POP_MPLS );
}


static VALUE
at_set_queue( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_SET_QUEUE );
}


static VALUE
at_group( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_GROUP );
}


static VALUE
at_set_nw_ttl( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_SET_NW_TTL );
}


static VALUE
at_dec_nw_ttl( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_DEC_NW_TTL );
}


static VALUE
at_set_field( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_SET_FIELD );
}


static VALUE
at_push_pbb( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_PUSH_PBB );
}


static VALUE
at_pop_pbb( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_POP_PBB );
}


static VALUE
at_experimenter( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPAT_EXPERIMENTER );
}


static VALUE
it_experimenter( VALUE self ) {
  UNUSED( self );
  return UINT2NUM( OFPIT_EXPERIMENTER );
}


void
Init_message_const( void ) {
  mMessageConst = rb_define_module_under( mTrema, "MessageConst" );

  rb_define_module_function( mMessageConst, "frag_normal", frag_normal, 0 );
  rb_define_module_function( mMessageConst, "frag_drop", frag_drop, 0 );
  rb_define_module_function( mMessageConst, "frag_reasm", frag_reasm, 0 );
  rb_define_module_function( mMessageConst, "frag_mask", frag_mask, 0 );

  // ofp_ports
  rb_define_module_function( mMessageConst, "max_port", max_port, 0 );
  rb_define_module_function( mMessageConst, "in_port", in_port, 0 );
  rb_define_module_function( mMessageConst, "table_port", table_port, 0 );
  rb_define_module_function( mMessageConst, "normal_port", normal_port, 0 );
  rb_define_module_function( mMessageConst, "flood_port", flood_port, 0 );
  rb_define_module_function( mMessageConst, "all_ports", all_ports, 0 );
  rb_define_module_function( mMessageConst, "controller_port", controller_port, 0 );
  rb_define_module_function( mMessageConst, "local_port", local_port, 0 );
  rb_define_module_function( mMessageConst, "any_port", any_port, 0 );

  // controller_max_length
  rb_define_module_function( mMessageConst, "controller_max_len_max", controller_max_len_max, 0 );
  rb_define_module_function( mMessageConst, "controller_max_len_no_buffer", controller_max_len_no_buffer, 0 );

  // OFP_NO_BUFFER constant
  rb_define_module_function( mMessageConst, "no_buffer", no_buffer, 0 );

  // OFP_PRIORITY values
  rb_define_module_function( mMessageConst, "default_priority", default_priority, 0 );
  rb_define_module_function( mMessageConst, "high_priority", high_priority, 0 );
  rb_define_module_function( mMessageConst, "low_priority", low_priority, 0 );

  // ofp_port_reason
  rb_define_module_function( mMessageConst, "port_add" , port_add, 0 );
  rb_define_module_function( mMessageConst, "port_delete" , port_delete, 0 );
  rb_define_module_function( mMessageConst, "port_modify" , port_modify, 0 );

  // experimental error code
  rb_define_module_function( mMessageConst, "experimenter_error", experimenter_error, 0 );

  rb_define_module_function( mMessageConst, "experimenter_mp", experimenter_mp, 0 );

  // action_types
  rb_define_module_function( mMessageConst, "at_output", at_output, 0 );
  rb_define_module_function( mMessageConst, "at_copy_ttl_out", at_copy_ttl_out, 0 );
  rb_define_module_function( mMessageConst, "at_copy_ttl_in", at_copy_ttl_in, 0 );
  rb_define_module_function( mMessageConst, "at_set_mpls_ttl", at_set_mpls_ttl, 0 );
  rb_define_module_function( mMessageConst, "at_dec_mpls_ttl", at_dec_mpls_ttl, 0 );
  rb_define_module_function( mMessageConst, "at_push_vlan", at_push_vlan, 0 );
  rb_define_module_function( mMessageConst, "at_pop_vlan", at_pop_vlan, 0 );
  rb_define_module_function( mMessageConst, "at_push_mpls", at_push_mpls, 0 );
  rb_define_module_function( mMessageConst, "at_pop_mpls", at_pop_mpls, 0 );
  rb_define_module_function( mMessageConst, "at_set_queue", at_set_queue, 0 );
  rb_define_module_function( mMessageConst, "at_group", at_group, 0 );
  rb_define_module_function( mMessageConst, "at_set_nw_ttl", at_set_nw_ttl, 0 );
  rb_define_module_function( mMessageConst, "at_dec_nw_ttl", at_dec_nw_ttl, 0 );
  rb_define_module_function( mMessageConst, "at_set_field", at_set_field, 0 );
  rb_define_module_function( mMessageConst, "at_push_pbb", at_push_pbb, 0 );
  rb_define_module_function( mMessageConst, "at_pop_pbb", at_pop_pbb, 0 );
  rb_define_module_function( mMessageConst, "at_experimenter", at_experimenter, 0 );
                        
  // experimenter instruction type
  rb_define_module_function( mMessageConst, "it_experimenter", it_experimenter, 0 );

  rb_require( "trema/message-const" );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

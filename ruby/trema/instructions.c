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
#include "hash-util.h"


extern VALUE mTrema;
VALUE mInstructions;


static openflow_instructions *
instructions_ptr( VALUE self ) {
  openflow_instructions *instructions;
  Data_Get_Struct( self, openflow_instructions, instructions );
  return instructions;
}


static VALUE
pack_goto_table_instruction( VALUE self, VALUE r_instructions, VALUE r_options ) {
  VALUE r_table_id = HASH_REF( r_options, table_id );
  append_instructions_goto_table( instructions_ptr( r_instructions ), ( uint8_t ) NUM2UINT( r_table_id ) ); 
  return self;
}


static VALUE
pack_write_metadata_instruction( VALUE self, VALUE r_instructions, VALUE r_options ) {
  VALUE r_metadata = HASH_REF( r_options, metadata );
  uint64_t metadata_mask = 0;
  VALUE r_metadata_mask = HASH_REF( r_options, metadata_mask );

  if ( !NIL_P( r_metadata_mask ) ) {
    metadata_mask = ( uint64_t ) NUM2ULL( r_metadata_mask );
  }
  append_instructions_write_metadata( instructions_ptr( r_instructions ), ( uint64_t ) NUM2ULL( r_metadata ), metadata_mask );
  return self;
}


static VALUE
pack_write_action_instruction( VALUE self, VALUE r_instructions, VALUE r_options ) {
  VALUE basic_actions = HASH_REF( r_options, actions );
  openflow_actions *actions = pack_basic_action( basic_actions );
  append_instructions_write_actions( instructions_ptr( r_instructions ), actions );
  return self;
}


static VALUE
pack_apply_action_instruction( VALUE self, VALUE r_instructions, VALUE r_options ) {
  VALUE action_list = HASH_REF( r_options, actions );
  openflow_actions *actions = pack_basic_action( action_list );
  append_instructions_apply_actions( instructions_ptr( r_instructions ), actions );
  return self;
}


static VALUE
pack_clear_action_instruction( VALUE self, VALUE r_instruction, VALUE r_options ) {
  UNUSED( r_options );
  append_instructions_clear_actions( instructions_ptr( r_instruction ) );
  return self;
}


static VALUE
pack_meter_instruction( VALUE self, VALUE r_instructions, VALUE r_options ) {
  VALUE r_meter = HASH_REF( r_options, meter );
  append_instructions_meter( instructions_ptr( r_instructions ), NUM2UINT( r_meter ) );
  return self;
}


static VALUE
pack_experimenter_instruction( VALUE self, VALUE r_instructions, VALUE r_options ) {
  VALUE r_experimenter = HASH_REF( r_options, experimenter );
  VALUE r_user_data = Qnil;

  if ( ( r_user_data = HASH_REF( r_options, user_data ) ) != Qnil ) {
    Check_Type( r_user_data, T_ARRAY );
    uint16_t length = ( uint16_t ) RARRAY_LEN( r_user_data );
    buffer *user_data = alloc_buffer_with_length( length );
    void *p = append_back_buffer( user_data, length );
    for ( int i = 0; i < length; i++ ) {
      ( ( uint8_t * ) p )[ i ] = ( uint8_t ) FIX2INT( rb_ary_entry( r_user_data , i ) );
    }
    append_instructions_experimenter( instructions_ptr( r_instructions ), NUM2UINT( r_experimenter ), user_data );
    free_buffer( user_data );
  }
  else {
    append_instructions_experimenter( instructions_ptr( r_instructions ), NUM2UINT( r_experimenter ), NULL );
  }

  return self;
}


void
Init_instructions( void ) {
  mInstructions = rb_define_module_under( mTrema, "Instructions" );

  rb_define_module_function( mInstructions, "pack_goto_table_instruction", pack_goto_table_instruction, 2 );
  rb_define_module_function( mInstructions, "pack_write_metadata_instruction", pack_write_metadata_instruction, 2 );
  rb_define_module_function( mInstructions, "pack_write_action_instruction", pack_write_action_instruction, 2 );
  rb_define_module_function( mInstructions, "pack_apply_action_instruction", pack_apply_action_instruction, 2 );
  rb_define_module_function( mInstructions, "pack_clear_action_instruction", pack_clear_action_instruction, 2 );
  rb_define_module_function( mInstructions, "pack_meter_instruction", pack_meter_instruction, 2 );
  rb_define_module_function( mInstructions, "pack_experimenter_instruction", pack_experimenter_instruction, 2 );
  rb_require( "trema/instructions" );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

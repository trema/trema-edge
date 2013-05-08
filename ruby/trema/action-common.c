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


#include <stdint.h>
#include "trema.h"
#include "ruby.h"


uint32_t
nw_addr_to_i( VALUE nw_addr ) {
  return ( uint32_t ) NUM2UINT( rb_funcall( nw_addr, rb_intern( "to_i" ), 0 ) );
}


uint8_t *
dl_addr_to_a( VALUE dl_addr, uint8_t *ret_dl_addr ) {
  VALUE mac_arr = rb_funcall( dl_addr, rb_intern( "to_a" ), 0 );
  int i;

  for ( i = 0; i < RARRAY_LEN( mac_arr ); i++ ) {
    ret_dl_addr[ i ] = ( uint8_t ) ( NUM2INT( RARRAY_PTR( mac_arr )[ i ] ) );
  }
  return ret_dl_addr;
}


uint8_t *
mac_addr_to_cstr( VALUE mac_addr ) {
  static uint8_t dl_addr[ OFP_ETH_ALEN ];
  return dl_addr_to_a( mac_addr, dl_addr );
}


openflow_actions *
pack_basic_action( VALUE r_action ) {
  openflow_actions *actions = create_actions();
  VALUE r_action_ins = Qnil;
  VALUE r_id = rb_intern( "pack_basic_action" );

  if ( !NIL_P( r_action ) ) {
    switch ( TYPE( r_action ) ) {
      case T_ARRAY: {
          VALUE *each = RARRAY_PTR( r_action );

          for ( int i = 0; i < RARRAY_LEN( r_action ); i++ ) {
            if ( rb_respond_to( each[ i ], r_id ) ) {
              r_action_ins = Data_Wrap_Struct( rb_obj_class( each[ i ] ), NULL, NULL, actions );
              rb_funcall( each[ i ], r_id, 1, r_action_ins );
            }
          }
      }
      break;
      case T_OBJECT:
        if ( rb_respond_to( r_action, r_id ) ) {
          r_action_ins = Data_Wrap_Struct( rb_obj_class( r_action ), NULL, NULL, actions );
          rb_funcall( r_action, r_id, 1, r_action_ins );
        }
      break;
      default:
        rb_raise( rb_eTypeError, "Action argument must be either an Array or an Action object" );
      break;
    }
  }
  Data_Get_Struct( r_action_ins, openflow_actions, actions );
  return actions;
}


oxm_matches *
pack_flexible_action( VALUE r_action ) {
  oxm_matches *oxm_match = create_oxm_matches();
  VALUE r_oxm_ins = Qnil;
  VALUE r_id = rb_intern( "flexible_action" );

  if ( !NIL_P( r_action ) ) {
    switch ( TYPE( r_action ) ) {
      case T_ARRAY: {
          VALUE *each = RARRAY_PTR( r_action );

          for ( int i = 0; i < RARRAY_LEN( r_action ); i++ ) {
            if ( rb_respond_to( each[ i ], r_id ) ) {
              r_oxm_ins = Data_Wrap_Struct( rb_obj_class( each[ i ] ), NULL, NULL, oxm_match );
              rb_funcall( each[ i ], r_id, 1, r_oxm_ins );
            }
          }
      }
      break;
      case T_OBJECT:
        if ( rb_respond_to( r_action, r_id ) ) {
          r_oxm_ins = Data_Wrap_Struct( rb_obj_class( r_action ), NULL, NULL, oxm_match );
          rb_funcall( r_action, r_id, 1, r_oxm_ins );
        }
      break;
      default:
        rb_raise( rb_eTypeError, "Action argument must be either an Array or an Action object" );
      break;
    }
  }
  Data_Get_Struct( r_oxm_ins, oxm_matches, oxm_match );
  return oxm_match;
}


openflow_instructions *
pack_instruction( VALUE r_instruction ) {
  openflow_instructions *instructions = create_instructions();
  VALUE r_ins_instance;
  VALUE r_id = rb_intern( "pack_instruction" );

  if ( !NIL_P( r_instruction ) ) {
    switch ( TYPE( r_instruction ) ) {
      case T_ARRAY: {
        VALUE *each = RARRAY_PTR( r_instruction );

        for ( int i = 0; i < RARRAY_LEN( r_instruction ); i++ ) {
          if ( rb_respond_to( each[ i ], r_id ) ) {
            r_ins_instance = Data_Wrap_Struct( rb_obj_class( each[ i ] ), NULL, NULL, instructions );
            rb_funcall( each[ i ], r_id, 1, r_ins_instance );
          }
        }
      }
      break;
      case T_OBJECT:
        if ( rb_respond_to( rb_obj_class( r_instruction ), r_id ) ) {
          r_ins_instance = Data_Wrap_Struct( r_instruction, NULL, NULL, instructions );
          rb_funcall( r_instruction, r_id, 1, r_ins_instance );
        }
      break;
      default:
        rb_raise( rb_eTypeError, "Instruction argument must be either an Array or an Instruction object" );
      break;
    }
  }
  Data_Get_Struct( r_ins_instance, openflow_instructions, instructions );
  return instructions;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

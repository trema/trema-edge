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
#include "conversion-util.h"


extern VALUE mTrema;
VALUE cMatch;


/*
 * Creates a {Match} instance from packet_in's data.
 *
 * @overload match_from(message)
 *
 *   @example
 *     def packet_in datapath_id, message
 *       send_flow_mod(
 *         datapath_id,
 *         :match => Match.from( message ),
 *         :actions => Trema::ActionOutput.new( 2 )
 *       )
 *     end
 *
 *   @param [PacketIn] message
 *     the {PacketIn}'s message content.
 *
 * @return [Match] self
 *   the match from packet_in's data.
 */
static VALUE
match_from( VALUE self, VALUE message ) {
  UNUSED( self );
  uint32_t in_port = OFPP_CONTROLLER;
  VALUE r_match = rb_iv_get( message, "@match" );
  if ( !NIL_P( r_match ) ) {
    VALUE r_in_port = rb_iv_get( r_match, "@in_port" );
    if ( !NIL_P( r_in_port ) ) {
      in_port = NUM2UINT( r_in_port );
      if ( in_port == 0 ) {
        rb_raise( rb_eArgError, "The in_port value must be greater than 0." );
      }
      if ( in_port > OFPP_MAX ) {
        if ( in_port != OFPP_CONTROLLER && in_port != OFPP_LOCAL ) {
          rb_raise( rb_eArgError, "The in_port value must be less than or equal to OFPP_MAX." );
        }
      }
    }
  }

  VALUE r_data = rb_iv_get( message, "@data" );
  if ( NIL_P( r_data ) ) {
    rb_raise( rb_eArgError, "The data is a mandatory option" );
  }
  buffer *data = r_array_to_buffer( r_data );
  bool ret = parse_packet( data );
  if ( !ret ) {
    rb_raise( rb_eArgError, "The data must be a Ethernet frame." );
  }

  oxm_matches *matches = create_oxm_matches();
  set_match_from_packet( matches, in_port, NULL, data );
  VALUE r_new = oxm_match_to_r_match( matches );
  delete_oxm_matches( matches );

  free_buffer( data );

  return r_new;
}


void
Init_match( void ) {
  cMatch = rb_define_class_under( mTrema, "Match", rb_eval_string( "Trema::Message" ) );
  rb_require( "trema/match" );
  rb_define_singleton_method( cMatch, "from", match_from, 1 );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

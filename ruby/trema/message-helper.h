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


#ifndef MESSAGE_HELPER_H
#define MESSAGE_HELPER_H


#include "ruby.h"


#define SEND_MULTIPART_REQUEST( type, klass_name, self, datapath_id, options ) \
  do {                                                               \
    VALUE type##_multipart_request = Qnil;                           \
    if ( !NIL_P( options ) ) {                                       \
      type##_multipart_request = rb_funcall( rb_eval_string( klass_name ), rb_intern( "new" ), 1, options ); \
    }                                                                \
    else {                                                           \
      type##_multipart_request = rb_funcall( rb_eval_string( klass_name ), rb_intern( "new" ), 0 ); \
    }                                                                \
    if ( !NIL_P( type##_multipart_request ) ) {                      \
      send_controller_message( self, datapath_id, type##_multipart_request ); \
    } \
    return self;                                                     \
  } while( 0 ) 


void Init_message_helper( void );


#endif // MESSAGE_HELPER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

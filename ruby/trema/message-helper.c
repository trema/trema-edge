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
#include "conversion-util.h"
#include "message-helper.h"
#include "hash-util.h"


extern VALUE mTrema;
VALUE mMessageHelper;


/*
 * @overload send_message(datapath_id, message)
 *   Sends an OpenFlow message to the datapath.
 *
 *   @example
 *     send_message datapath_id, FeaturesRequest.new
 *
 *
 *   @param [Number] datapath_id
 *     the datapath to which a message is sent.
 *
 *   @param [FeaturesRequest] message
 *     the message to be sent.
 */
static VALUE
send_controller_message( VALUE self, VALUE datapath_id, VALUE message ) {
  VALUE id_pack_msg = rb_intern( "pack_msg" );

  if ( !NIL_P( message ) ) {
    switch ( TYPE( message ) ) {
      case T_ARRAY: {
          for ( int i = 0; i < RARRAY_LEN( message ); i++ ) {
            if ( rb_respond_to( rb_ary_entry( message, i ), id_pack_msg ) ) {
              rb_funcall( rb_ary_entry( message, i ), id_pack_msg, 1, datapath_id );
            }
          }
      }
      break;
      case T_OBJECT:
        if ( rb_respond_to( message, id_pack_msg ) ) {
          rb_funcall( message, id_pack_msg, 1, datapath_id );
        }
      break;
      default:
        rb_raise( rb_eTypeError, "Message argument must be an Array or a Message object" );
      break;
    }
  }
  return self;
}


static VALUE
send_flow_mod( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );

  if ( !NIL_P( options ) ) {
    VALUE flow_mod = rb_funcall( rb_eval_string( "Trema::Messages::FlowMod" ), rb_intern( "new" ), 1, options );

    send_controller_message( self, datapath_id, flow_mod );
  }
  return self;
}



static VALUE
send_packet_out( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );

  uint32_t buffer_id = OFP_NO_BUFFER;
  buffer *data = NULL;
  openflow_actions *actions = NULL;
  uint32_t in_port = OFPP_ANY;
  if ( !NIL_P( options ) ) {
    VALUE r_opt_action = HASH_REF( options, actions );
    if ( !NIL_P( r_opt_action ) ) {
      actions = pack_basic_action( r_opt_action );
    }

    VALUE r_opt_message = HASH_REF( options, packet_in );
    VALUE r_opt_data = HASH_REF( options, data );
    if ( !NIL_P( r_opt_message ) ) {

      if ( datapath_id == rb_iv_get( r_opt_message, "@datapath_id" ) ) {
        buffer_id = NUM2UINT( rb_iv_get( r_opt_message, "@buffer_id" ) );
        VALUE match = rb_iv_get( r_opt_message, "@match" );
        in_port = NUM2UINT( rb_iv_get( match, "@in_port" ) );
      }
       
      VALUE r_data = rb_iv_get( r_opt_message, "@data" );
      data = r_array_to_buffer( r_data );
    }
    else if ( !NIL_P( r_opt_data ) ) {
      data = r_array_to_buffer( r_opt_data );
    }

    buffer *packet_out;
    if ( buffer_id == OFP_NO_BUFFER &&
         ( !NIL_P( r_opt_message ) || !NIL_P( r_opt_data ) )) {
      buffer *frame = duplicate_buffer( data );
      fill_ether_padding( frame );

      packet_out = create_packet_out(
        get_transaction_id(),
        buffer_id, 
        in_port,
        actions,
        frame
      );
      free_buffer( data );
      free_buffer( frame );
    } 
    else {
      packet_out = create_packet_out(
        get_transaction_id(),
        buffer_id, 
        in_port,
        actions,
        NULL
      );
    }
    send_openflow_message( NUM2ULL( datapath_id ), packet_out );

    free_buffer( packet_out );
    delete_actions( actions );
  }
  return self;
}


static VALUE
send_group_mod( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );

  if ( !NIL_P( options ) ) {
    VALUE group_mod = rb_funcall( rb_eval_string( "Trema::Messages::GroupMod" ), rb_intern( "new" ), 1, options );

    send_controller_message( self, datapath_id, group_mod );
  }
  return self;
}


static VALUE
send_flow_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );
  SEND_MULTIPART_REQUEST( flow, "Messages::FlowMultipartRequest", self, datapath_id, options );
}


static VALUE
send_desc_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );  
  SEND_MULTIPART_REQUEST( desc, "Messages::DescMultipartRequest", self, datapath_id, options );
}


static VALUE
send_aggregate_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );
  SEND_MULTIPART_REQUEST( aggregate, "Messages::AggregateMultipartRequest", self, datapath_id, options );
}

  
static VALUE
send_table_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );  
  SEND_MULTIPART_REQUEST( table, "Messages::TableMultipartRequest", self, datapath_id, options );
}


static VALUE
send_port_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );
  SEND_MULTIPART_REQUEST( port, "Messages::PortMultipartRequest", self, datapath_id, options );
}



static VALUE
send_table_features_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );  
  SEND_MULTIPART_REQUEST( table_features, "Messages::TableFeaturesMultipartRequest", self, datapath_id, options );
}


static VALUE
send_group_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );  
  SEND_MULTIPART_REQUEST( group, "Messages::GroupMultipartRequest", self, datapath_id, options );
}


static VALUE
send_group_desc_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );
  SEND_MULTIPART_REQUEST( group_desc, "Messages::GroupDescMultipartRequest", self, datapath_id, options );
}


static VALUE
send_group_features_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );
  SEND_MULTIPART_REQUEST( group_features, "Messages::GroupFeaturesMultipartRequest", self, datapath_id, options );
}


static VALUE
send_port_desc_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );
  SEND_MULTIPART_REQUEST( port_desc, "Messages::PortDescMultipartRequest", self, datapath_id, options );
}


static VALUE
send_queue_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );
  SEND_MULTIPART_REQUEST( queue, "Messages::QueueMultipartRequest", self, datapath_id, options );
}


static VALUE
send_meter_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );
  SEND_MULTIPART_REQUEST( meter, "Messages::MeterMultipartRequest", self, datapath_id, options );
}


static VALUE
send_meter_config_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );
  SEND_MULTIPART_REQUEST( meter_config, "Messages::MeterConfigMultipartRequest", self, datapath_id, options );
}


static VALUE
send_meter_features_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );
  SEND_MULTIPART_REQUEST( meter_features, "Messages::MeterFeaturesMultipartRequest", self, datapath_id, options );
}


static VALUE
send_experimenter_multipart_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );
  SEND_MULTIPART_REQUEST( experimenter, "Messages::ExperimenterMultipartRequest", self, datapath_id, options );
}


static VALUE
send_barrier_request( int argc, VALUE *argv, VALUE self ) {
  VALUE datapath_id = Qnil;
  VALUE options = Qnil;
  rb_scan_args( argc, argv, "11", &datapath_id, &options );
  VALUE r_barrier_request = rb_funcall( rb_eval_string( "Trema::Messages::BarrierRequest" ), rb_intern( "new" ), 1, options );
  send_controller_message( self, datapath_id, r_barrier_request );
  return self;
}


void
Init_message_helper( void ) {
  mMessageHelper = rb_define_module_under( mTrema, "MessageHelper" );

  rb_define_module_function( mMessageHelper, "send_flow_mod", send_flow_mod, -1 );
  rb_define_module_function( mMessageHelper, "send_message", send_controller_message, 2 );
  rb_define_module_function( mMessageHelper, "send_packet_out", send_packet_out, - 1 );
  rb_define_module_function( mMessageHelper, "send_group_mod", send_group_mod, -1 );
  rb_define_module_function( mMessageHelper, "send_flow_multipart_request", send_flow_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_desc_multipart_request", send_desc_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_aggregate_multipart_request", send_aggregate_multipart_request, - 1 );
  rb_define_module_function( mMessageHelper, "send_table_multipart_request", send_table_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_port_multipart_request", send_port_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_table_features_multipart_request", send_table_features_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_group_multipart_request", send_group_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_group_desc_multipart_request", send_group_desc_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_group_features_multipart_request", send_group_features_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_port_desc_multipart_request", send_port_desc_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_queue_multipart_request", send_queue_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_meter_multipart_request", send_meter_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_meter_config_multipart_request", send_meter_config_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_meter_features_multipart_request", send_meter_features_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_experimenter_multipart_request", send_experimenter_multipart_request, -1 );
  rb_define_module_function( mMessageHelper, "send_barrier_request", send_barrier_request, - 1 );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

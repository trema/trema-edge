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
#include "messages/packet-in-handler.h"
#include "messages/switch-ready.h"
#include "messages/port-status-handler.h"
#include "messages/flow-removed-handler.h"
#include "messages/error-handler.h"
#include "messages/multipart-reply-handler.h"
#include "messages/barrier-reply-handler.h"
#include "messages/echo-reply-handler.h"
#include "messages/get-config-reply-handler.h"
#include "messages/features-reply-handler.h"


extern VALUE mTrema;
VALUE mMessageHandler;


VALUE
install_handlers( VALUE self ) {
  set_packet_in_handler( handle_packet_in, ( void * ) self );
  set_switch_ready_handler( handle_switch_ready, ( void * ) self );
  set_port_status_handler( handle_port_status, ( void * ) self );
  set_flow_removed_handler( handle_flow_removed, ( void * ) self );
  set_error_handler( handle_error, ( void * ) self );
  set_multipart_reply_handler( handle_multipart_reply, ( void * ) self );
  set_barrier_reply_handler( handle_barrier_reply, ( void * ) self );
  set_echo_reply_handler( handle_echo_reply, ( void * ) self );
  set_get_config_reply_handler( handle_get_config_reply, ( void * ) self );
  set_features_reply_handler( handle_features_reply, ( void * ) self );
  return self;
}


void
Init_message_handler( void ) {
  mMessageHandler = rb_define_module_under( mTrema, "MessageHandler" );

  rb_define_module_function( mMessageHandler, "install_handlers", install_handlers, 1 );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

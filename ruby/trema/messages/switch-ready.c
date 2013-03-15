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

/*
 * @overload send_message(datapath_id, message)
 *   Sends an OpenFlow message to the datapath.
 *
 *   @example
 *     send_message datapath_id, FeaturesRequest.new
 *
 *   @param [Integer] datapath_id
 *     the datapath to which a message is sent.
*/


void
handle_switch_ready( uint64_t datapath_id, void *controller ) {
  if ( rb_respond_to( ( VALUE ) controller, rb_intern( "switch_ready" ) ) ) {
    rb_funcall( ( VALUE ) controller, rb_intern( "switch_ready" ), 1, ULL2NUM( datapath_id ) );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

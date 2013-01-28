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
#include "action-tlv.h"


static void pack_action_tlv_push_vlan( void *dest, const struct action_tlv_args *args );


static struct action_tlv action_tlv_push_vlan = {
  OFPAT_PUSH_VLAN,
  ( uint16_t ) sizeof( struct ofp_action_push ),
  pack_action_tlv_push_vlan
};


void
init_action_tlv_push_vlan( void ) {
  register_action( &action_tlv_push_vlan );
}


static void
pack_action_tlv_push_vlan( void *dest, const struct action_tlv_args *args ) {
  struct ofp_action_push *ac_push = dest;

  ac_push->type = action_tlv_push_vlan.type;
  ac_push->len = action_tlv_push_vlan.len;
  ac_push->ethertype = args->uac_push_vlan.ethertype;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

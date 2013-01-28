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


static void pack_action_pop_mpls( void *dest, const struct action_tlv_args *args );


static struct action_tlv action_tlv_pop_mpls = {
  OFPAT_POP_MPLS,
  ( uint16_t ) sizeof( struct ofp_action_pop_mpls ),
  pack_action_pop_mpls
};


void
init_action_tlv_pop_mpls( void ) {
  register_action( &action_tlv_pop_mpls );
}


static void
pack_action_pop_mpls( void *dest, const struct action_tlv_args *args ) {
  struct ofp_action_pop_mpls *ac_pop_mpls = dest;

  ac_pop_mpls->type = action_tlv_pop_mpls.type;
  ac_pop_mpls->len = action_tlv_pop_mpls.len;
  ac_pop_mpls->ethertype = args->uac_pop_mpls.ethertype;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

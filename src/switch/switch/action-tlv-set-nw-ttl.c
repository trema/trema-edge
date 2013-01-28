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
#include "ofdp.h"
#include "action-tlv.h"


static void pack_action_tlv_set_nw_ttl( void *dest, const struct action_tlv_args *args );


static struct action_tlv action_tlv_set_nw_ttl = {
  OFPAT_SET_NW_TTL,
  ( uint16_t ) sizeof( struct ofp_action_nw_ttl ),
  pack_action_tlv_set_nw_ttl
};


void
init_action_tlv_set_nw_ttl( void ) {
  register_action( &action_tlv_set_nw_ttl );
}


static void
pack_action_tlv_set_nw_ttl( void *dest, const struct action_tlv_args *args ) {
  struct ofp_action_nw_ttl *ac_nw_ttl = dest;

  ac_nw_ttl->type = action_tlv_set_nw_ttl.type;
  ac_nw_ttl->len = action_tlv_set_nw_ttl.len;
  ac_nw_ttl->nw_ttl = args->uac_nw_ttl.nw_ttl;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

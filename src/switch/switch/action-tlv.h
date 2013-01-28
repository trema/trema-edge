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


#ifndef ACTION_TLV_H
#define ACTION_TLV_H


#ifdef __cplusplus
extern "C" {
#endif


struct action_tlv_args {
  union {
    struct ofp_action_header ac_header;
    struct ofp_action_output ac_output;
    struct ofp_action_group ac_group;
    struct ofp_action_set_queue ac_set_queue;
    struct ofp_action_mpls_ttl ac_mpls_ttl;
    struct ofp_action_nw_ttl ac_nw_ttl;
    struct ofp_action_push ac_push_vlan;
    struct ofp_action_push ac_push_mpls;
    struct ofp_action_push ac_push_pbb;
    struct ofp_action_pop_mpls ac_pop_mpls;
    struct ofp_action_set_field ac_set_field;
    struct ofp_action_experimenter_header *ac_experimental_header;
  } all_actions;
};


#define uac_header all_actions.ac_header
#define uac_output all_actions.ac_output
#define uac_group all_actions.ac_group
#define uac_set_queue all_actions.ac_set_queue
#define uac_mpls_ttl all_actions.ac_mpls_ttl
#define uac_nw_ttl all_actions.ac_nw_ttl
#define uac_push_vlan all_actions.ac_push_vlan
#define uac_push_mpls all_actions.ac_push_mpls
#define uac_push_pbb all_actions.ac_push_pbb
#define uac_pop_mpls all_actions.ac_pop_mpls
#define uac_set_field all_actions.set_field
#define uac_experimental_header all_actions.ac_experimental_header


struct action_tlv {
  uint16_t type;
  uint16_t len;
  void ( *pack )( void *dest, const struct action_tlv_args *args );
};


void init_actions( void );
void finalize_actions( void );
void register_action( struct action_tlv * );


#ifdef __cplusplus
}
#endif


#endif // ACTION_TLV_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

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


#ifndef ACTION_HELPER_H
#define ACTION_HELPER_H


#ifdef __cplusplus
extern "C" {
#endif


#include "ofdp.h"


action_list * ( *assign_actions )( action_list *action_list, const struct ofp_action_header *action, uint16_t action_length );
void ( *action_pack )( void *dest, action_list **list );
uint16_t ( *action_list_length )( action_list **list );


#ifdef __cplusplus
}
#endif


#endif // ACTION_HELPER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

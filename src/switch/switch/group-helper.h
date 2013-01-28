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


#ifndef GROUP_HELPER_H
#define GROUP_HELPER_H


#ifdef __cplusplus
extern "C" {
#endif


void ( *handle_group_add )( const uint32_t transaction_id,
        const uint8_t type,
        const uint32_t group_id,
        const list_element *buckets );
void ( *handle_group_mod_mod )( const uint32_t transaction_id,
        const uint8_t type,
        const uint32_t group_id,
        const list_element *buckets );
void ( *handle_group_mod_delete )( const uint32_t transaction_id,
        const uint32_t group_id );


#ifdef __cplusplus
}
#endif


#endif // GROUP_HELPER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */


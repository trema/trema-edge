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


#ifndef OXM_INTERFACE_H
#define OXM_INTERFACE_H


#ifdef __cplusplus
extern "C" {
#endif


uint16_t match_length( const match *match );
uint16_t oxm_length( const uint16_t type );
uint32_t oxm_attr_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );


#ifdef __cplusplus
}
#endif


#endif // OXM_INTERFACE_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

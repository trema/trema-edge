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


#ifndef SWITCH_INSTRUCTION_H
#define SWITCH_INSTRUCTION_H


#ifdef __cplusplus
extern "C" {
#endif


struct instruction {
  uint16_t type;
  uint16_t len;
  uint16_t ( *length )( void );
  // void ( *pack )( struct ofp_match *ofp_match, const match *match );
};


void register_instruction( struct instruction *instruction_subclass );


#ifdef __cplusplus
}
#endif


#endif // SWITCH_INSTRUCTION_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

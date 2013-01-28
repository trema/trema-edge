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


#include <stdint.h>
#include "trema.h"
#include "switch-instruction.h"


static uint16_t instruction_goto_table_length( void );


static struct instruction instruction_goto_table = {
  OFPIT_GOTO_TABLE,
  ( uint16_t ) sizeof( struct ofp_instruction_goto_table ),
  instruction_goto_table_length
};


void 
init_instruction_goto_table( void ) {
  register_instruction( &instruction_goto_table );
}


static uint16_t
instruction_goto_table_length( void ) {
  return instruction_goto_table.len;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

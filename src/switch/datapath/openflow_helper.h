/*
 * Copyright (C) 2012-2013 NEC Corporation
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


#ifndef OPENFLOW_HELPER_H
#define OPENFLOW_HELPER_H


#include "action_bucket.h"
#include "flow_table.h"
#include "group_table.h"
#include "match.h"
#include "ofdp_error.h"
#include "port_manager.h"
#include "switch_port.h"


size_t get_oxm_length_from_match8( const match8 *match, const unsigned int array_size );
size_t get_oxm_length_from_match16( const match16 *match, const unsigned int array_size );
size_t get_oxm_length_from_match32( const match32 *match, const unsigned int array_size );
size_t get_oxm_length_from_match64( const match64 *match, const unsigned int array_size );
size_t get_oxm_length( const match *match );
size_t get_ofp_action_length( const action *action );
size_t get_ofp_bucket_length( const bucket *bucket );
size_t get_ofp_buckets_length( bucket_list *buckets );
bool get_ofp_bucket( const bucket *bucket, struct ofp_bucket **translated, size_t *length );
bool get_ofp_action( const action* action, struct ofp_action_header **translated, size_t *length );
bool get_ofp_group_stats( const group_stats *stats, struct ofp_group_stats **translated, size_t *length );
bool get_ofp_bucket_counter( const bucket_counter *counter, struct ofp_bucket_counter *translated );
bool get_ofp_table_stats( const table_stats *stats, struct ofp_table_stats *translated );
bool get_ofp_port_stats( const port_stats *stats, struct ofp_port_stats *translated );
bool get_ofp_port( const port_description *description, struct ofp_port *translated );
void switch_port_to_ofp_port( struct ofp_port *ofp_port, const switch_port *port );
bool get_ofp_error( OFDPE error_code, uint16_t *type, uint16_t *code );


#endif // OPENFLOW_HELPER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/

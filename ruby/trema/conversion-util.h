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


#ifndef CONVERSION_UTIL_H
#define CONVERSION_UTIL_H


VALUE buffer_to_r_array( const buffer *buffer );
VALUE oxm_match_to_r_match( const oxm_matches *match );
VALUE ofp_match_to_r_match( const struct ofp_match *match );
buffer *r_array_to_buffer( VALUE r_array );
struct in6_addr ipv6_addr_to_in6_addr( VALUE ipv6_addr );
void r_match_to_oxm_match( VALUE r_match, oxm_matches *match );


#endif // CONVERSION_UTIL_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

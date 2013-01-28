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


#ifndef ARRAY_UTIL_H
#define ARRAY_UTIL_H


#ifdef __cplusplus
extern "C" {
#endif


#define ARRAY_SIZE( x ) ( sizeof( x ) / sizeof( x[ 0 ] ) )
#define ALLOC_NR( x ) ( ( ( x ) * 16 ) * 3 / 2 )


#define ALLOC_GROW( x, nr, alloc ) \
  do { \
    if ( ( nr ) > alloc ) { \
      if ( ( ALLOC_NR( alloc ) < ( nr ) ) ) { \
        alloc = ( nr ); \
      } \
      else { \
        alloc = ALLOC_NR( alloc ); \
      } \
      x = xrealloc( ( x ), alloc * sizeof( *( x ) ) ); \
    } \
   } while ( 0 )


#ifdef __cplusplus
}
#endif


#endif // ARRAY_UTIL_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

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


#ifndef ASYNC_UTIL_H
#define ASYNC_UTIL_H


#include <pthread.h>


#ifdef __cplusplus
extern "C" {
#endif


#define LOCK_OBJ( name ) \
static inline void \
name##_lock( void ) { \
  pthread_mutex_lock( &name##_mutex ); \
}


#define UNLOCK_OBJ( name ) \
static inline void \
name##_unlock( void ) { \
  pthread_mutex_unlock( &name##_mutex ); \
}


#define GET_OBJ_INFO( name ) \
static struct name##_info * \
get_##name##_info() { \
  pthread_t self = current_thread(); \
  uint32_t nr = name##_list.name##s_nr; \
\
  for( uint32_t i = 0; i < nr; i++ ) { \
    if ( name##_list.name##s[ i ] != NULL ) { \
      if ( name##_list.name##s[ i ]->thread_id == self ) { \
        return name##_list.name##s[ i ]; \
      } \
    } \
  } \
  for ( uint32_t i = 0; i < nr; i++ ) { \
    if ( name##_list.name##s[ i ] != NULL ) { \
      if ( !name##_list.name##s[ i ]->thread_id ) { \
        return name##_list.name##s[ i ]; \
      } \
    } \
  } \
  return NULL; \
}


#define DELETE_OBJ_INFO( name ) \
static void \
delete_##name##_info( struct name##_info *obj ) { \
  uint32_t nr = name##_list.name##s_nr; \
\
  for ( uint32_t i = 0; i < nr; i++ ) { \
    if ( name##_list.name##s[ i ] != NULL ) { \
      if ( name##_list.name##s[ i ] == obj ) { \
        xfree( obj ); \
        name##_list.name##s[ i ] = NULL; \
        break; \
      } \
    } \
  } \
}


pthread_t current_thread( void );        
int create_event_fd( void );


#ifdef __cplusplus
}
#endif


#endif // ASYNC_UTIL_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

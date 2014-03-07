/*
 * Author: Yasuhito Takamiya <yasuhito@gmail.com>
 *
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


#include <assert.h>
#include <pthread.h>
#include "doubly_linked_list.h"
#include "wrapper.h"


typedef struct dlist_element_sentinel {
  dlist_element public;
  pthread_mutex_t *mutex;
} dlist_element_sentinel;


/**
 * Allocates space for one dlist_element.
 *
 * @return a pointer to the newly-allocated dlist_element, as a sentinel.
 */
dlist_element *
create_dlist() {
  dlist_element_sentinel *sentinel = ( dlist_element_sentinel * ) xmalloc( sizeof( dlist_element_sentinel ) );
  sentinel->public.data = NULL;
  sentinel->public.prev = ( dlist_element * ) sentinel;
  sentinel->public.next = ( dlist_element * ) sentinel;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init( &attr );
  pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_RECURSIVE_NP );
  sentinel->mutex = xmalloc( sizeof( pthread_mutex_t ) );
  pthread_mutex_init( sentinel->mutex, &attr );

  return ( dlist_element * ) sentinel;
}


/**
 * Inserts a new element into the list before the given position.
 *
 * @param element the list element before which the new element is inserted.
 * @param data the data for the new element.
 * @return a pointer to newly inserted element.
 */
dlist_element *
insert_before_dlist( dlist_element *sentinel, dlist_element *element, void *data ) {
  if ( sentinel == NULL ) {
    die( "sentinel element must not be NULL" );
  }
  assert( data != NULL ); // only sentinel can have NULL data

  pthread_mutex_t *mutex = ( ( dlist_element_sentinel * ) sentinel )->mutex;
  pthread_mutex_lock( mutex );

  dlist_element *new_prev = ( dlist_element * ) xmalloc( sizeof( dlist_element ) );

  if ( element->prev ) {
    dlist_element *old_prev = element->prev;
    new_prev->prev = old_prev;
    old_prev->next = new_prev;
  }

  element->prev = new_prev;
  new_prev->next = element;
  new_prev->data = data;

  pthread_mutex_unlock( mutex );

  return new_prev;
}


/**
 * Inserts a new element into the list after the given position.
 *
 * @param element the list element after which the new element is inserted.
 * @param data the data for the new element.
 * @return a pointer to newly inserted element.
 */
dlist_element *
insert_after_dlist( dlist_element *sentinel, dlist_element *element, void *data ) {
  if ( sentinel == NULL ) {
    die( "sentinel element must not be NULL" );
  }
  assert( data != NULL ); // only sentinel can have NULL data

  pthread_mutex_t *mutex = ( ( dlist_element_sentinel * ) sentinel )->mutex;
  pthread_mutex_lock( mutex );

  dlist_element *new_next = ( dlist_element * ) xmalloc( sizeof( dlist_element ) );

  if ( element->next ) {
    dlist_element *old_next = element->next;
    new_next->next = old_next;
    old_next->prev = new_next;
  }

  element->next = new_next;
  new_next->prev = element;
  new_next->data = data;

  pthread_mutex_unlock( mutex );

  return new_next;
}


/**
 * Gets the first element in a list.
 *
 * @param element a pointer to any of the element in the list.
 * @return the first element in the list.
 */
dlist_element *
get_first_element( dlist_element *sentinel ) {
  if ( sentinel == NULL ) {
    die( "sentinel element must not be NULL" );
  }
  return sentinel->next;
}


/**
 * Gets the last element in a list.
 *
 * @param element a pointer to any of the element in the list.
 * @return the last element in the list.
 */
dlist_element *
get_last_element( dlist_element *sentinel ) {
  if ( sentinel == NULL ) {
    die( "sentinel element must not be NULL" );
  }
  return sentinel->prev;
}


/**
 * Finds the element in a list which contains the given data.
 *
 * @param element a pointer to any of the element in the list.
 * @param data the element data to find.
 * @return the found list element, or NULL if it is not found.
 */
dlist_element *
find_element( dlist_element *sentinel, const void *data ) {
  if ( sentinel == NULL ) {
    die( "sentinel element must not be NULL" );
  }

  pthread_mutex_lock( ( ( dlist_element_sentinel * ) sentinel )->mutex );

  dlist_element *e = NULL;
  for ( e = sentinel->next; e != sentinel; e = e->next ) {
    if ( e->data == data ) {
      pthread_mutex_unlock( ( ( dlist_element_sentinel * ) sentinel )->mutex );
      return e;
    }
  }

  pthread_mutex_unlock( ( ( dlist_element_sentinel * ) sentinel )->mutex );

  return NULL;
}


static void
_delete_dlist_element( dlist_element *element ) {
  element->prev->next = element->next;
  element->next->prev = element->prev;
  xfree( element );
}

/**
 * Removes an element from a list. If two elements contain the same
 * data, only the first is removed. If none of the elements contain
 * the data, the list is unchanged.
 *
 * @param element a element to remove.
 * @return true on success; false otherwise.
 */
bool
delete_dlist_element( dlist_element *sentinel, dlist_element *element ) {
  if ( sentinel == NULL || element == NULL ) {
    die( "element must not be NULL" );
  }

  pthread_mutex_t *mutex = ( ( dlist_element_sentinel * ) sentinel )->mutex;
  pthread_mutex_lock( mutex );

  _delete_dlist_element( element );

  pthread_mutex_unlock( mutex );

  return true;
}


/**
 * Removes all elements from a list.
 *
 * @param element a pointer to any of the element in the list.
 * @return true on success; false otherwise.
 */
bool
delete_dlist( dlist_element *sentinel ) {
  if ( sentinel == NULL ) {
    die( "sentinel element must not be NULL" );
  }

  pthread_mutex_t *mutex = ( ( dlist_element_sentinel * ) sentinel )->mutex;
  pthread_mutex_lock( mutex );

  dlist_element *e_next;
  for ( dlist_element *e = sentinel->next; e != sentinel; e = e_next ) {
    e_next = e->next;
    _delete_dlist_element( e );
  }
  xfree( sentinel );

  pthread_mutex_unlock( mutex );
  pthread_mutex_destroy( mutex );
  xfree(mutex);

  return true;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

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


#ifndef MUTEX_H
#define MUTEX_H

#include <pthread.h>
#include "bool.h"

bool init_mutex( pthread_mutex_t *mutex );
bool finalize_mutex( pthread_mutex_t *mutex );
bool lock_mutex( pthread_mutex_t *mutex );
bool unlock_mutex( pthread_mutex_t *mutex );
bool try_lock( pthread_mutex_t *mutex );

char *safe_strerror_r( int errnum, char *buf, size_t buflen );

#endif // MUTEX_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/

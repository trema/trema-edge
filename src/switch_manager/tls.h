/*
 * Author: Yasunobu Chiba
 *
 * Copyright (C) 2013 NEC Corporation
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


#ifndef TLS_H
#define TLS_H


#include <openssl/err.h>
#include <openssl/ssl.h>
#include "trema.h"


bool init_tls_server( const char *cert_file, const char *key_file );
bool finalize_tls_server();
SSL *init_tls_session( const int fd );
bool finalize_tls_session( SSL *ssl );


#endif // TLS_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

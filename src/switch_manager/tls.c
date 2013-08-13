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


#include <assert.h>
#include "tls.h"


static SSL_CTX *ctx = NULL;


static bool
load_certificates( const char *cert_file, const char *key_file ) {
  assert( ctx != NULL );
  assert( cert_file != NULL );
  assert( key_file != NULL );

  debug( "Loading certificate ( ctx = %p, cert_file = %s, key_file = %s ).", ctx, cert_file, key_file );

  unsigned long error_no = 0;
  char error_str[ 256 ];
  memset( error_str, '\0', sizeof( error_str ) );

  int ret = SSL_CTX_use_certificate_file( ctx, cert_file, SSL_FILETYPE_PEM );
  if ( ret != 1 ) {
    error_no = ERR_get_error();
    ERR_error_string_n( error_no, error_str, sizeof( error_str ) );
    error( "Failed to load a certificate file ( file = %s, error = %s [%ul] ).",
           cert_file, error_str, error_no );
    return false;
  }

  ret = SSL_CTX_use_PrivateKey_file( ctx, key_file, SSL_FILETYPE_PEM );
  if ( ret != 1 ) {
    error_no = ERR_get_error();
    ERR_error_string_n( error_no, error_str, sizeof( error_str ) );
    error( "Failed to load a private key file ( file = %s, error = %s [%ul] ).",
           key_file, error_str, error_no );
    return false;
  }

  ret = SSL_CTX_check_private_key( ctx );
  if ( ret != 1 ) {
    error_no = ERR_get_error();
    ERR_error_string_n( error_no, error_str, sizeof( error_str ) );
    error( "Failed to check private key ( error = %s [%ul] ).", error_str, error_no );
    return false;
  }

  return true;
}


SSL *
init_tls_session( const int fd ) {
  debug( "Initializing TLS session ( fd = %d, ctx = %p ).", fd, ctx );

  assert( fd >= 0 );
  assert( ctx != NULL );

  SSL *ssl = SSL_new( ctx );
  assert( ssl != NULL );

  int ret = SSL_set_fd( ssl, fd );
  if ( ret != 1 ) {
    error( "Failed to set a file descriptor to SSL object ( fd = %d, ctx = %p, ssl = %p ).",
           fd, ctx, ssl );
    SSL_free( ssl );
    return NULL;
  }

  ret = SSL_accept( ssl );
  if ( ret != 1 ) {
    int error_no = SSL_get_error( ssl, ret );
    error( "Failed to initialize TLS handshake ( fd = %d, ctx = %p, ssl = %p, error = %d ).",
           fd, ctx, ssl, error_no );
    SSL_free( ssl );
    return NULL;
  }

  return ssl;
}


bool
finalize_tls_session( SSL *ssl ) {
  debug( "Finalizing TLS session ( ssl = %p, ctx = %p ).", ssl, ctx );

  assert( ssl != NULL );

  if ( SSL_get_shutdown( ssl ) != SSL_SENT_SHUTDOWN ) {
    // FIXME: SSL_shutdown() may return an error if underlying socket is non-blocking.
    SSL_shutdown( ssl );
  }
  SSL_free( ssl );

  return true;
}


bool
init_tls_server( const char *cert_file, const char *key_file ) {
  debug( "Initializing TLS server ( ctx = %p, cert_file = %s, key_file = %s ).",
         ctx, cert_file, key_file );

  assert( ctx == NULL );

  SSL_library_init();
  SSL_load_error_strings();

  const SSL_METHOD *method = TLSv1_server_method();
  ctx = SSL_CTX_new( method );
  if ( ctx == NULL ) {
    unsigned long error_no = ERR_get_error();
    char error_str[ 256 ];
    memset( error_str, '\0', sizeof( error_str ) );
    ERR_error_string_n( error_no, error_str, sizeof( error_str ) );
    error( "Failed to create SSL context ( %s [%ul] ).", error_str, error_no );
    return false;
  }

  const char *ciphers = "HIGH";
  int retval = SSL_CTX_set_cipher_list( ctx, ciphers );
  if ( retval != 1 ) {
    unsigned long error_no = ERR_get_error();
    char error_str[ 256 ];
    memset( error_str, '\0', sizeof( error_str ) );
    ERR_error_string_n( error_no, error_str, sizeof( error_str ) );
    error( "Failed to set cipher list ( ctx = %p, ciphers = %s, retval = %s, error = %s [%ul] ).",
           ctx, ciphers, retval, error_str, error_no );
    return false;
  }

  bool ret = load_certificates( cert_file, key_file );
  if ( !ret ) {
    error( "Failed to load certificates." );
    SSL_CTX_free( ctx );
    ctx = NULL;
    return false;
  }

  return true;
}


bool
finalize_tls_server() {
  debug( "Finalizing TLS server ( ctx = %p ).", ctx );

  assert( ctx != NULL );

  SSL_CTX_free( ctx );
  ctx = NULL;

  return true;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

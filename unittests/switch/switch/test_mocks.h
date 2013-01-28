#ifndef TEST_MOCK_T
#define TEST_MOCK_T

#include <stdio.h>
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <cmockery.h>
#include "checks.h"
#include "bool.h"

#define static /**/

extern void
mock_error( const char *format, ... );

extern void
mock_debug( const char *format, ... );

extern void
mock_warn( const char *format, ... );

extern void
mock_info( const char *format, ... );

extern int
mock_chdir( char *path );

extern void
mock_exit( int status );


extern pid_t
mock_fork();

extern pid_t
mock_setsid();

extern mode_t
mock_umask( mode_t mode );

extern int
mock_close( int fd );

extern int
mock_open( char *pathname, int flags, mode_t mode );

extern int
mock_lockf( int fd, int cmd, off_t len );

extern pid_t
mock_getpid();

extern ssize_t
mock_write( int fd, void *buf, size_t count );

extern int
mock_unlink( char *pathname );

extern int
mock_access( char *pathname, int mode);

extern ssize_t
mock_read( int fd, void *buf, size_t count );

extern int
mock_kill( pid_t pid, int sig );

extern int
mock_rename( char *oldpath, char *newpath );

extern void
mock_execute_timer_events();

extern bool
mock_add_periodic_event_callback( const time_t seconds, void ( *callback )( void *user_data ),
																	void *user_data );

extern int
mock_clock_gettime( clockid_t clk_id, struct timespec *tp );

extern bool
mock_set_external_callback( void ( *callback ) ( void ) );

extern void
mock_dump_stats();

extern bool
mock_init_timer();

extern bool
mock_finalize_timer();

extern bool
mock_finalize_packetin_filter_interface();

extern int
mock_socket( int domain, int type, int protocol );

extern int
mock_bind( int sockfd, const struct sockaddr *addr, socklen_t addrlen );

extern int
mock_listen( int sockfd, int backlog );

extern int
mock_connect( int sockfd, const struct sockaddr *addr, socklen_t addrlen );

extern int
mock_select( int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
							struct timeval *timeout );

extern int
mock_accept( int sockfd, struct sockaddr *addr, socklen_t *addrlen );

extern ssize_t
mock_recv( int sockfd, void *buf, size_t len, int flags );

extern ssize_t
mock_send( int sockfd, const void *buf, size_t len, int flags );

extern int
mock_setsockopt( int s, int level, int optname, const void *optval, socklen_t optlen );

extern void*
mock_error_malloc(size_t size);

extern void
mock_die( const char *format, ... );

#endif /* TEST_MOCK_T */

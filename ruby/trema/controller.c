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


#include "buffer.h"
#include "controller.h"
#include "openflow.h"
#include "ruby.h"
#include "trema.h"
#include "action-common.h"


extern VALUE mTrema;
VALUE cController;


static void
handle_timer_event( void *self ) {
  if ( rb_respond_to( ( VALUE ) self, rb_intern( "handle_timer_event" ) ) ) {
    rb_funcall( ( VALUE ) self, rb_intern( "handle_timer_event" ), 0 );
  }
}


/*
 * Starts this controller. Usually you do not need to invoke
 * explicitly, because this is called implicitly by "trema run"
 * command.
 */
static VALUE
controller_run( VALUE self ) {
  setenv( "TREMA_HOME", RSTRING_PTR( rb_funcall( mTrema, rb_intern( "home" ), 0 ) ), 1 );

  VALUE name = rb_funcall( self, rb_intern( "name" ), 0 );
  rb_gv_set( "$PROGRAM_NAME", name );

  int argc = 3;
  char **argv = xmalloc( sizeof ( char * ) * ( uint32_t ) ( argc + 1 ) );
  argv[ 0 ] = RSTRING_PTR( name );
  argv[ 1 ] = ( char * ) ( uintptr_t ) "--name";
  argv[ 2 ] = RSTRING_PTR( name );
  argv[ 3 ] = NULL;
  init_trema( &argc, &argv );
  xfree( argv );

  struct itimerspec interval;
  interval.it_interval.tv_sec = 1;
  interval.it_interval.tv_nsec = 0;
  interval.it_value.tv_sec = 0;
  interval.it_value.tv_nsec = 0;
  add_timer_event_callback( &interval, handle_timer_event, ( void * ) self );

  rb_funcall( self, rb_intern( "install_handlers" ), 1, self );
  if ( rb_respond_to( self, rb_intern( "start" ) ) ) {
    rb_funcall( self, rb_intern( "start" ), 0 );
  }

  rb_funcall( self, rb_intern( "start_trema" ), 0 );

  return self;
}


/*
 * @overload shutdown!
 *   In the context of trema framework stops this controller and its applications.
 */
static VALUE
controller_shutdown( VALUE self ) {
  stop_trema();
  return self;
}


static void
thread_pass( void *user_data ) {
  UNUSED( user_data );
  rb_thread_check_ints();
  rb_funcall( rb_cThread, rb_intern( "pass" ), 0 );
}


/*
 * In the context of trema framework invokes the scheduler to start its applications.
 */
static VALUE
controller_start_trema( VALUE self ) {
  struct itimerspec interval;
  interval.it_interval.tv_sec = 0;
  interval.it_interval.tv_nsec = 1000000;
  interval.it_value.tv_sec = 0;
  interval.it_value.tv_nsec = 0;
  add_timer_event_callback( &interval, thread_pass, NULL );

  start_trema();

  return self;
}


/********************************************************************************
 * Init Controller module.
 ********************************************************************************/
void
Init_controller( void ) {
  rb_require( "trema/app" );
  VALUE cApp = rb_eval_string( "Trema::App" );
  cController = rb_define_class_under( mTrema, "Controller", cApp );

  rb_define_method( cController, "run!", controller_run, 0 );
  rb_define_method( cController, "shutdown!", controller_shutdown, 0 );
  rb_define_private_method( cController, "start_trema", controller_start_trema, 0 );

  rb_require( "trema/controller" );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

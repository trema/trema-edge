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


#include "trema.h"
#include "tasks.h"


extern VALUE mTrema;
VALUE cTasks;


static void
tasks_read( int __attribute__((unused)) fd, void *data ) {
  VALUE self = ( VALUE ) data;

  rb_funcall( self, rb_intern( "consume_tasks" ), 0);
}


static VALUE
queue_readable( VALUE self, VALUE fileno ) {
  int fd = NUM2INT( fileno );

  set_fd_handler( fd, &tasks_read, ( void * ) self, NULL, NULL );
  set_readable( fd, true );

  return self;
}

static VALUE
unqueue_readable( VALUE self, VALUE fileno ) {
  int fd = NUM2INT( fileno );

  set_readable( fd, false );
  delete_fd_handler( fd );

  return self;
}

void
Init_tasks( void ) {
  mTrema = rb_define_module( "Trema" );
  cTasks = rb_define_class_under( mTrema, "Tasks", rb_cObject );

  rb_define_private_method( cTasks, "queue_readable", queue_readable, 1 );
  rb_define_private_method( cTasks, "unqueue_readable", unqueue_readable, 1 );

  rb_require( "trema/tasks" );
}

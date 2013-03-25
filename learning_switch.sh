#!/bin/sh -
#
# Author: SUGYO Kazushi
#
# Copyright (C) 2008-2013 NEC Corporation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

TREMA_SRC=.
OBJECTS="${TREMA_SRC}/objects"

APP_NAME="learning_switch"
APP="${OBJECTS}/examples/learning_switch/learning_switch"
#APP_OPTS="--name ${APP_NAME} --daemonize"
APP_OPTS="-l debug --name ${APP_NAME} --daemonize"

SWITCH_STATE_NOTIFY="state_notify::${APP_NAME}"
SWITCH_PORT_STATUS="port_status::${APP_NAME}"
SWITCH_VENDOR="vendor::${APP_NAME}"
SWITCH_PACKET_IN="packet_in::${APP_NAME}" 
FILTER_LLDP="lldp::${APP_NAME}"
FILTER_PACKET_IN="packet_in::${APP_NAME}"

SWITCH_DAEMON="${OBJECTS}/switch_manager/switch_daemon"
#SWITCH_DAEMON_OPTS="--no-cookie-translation $SWITCH_STATE_NOTIFY $SWITCH_PORT_STATUS $SWITCH_VENDOR $SWITCH_PACKET_IN"
SWITCH_DAEMON_OPTS="-l debug --no-cookie-translation $SWITCH_STATE_NOTIFY $SWITCH_PORT_STATUS $SWITCH_VENDOR $SWITCH_PACKET_IN"
SWITCH_MANAGER="${OBJECTS}/switch_manager/switch_manager"
#SWITCH_MANAGER_OPTS="--daemonize --switch=${SWITCH_DAEMON} -- $SWITCH_DAEMON_OPTS"
SWITCH_MANAGER_OPTS="-l debug --daemonize --switch=${SWITCH_DAEMON} -- $SWITCH_DAEMON_OPTS"

TREMA_HOME="${TREMA_SRC}"

case "$1" in
	start)
		for dir in log pid sock; do
			if [ ! -d ${TREMA_HOME}/tmp/${dir} ]; then
				mkdir -p ${TREMA_HOME}/tmp/${dir}
			fi
		done
		TREMA_HOME=$TREMA_HOME $SWITCH_MANAGER $SWITCH_MANAGER_OPTS
		TREMA_HOME=$TREMA_HOME $APP $APP_OPTS
	;;
	stop)
		pidfile=${TREMA_HOME}/tmp/pid/${APP_NAME}.pid
		if [ -f $pidfile ]; then
			kill -TERM `cat $pidfile` > /dev/null 2>&1
		fi
		pidfile=${TREMA_HOME}/tmp/pid/switch_manager.pid
		if [ -f $pidfile ]; then
			kill -TERM `cat $pidfile` > /dev/null 2>&1
		fi
		for pidfile in ${TREMA_HOME}/tmp/pid/switch.*.pid; do
			if [ -f $pidfile ]; then
				kill -TERM `cat $pidfile` > /dev/null 2>&1
			fi
		done
	;;
	*)
	echo "Usage: $0 [start|stop]"
	;;
esac

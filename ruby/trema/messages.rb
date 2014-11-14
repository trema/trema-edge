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

require_relative 'message'
require_relative 'messages/hello'
require_relative 'messages/echo-request'
require_relative 'messages/echo-reply'
require_relative 'messages/features-request'
require_relative 'messages/features-reply'
require_relative 'messages/get-config-request'
require_relative 'messages/get-config-reply'
require_relative 'messages/set-config'
require_relative 'messages/flow-mod'
require_relative 'messages/packet-info'
require_relative 'messages/packet-in'
require_relative 'messages/packet-out'
require_relative 'messages/port-status'
require_relative 'messages/flow-removed'
require_relative 'messages/bucket'
require_relative 'messages/group-mod'
require_relative 'messages/error'
require_relative 'messages/port'
require_relative 'messages/barrier-request'
require_relative 'messages/barrier-reply'
require_relative 'messages/multipart-request'
require_relative 'messages/multipart-reply'
require_relative 'messages/flow-multipart-request'
require_relative 'messages/flow-multipart-reply'
require_relative 'messages/desc-multipart-request'
require_relative 'messages/desc-multipart-reply'
require_relative 'messages/aggregate-multipart-request'
require_relative 'messages/aggregate-multipart-reply'
require_relative 'messages/table-multipart-request'
require_relative 'messages/table-multipart-reply'
require_relative 'messages/port-multipart-request'
require_relative 'messages/port-multipart-reply'
require_relative 'messages/table-features-multipart-request'
require_relative 'messages/table-features-multipart-reply'
require_relative 'messages/group-multipart-request'
require_relative 'messages/group-multipart-reply'
require_relative 'messages/group-desc-multipart-request'
require_relative 'messages/group-desc-multipart-reply'
require_relative 'messages/group-features-multipart-request'
require_relative 'messages/group-features-multipart-reply'
require_relative 'messages/port-desc-multipart-request'
require_relative 'messages/port-desc-multipart-reply'
require_relative 'messages/queue-multipart-request'
require_relative 'messages/meter-multipart-request'
require_relative 'messages/meter-config-multipart-request'
require_relative 'messages/meter-features-multipart-request'
require_relative 'messages/experimenter-multipart-request'

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

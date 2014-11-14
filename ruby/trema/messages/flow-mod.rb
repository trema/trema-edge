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

module Trema
  module Messages
    class FlowMod < Message
      unsigned_int64 :cookie, :cookie_mask
      unsigned_int8 :table_id, :command
      unsigned_int16 :idle_timeout, :hard_timeout
      unsigned_int16 :priority
      unsigned_int32 :buffer_id, :out_port, :out_group
      unsigned_int16 :flags
      match :match
      array :instructions
    end
  end

  FlowMod = Messages::FlowMod
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

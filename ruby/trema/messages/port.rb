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
    class Port < Message
      unsigned_int32 :port_no, presence: true
      mac :hw_addr
      string :name
      unsigned_int32 :config, presence: true
      unsigned_int32 :state, presence: true
      unsigned_int32 :curr, presence: true
      unsigned_int32 :advertised, presence: true
      unsigned_int32 :supported, presence: true
      unsigned_int32 :peer, presence: true
      unsigned_int32 :curr_speed, presence: true
      unsigned_int32 :max_speed, presence: true
    end
  end

  Port = Messages::Port
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

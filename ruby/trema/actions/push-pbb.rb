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
  module Actions
    #
    # An action that pushes a new PBB(Provider BackBone Bridging) header onto
    # the packet. A PBB frame format consists of a supplementary MAC layer that
    # encapsulates another ethernet frame.
    #
    # @example
    #   PushPbb.new
    #
    class PushPbb < BasicAction
      #
      # The PPB ethertype is 0x88e7.
      #
      DEFAULT_ETHER_TYPE = 0x88e7

      unsigned_int16 :ether_type, presence: true, default: DEFAULT_ETHER_TYPE
    end
  end

  PushPbb = Actions::PushPbb
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

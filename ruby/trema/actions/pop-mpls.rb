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
    # An action that pops an MPLS shim header from the packet.
    # Only ethernet type 0x8847(mpls) and 0x8848(mpls-ual) should be used.
    #
    # @example
    #   PopMpls.new( 0x8847 )
    #
    # @param [Integer] ethertype
    #   the ethertype to set to.
    #
    class PopMpls < Mpls
    end
  end

  PopMpls = Actions::PopMpls
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

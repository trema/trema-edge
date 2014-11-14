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
  class Mpls < BasicAction
    #
    # 0x8847 - Multiprotocol Label Switching
    # 0x8848 - Multiprotocol Label Switching with Upstream-assigned Label
    #
    MPLS_ETHER_TAGS = [0x8847, 0x8848]

    unsigned_int16 :ether_type, presence: true, within: :check_mpls_ether_type

    def check_mpls_ether_type(ether_type, name)
      unless MPLS_ETHER_TAGS.include? ether_type
        fail ArgumentError, "Invalid #{ name } specified."
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

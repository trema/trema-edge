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
    # A field to match a 20-bit IPv6 flow label
    #
    class Ipv6FlowLabel < FlexibleAction
      ofp_type OFPXMT_OFB_IPV6_FLABEL
      unsigned_int32 :ipv6_flow_label, presence: true, alias: :ipv6_flabel
      alias_method :ipv6_flabel, :ipv6_flow_label
    end
  end

  Ipv6FlowLabel = Actions::Ipv6FlowLabel
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

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
    # A match field to match a diffserv code point. The value is restricted
    # within 0 to 63.
    #
    class IpDscp < FlexibleAction
      unsigned_int8 :ip_dscp, presence: true, within: :check_ip_dscp_range

      def check_ip_dscp_range(ip_dscp, name)
        range = 0..63
        unless range.include? ip_dscp
          fail ArgumentError, "#{ name } value must be >= #{ range.first } and <= #{ range.last }."
        end
      end
    end
  end

  IpDscp = Actions::IpDscp
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

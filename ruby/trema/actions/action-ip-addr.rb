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

require 'ipaddr'

module Trema
  module Actions
    #
    # A base class to match all IP(v4/v6) source and destination addresses
    #
    class ActionIpAddr < FlexibleAction
      ip_addr :ip_addr, presence: true, validate_with: :check_ip_addr

      def check_ip_addr(ip_addr, _name)
        unless ip_addr.is_a? IPAddr
          fail ArgumentError, 'An IP(v4/v6) address must be specified as an IPAddr object instance'
        end
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

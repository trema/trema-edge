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

require 'trema/mac'

module Trema
  module Actions
    #
    # A base class for matching source and destination MAC addresses.
    #
    class EthAddr < FlexibleAction
      mac :mac_address, presence: true, validate_with: :check_mac_address

      def check_mac_address(mac_address, _name)
        unless mac_address.is_a? Trema::Mac
          fail ArgumentError, 'A MAC address must be a Trema::Mac object instance'
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

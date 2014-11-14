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
    class Hello < Message
      unsigned_int32 :transaction_id, default: lambda { next_transaction_id }, alias: :xid
      array :version, validate_with: :check_version, default: [OFP_VERSION]

      def check_version(version, name)
        if version[0] != OFP_VERSION
          fail ArgumentError, "Invalid #{ name } specified"
        end
        if version.length > 1
          fail ArgumentError, 'Multiple versions not supported'
        end
      end
    end
  end

  Hello = Messages::Hello
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

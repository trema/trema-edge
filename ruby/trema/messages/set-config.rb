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
    class SetConfig < Message
      unsigned_int32 :transaction_id
      unsigned_int16 :flags, within: :check_flags
      unsigned_int16 :miss_send_len, presence: true

      def check_flags(flags, name)
        unless MessageConst::CONFIG_FLAGS.include? flags
          fail ArgumentError, "#{ name } must be >= #{ MessageConst::CONFIG_FLAGS.first } and <= #{ MessageConst::CONFIG_FLAGS.last }"
        end
      end
    end
  end

  SetConfig = Messages::SetConfig
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

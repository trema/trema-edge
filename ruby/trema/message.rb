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

require_relative 'accessor'

module Trema
  class Message < Accessor
    include Messages
    include MessageConst

    def self.next_transaction_id
      Messages.next_xid
    end

    def pack_msg(datapath_id)
      params = { datapath_id: datapath_id }
      instance_variables.each do | each |
        params[each.to_s.sub('@', '').to_sym] = instance_variable_get(each)
      end
      method = "pack_#{ self.class.name.demodulize.underscore }_msg"
      __send__ method, params
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

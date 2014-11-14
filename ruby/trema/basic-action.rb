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
  class BasicAction < Accessor
    include Actions

    def self.ofp_type(type)
      prefix = 'OFPAT_'
      store "#{ prefix }#{ type }", self
    end

    #
    # appends its action into a list of actions
    #
    def pack_basic_action(action)
      params = {}
      instance_variables.each do | each |
        params[each.to_s.sub('@', '').to_sym] = instance_variable_get(each)
      end
      if instance_of? Actions::SetField
        return pack_field action, params
      end
      method = "pack_#{ self.class.name.demodulize.underscore }"
      __send__ method, action, params
    end

    private

    def pack_field(set_field, params)
      options = {}
      params.each do | _k, v |
        v.each do | action |
          action.instance_variables.each do | attr |
            options[attr.to_s.sub('@', '').to_sym] = action.instance_variable_get(attr)
          end
          method = "pack_#{ action.class.name.demodulize.underscore }"
          action.__send__ method, set_field, options
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

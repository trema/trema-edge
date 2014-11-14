#
# A test example program to send a OFPT_GROUP_MOD messages.
#
# Copyright (C) 2013 NEC Corporation
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

module MessageConst
  enum_range %w( OFPMPF_REPLY_MORE )
end

module Messages
  class MultipartReply
    def more?
      (@flags & OFPMPF_REPLY_MORE) == OFPMPF_REPLY_MORE
    end
  end
end

class GroupModController < Controller
  def switch_ready(datapath_id)
    action = SendOutPort.new(
      port_number: OFPP_CONTROLLER,
      max_len: OFPCML_NO_BUFFER
    )
    bucket = Bucket.new(actions: [action])
    send_group_mod_add(
      datapath_id,
      type: OFPGT_INDIRECT,
      group_id: 200,
      buckets: [bucket]
    )

    send_group_desc_multipart_request datapath_id
  end

  def group_desc_multipart_reply(datapath_id, messages)
    info "datapath_id: #{ datapath_id.to_hex }"
    info "transaction_id: #{ messages.transaction_id.to_hex }"
    info "type: #{ messages.type }"
    info "flags: #{ messages.flags }"
    messages.parts.each do | group_desc |
      info "group_id: #{ group_desc.group_id }"
      info "  type: #{ group_desc.type }"
      group_desc.buckets.each do | bucket |
        info '  bucket:'
        info "    weight: #{ bucket.weight }"
        info "    watch_port: #{ bucket.watch_port }"
        info "    watch_group: #{ bucket.watch_group }"
        bucket.actions.each do | action |
          if action.is_a? Actions::SendOutPort
            info '    SendOutPort:'
            info "      port_number: #{ action.port_number }"
            info "      max_len: #{ action.max_len }"
          else
            info "    action: #{ action.class }"
          end
        end
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8
### indent-tabs-mode: nil
### End:

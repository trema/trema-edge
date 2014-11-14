#
# A test example program to send a OFPT_MULTIPART_REQUEST message and
# print the reply.
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

class PortDescMultipartRequestController < Controller
  def switch_ready(datapath_id)
    send_port_desc_multipart_request datapath_id
  end

  def port_desc_multipart_reply(datapath_id, messages)
    info "datapath_id: #{ datapath_id.to_hex }"
    info "transaction_id: #{ messages.transaction_id.to_hex }"
    info "type: #{ messages.type }"
    info "flags: #{ messages.flags }"
    messages.parts.first.ports.each do | port |
      info "port_no: #{ port.port_no }"
      info "  hw_addr: #{ port.hw_addr }"
      info "  name: #{ port.name }"
      info "  config: #{ port.config.to_hex }"
      info "  state: #{ port.state.to_hex }"
      info "  curr: #{ port.curr.to_hex }"
      info "  advertised: #{ port.advertised.to_hex }"
      info "  supported: #{ port.supported.to_hex }"
      info "  peer: #{ port.peer.to_hex }"
      info "  curr_speed: #{ port.curr_speed.to_hex }"
      info "  max_speed: #{ port.max_speed.to_hex }"
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8
### indent-tabs-mode: nil
### End:

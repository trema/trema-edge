#
# A simple openflow controller for benchmarking.
#
# Author: Nick Karanatsios <nickkaranatsios@gmail.com>
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

class CbenchSwitch < Controller
  def switch_ready(datapath_id)
    action = SendOutPort.new(port_number: OFPP_CONTROLLER, max_len: OFPCML_NO_BUFFER)
    ins = ApplyAction.new(actions: [action])
    send_flow_mod_add(datapath_id,
                      priority: OFP_LOW_PRIORITY,
                      buffer_id: OFP_NO_BUFFER,
                      flags: OFPFF_SEND_FLOW_REM,
                      instructions: [ins]
    )
  end

  def packet_in(datapath_id, message)
    action = SendOutPort.new(port_number: message.in_port + 1)
    ins = Instructions::ApplyAction.new(actions: [action])
    send_flow_mod_add(
      datapath_id,
      match: ExactMatch.from(message),
      buffer_id: message.buffer_id,
      instructions: [ins]
    )
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

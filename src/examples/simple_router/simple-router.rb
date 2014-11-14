#
# A router implementation in Trema
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

require_relative 'arp-table'
require_relative 'interface'
require_relative 'router-utils'
require_relative 'routing-table'
require_relative 'packet-in'

class SimpleRouter < Controller
  include RouterUtils

  def start
    load 'simple_router.conf'
    @interfaces = Interfaces.new($interface)
    @arp_table = ARPTable.new
    @routing_table = RoutingTable.new($route)
  end

  def switch_ready(datapath_id)
    set_table_miss_flow_entry(datapath_id)
  end

  def packet_in(dpid, message)
    return unless to_me?(message)

    if message.arp_request?
      handle_arp_request dpid, message
    elsif message.arp_reply?
      handle_arp_reply message
    elsif message.ipv4?
      handle_ipv4 dpid, message
    else
      # noop.
    end
  end

  private

  def to_me?(message)
    return true if message.eth_dst.broadcast?

    interface = @interfaces.find_by_port(message.in_port)
    if interface && interface.has?(message.eth_dst)
      return true
    end
  end

  def handle_arp_request(dpid, message)
    port = message.in_port
    daddr = message.arp_tpa
    interface = @interfaces.find_by_port_and_ipaddr(port, daddr)
    if interface
      arp_reply = create_arp_reply_from(message, interface.hwaddr)
      packet_out dpid, arp_reply, SendOutPort.new(port_number: interface.port)
    end
  end

  def handle_arp_reply(message)
    @arp_table.update message.in_port, message.arp_spa, message.arp_sha
  end

  def handle_ipv4(dpid, message)
    if should_forward?(message)
      forward dpid, message
    elsif message.icmpv4_echo_request?
      handle_icmpv4_echo_request dpid, message
    else
      # noop.
    end
  end

  def should_forward?(message)
    !@interfaces.find_by_ipaddr(message.ipv4_dst)
  end

  def handle_icmpv4_echo_request(dpid, message)
    interface = @interfaces.find_by_port(message.in_port)
    saddr = message.ipv4_src
    arp_entry = @arp_table.lookup(saddr)
    if arp_entry
      icmpv4_reply = create_icmpv4_reply(arp_entry, interface, message)
      packet_out dpid, icmpv4_reply, SendOutPort.new(port_number: interface.port)
    else
      handle_unresolved_packet dpid, message, interface, saddr
    end
  end

  def forward(dpid, message)
    next_hop = resolve_next_hop(message.ipv4_dst)

    interface = @interfaces.find_by_prefix(next_hop)
    if !interface || interface.port == message.in_port
      return
    end

    arp_entry = @arp_table.lookup(next_hop)
    if arp_entry
      eth_src = interface.hwaddr
      eth_dst = arp_entry.hwaddr
      instruction = create_instruction_from(eth_src, eth_dst, interface.port)
      flow_mod dpid, message, instruction
      packet_out dpid, message.data, SendOutPort.new(port_number: OFPP_TABLE)
    else
      handle_unresolved_packet dpid, message, interface, next_hop
    end
  end

  def resolve_next_hop(daddr)
    interface = @interfaces.find_by_prefix(daddr)
    if interface
      daddr
    else
      @routing_table.lookup(daddr)
    end
  end

  def flow_mod(dpid, message, instruction)
    send_flow_mod_add(
      dpid,
      match: ExactMatch.from(message),
      instructions: instruction
    )
  end

  def packet_out(dpid, packet, action)
    if packet.is_a? String
      packet = packet.unpack('C*')
    end
    message = PacketIn.new(
      datapath_id: dpid,
      buffer_id: OFP_NO_BUFFER,
      match: Match.new(in_port: OFPP_CONTROLLER),
      data: packet)
    send_packet_out(
      dpid,
      packet_in: message,
      actions: action
    )
  end

  def handle_unresolved_packet(dpid, _message, interface, ipaddr)
    arp_request = create_arp_request_from(interface, ipaddr)
    packet_out dpid, arp_request, SendOutPort.new(interface.port)
  end

  def create_instruction_from(eth_src, eth_dst, port)
    action = [
      SetField.new(action_set: [
        DecIpTtl.new,
        EthSrc.new(mac_address: eth_src),
        EthDst.new(mac_address: eth_dst)
      ]),
      SendOutPort.new(port_number: port)
    ]
    [
      Instructions::ApplyAction.new(actions: action)
    ]
  end

  def set_table_miss_flow_entry(dpid)
    action = SendOutPort.new(port_number: OFPP_CONTROLLER, max_len: OFPCML_NO_BUFFER)
    inst = Instructions::ApplyAction.new(actions: [action])
    send_flow_mod_add(
      dpid,
      priority: 0,
      instructions: [inst]
    )
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8
### indent-tabs-mode: nil
### End:

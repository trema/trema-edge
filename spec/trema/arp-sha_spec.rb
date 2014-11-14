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

require File.join(File.dirname(__FILE__), '..', 'spec_helper')
require 'timeout'
require 'trema'

describe Trema::ArpSha, 'new( VALID OPTIONS )' do
  subject { ArpSha.new(mac_address: mac) }
  let(:mac) { Mac.new('11:22:33:44:55:66') }

  describe ( :mac_address) do
    subject { super().send((:mac_address)) }
    it { is_expected.to eq(Mac.new('11:22:33:44:55:66')) }
  end
end

describe Trema::ArpSha, '.new( MANDADORY OPTION MISSING ) - mac_address' do
  subject { ArpSha.new }
  it 'should raise ArgumentError' do
    expect { subject }.to raise_error(ArgumentError, /Required option mac_address missing/)
  end
end

describe Trema::ArpSha, '.new( VALID OPTIONS )' do
  context 'when setting a flow with a match arp_sha field set' do
    it 'should match its arp_sha field when an ARP packet received' do
      network_blk = proc do
        trema_switch('lsw') { datapath_id 0xabc }
        vhost('host1') do
          ip '192.168.0.1'
          netmask '255.255.255.0'
          mac '00:00:00:00:00:01'
        end
        vhost('host2') do
          ip '192.168.0.2'
          netmask '255.255.255.0'
          mac '00:00:00:00:00:02'
        end
        link 'host1', 'lsw:1'
        link 'host2', 'lsw:2'
      end
      mc = MockController.new(network_blk)
      expect(mc).to receive(:switch_ready) do | datapath_id |
        action = SendOutPort.new(port_number: OFPP_CONTROLLER)
        apply_ins = ApplyAction.new(actions: [action])
        mac = `ifconfig trema1-0`[/([0-9|a-f]{2}:[0-9|a-f]{2}:[0-9|a-f]{2}:[0-9|a-f]{2}:[0-9|a-f]{2}:[0-9|a-f]{2})/]
        match_fields = Match.new(in_port: 1, eth_type: 2054, arp_sha: Mac.new(mac))
        mc.send_flow_mod_add(datapath_id,
                             cookie: 1111,
                             match: match_fields,
                             instructions: [apply_ins])
      end
      expect(mc).to receive(:packet_in).at_least(:once) do | _datapath_id, message |
        mac = `ifconfig trema1-0`[/([0-9|a-f]{2}:[0-9|a-f]{2}:[0-9|a-f]{2}:[0-9|a-f]{2}:[0-9|a-f]{2}:[0-9|a-f]{2})/]
        action = Trema::ArpSha.new(mac_address: Mac.new(mac))
        expect(action.mac_address.to_s).to eq(message.packet_info.arp_sha.to_s)
      end
      mc.start_receiving
      system('ping -I trema1-0 -c 1 192.168.0.1 >/dev/null 2>&1')
      mc.time_sleep(2) do
        mc.stop_receiving
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

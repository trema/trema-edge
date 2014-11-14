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

require File.join(File.dirname(__FILE__), '..', 'spec_helper')
require 'trema'

describe ActionSetVlanPcp, '.new( VALID OPTION )' do
  subject { ActionSetVlanPcp.new(vlan_pcp: 7) }

  describe '#vlan_pcp' do
    subject { super().vlan_pcp }
    it { is_expected.to eq(7) }
  end
  it 'should inspect its attributes' do
    expect(subject.inspect).to eq('#<Trema::ActionSetVlanPcp vlan_pcp=7>')
  end
end

describe ActionSetVlanPcp, '.new( MANDATORY OPTION MISSING )' do
  it 'should raise ArgumentError' do
    expect { subject }.to raise_error(ArgumentError)
  end
end

describe ActionSetVlanPcp, '.new( INVALID OPTION )' do
  context 'when value outside allowed range' do
    subject { ActionSetVlanPcp.new(vlan_pcp: 250) }
    it 'should raise RangeError' do
      expect { subject }.to raise_error(RangeError)
    end
  end

  context 'when argument type Array instead of Hash' do
    subject { ActionSetVlanPcp.new([7]) }
    it 'should raise TypeError' do
      expect { subject }.to raise_error(TypeError)
    end
  end
end

describe ActionSetVlanPcp, '.new( VALID OPTION )' do
  context 'when sending #flow_mod(add) with action set to mod_vlan_pcp' do
    it 'should respond to #append' do
      class FlowModAddController < Controller; end
      network do
        vswitch { datapath_id 0xabc }
      end.run(FlowModAddController) do
        action = ActionSetVlanPcp.new(vlan_pcp: 7)
        expect(action).to receive(:append)
        controller('FlowModAddController').send_flow_mod_add(0xabc, actions: action)
      end
    end

    it 'should have a flow with action set to mod_vlan_pcp' do
      class FlowModAddController < Controller; end
      network do
        vswitch { datapath_id 0xabc }
      end.run(FlowModAddController) do
        controller('FlowModAddController').send_flow_mod_add(0xabc, actions: ActionSetVlanPcp.new(vlan_pcp: 7))
        expect(vswitch('0xabc').size).to eq(1)
        expect(vswitch('0xabc').flows[0].actions).to match(/mod_vlan_pcp:7/)
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

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
require 'trema/ip'

describe ActionSetNwDst, '.new( VALID OPTION )' do
  subject { ActionSetNwDst.new(nw_dst: IP.new('192.168.1.1')) }

  describe '#nw_dst' do
    subject { super().nw_dst }
    it { is_expected.to be_an_instance_of Trema::IP  }
  end
  it 'should inspect its attributes' do
    expect(subject.inspect).to eq('#<Trema::ActionSetNwDst nw_dst=192.168.1.1>')
  end
  it { is_expected.to respond_to(:to_i) }
  it 'should return an Integer' do
    expect(subject.nw_dst.to_i).to eq(3_232_235_777)
  end
end

describe ActionSetNwDst, '.new( MANDATORY OPTION MISSING )' do
  it 'should raise ArgumentError' do
    expect { subject }.to raise_error(ArgumentError)
  end
end

describe ActionSetNwDst, '.new( INVALID OPTION )' do
  context 'when argument type Array instead of Hash' do
    subject { ActionSetNwDst.new([1234]) }
    it 'should raise TypeError' do
      expect { subject }.to raise_error(TypeError)
    end
  end

  context 'when nw dst not a Trema::IP object' do
    subject { ActionSetNwDst.new(nw_dst: 1234) }
    it 'should raise TypeError' do
      expect { subject }.to raise_error(TypeError, /nw dst address should be an IP object/)
    end
  end
end

describe ActionSetNwDst, '.new( VALID OPTION )' do
  context 'when sending #flow_mod(add) with action set to mod_nw_dst' do
    it 'should respond to #append' do
      class FlowModAddController < Controller; end
      network do
        vswitch { datapath_id 0xabc }
      end.run(FlowModAddController) do
        action = ActionSetNwDst.new(nw_dst: IP.new('192.168.1.1'))
        expect(action).to receive(:append)
        controller('FlowModAddController').send_flow_mod_add(0xabc, actions: action)
      end
    end

    it 'should have a flow with action set to mod_nw_dst' do
      class FlowModAddController < Controller; end
      network do
        vswitch { datapath_id 0xabc }
      end.run(FlowModAddController) do
        controller('FlowModAddController').send_flow_mod_add(0xabc, actions: ActionSetNwDst.new(nw_dst: IP.new('192.168.1.1')))
        expect(vswitch('0xabc').size).to eq(1)
        expect(vswitch('0xabc').flows[0].actions).to match(/mod_nw_dst:192.168.1.1/)
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

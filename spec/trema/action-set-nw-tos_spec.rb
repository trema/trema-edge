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

shared_examples_for 'any OpenFlow message with nw_tos option' do
  it_should_behave_like 'any OpenFlow message', option: :nw_tos, name: 'Nw tos', size: 8
end

describe ActionSetNwTos, '.new( VALID OPTION )' do
  subject { ActionSetNwTos.new(nw_tos: nw_tos) }
  let(:nw_tos) { 4 }

  describe '#nw_tos' do
    subject { super().nw_tos }
    it { is_expected.to eq(4) }
  end
  it 'should inspect its attributes' do
    expect(subject.inspect).to eq('#<Trema::ActionSetNwTos nw_tos=4>')
  end
  it_should_behave_like 'any OpenFlow message with nw_tos option'
end

describe ActionSetNwTos, '.new( MANDATORY OPTION MISSING )' do
  it 'should raise ArgumentError' do
    expect { subject }.to raise_error(ArgumentError)
  end
end

describe ActionSetNwTos, '.new( INVALID OPTION ) - argument type Array instead of Hash' do
  subject { ActionSetNwTos.new([4]) }
  it 'should raise TypeError' do
    expect { subject }.to raise_error(TypeError)
  end
end

describe ActionSetNwTos, '.new( VALID OPTION )' do
  context 'when sending #flow_mod(add) with action set to mod_nw_tos' do
    it 'should respond to #append' do
      class FlowModAddController < Controller; end
      network do
        vswitch { datapath_id 0xabc }
      end.run(FlowModAddController) do
        action = ActionSetNwTos.new(nw_tos: 4)
        expect(action).to receive(:append)
        controller('FlowModAddController').send_flow_mod_add(0xabc, actions: action)
      end
    end

    it 'should have a flow with action set to mod_nw_tos' do
      class FlowModAddController < Controller; end
      network do
        vswitch { datapath_id 0xabc }
      end.run(FlowModAddController) do
        controller('FlowModAddController').send_flow_mod_add(0xabc, actions: ActionSetNwTos.new(nw_tos: 4))
        expect(vswitch('0xabc').size).to eq(1)
        expect(vswitch('0xabc').flows[0].actions).to match(/mod_nw_tos:4/)
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

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

describe ActionSetDlSrc, '.new( VALID OPTION )' do
  subject { ActionSetDlSrc.new(dl_src: Mac.new('52:54:00:a8:ad:8c')) }

  describe ( :dl_src) do
    subject { super().send((:dl_src)) }
    it { is_expected.to be_an_instance_of(Trema::Mac) }
  end
  it 'should inspect its attributes' do
    expect(subject.inspect).to eq('#<Trema::ActionSetDlSrc dl_src=52:54:00:a8:ad:8c>')
  end
end

describe ActionSetDlSrc, '.new( MANDATORY OPTION MISSING )' do
  it 'should raise ArgumentError' do
    expect { subject }.to raise_error(ArgumentError)
  end
end

describe ActionSetDlSrc, '.new( INVALID OPTION )' do
  context 'when argument type Array instead of Hash' do
    subject { ActionSetDlSrc.new([Mac.new('52:54:00:a8:ad:8c')]) }
    it 'should raise TypeError' do
      expect { subject }.to raise_error(TypeError)
    end
  end

  context 'when dl_src not a Trema::Mac object' do
    subject { ActionSetDlSrc.new dl_src: 1234 }
    it 'should raise TypeError' do
      expect { subject }.to raise_error(TypeError, /dl src address should be a Mac object/)
    end
  end
end

describe ActionSetDlSrc, '.new( VALID OPTION )' do
  context 'when sending #flow_mod(add) with action set to mod_dl_src' do
    it 'should respond to #append' do
      class FlowModAddController < Controller; end
      network do
        vswitch { datapath_id 0xabc }
      end.run(FlowModAddController) do
        action = ActionSetDlSrc.new(dl_src: Mac.new('52:54:00:a8:ad:8c'))
        expect(action).to receive(:append)
        controller('FlowModAddController').send_flow_mod_add(0xabc, actions: action)
      end
    end

    it 'should have a flow with action set to mod_dl_src' do
      class FlowModAddController < Controller; end
      network do
        vswitch { datapath_id 0xabc }
      end.run(FlowModAddController) do
        controller('FlowModAddController').send_flow_mod_add(0xabc, actions: ActionSetDlSrc.new(dl_src: Mac.new('52:54:00:a8:ad:8c')))
        sleep 2 # FIXME: wait to send_flow_mod
        expect(vswitch('0xabc').size).to eq(1)
        expect(vswitch('0xabc').flows[0].actions).to match(/mod_dl_src:52:54:00:a8:ad:8c/)
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

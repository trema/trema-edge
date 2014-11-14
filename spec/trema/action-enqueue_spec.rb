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

shared_examples_for 'any OpenFlow message with queue id option' do
  it_should_behave_like 'any OpenFlow message', option: :queue_id, name: 'Queue id', size: 32
end

describe ActionEnqueue, 'new( VALID OPTIONS )' do
  subject { ActionEnqueue.new port: port, queue_id: queue_id  }
  let(:port) { 1 }
  let(:queue_id) { 123 }

  describe ( :port) do
    subject { super().send((:port)) }
    it { is_expected.to eq(1) }
  end

  describe ( :queue_id) do
    subject { super().send((:queue_id)) }
    it { is_expected.to eq(123) }
  end
  it 'should inspect its attributes' do
    expect(subject.inspect).to eq('#<Trema::ActionEnqueue port=1,queue_id=123>')
  end
  it_should_behave_like 'any OpenFlow message with port option'
  it_should_behave_like 'any OpenFlow message with queue id option'
end

describe ActionEnqueue, '.new( MANDADORY OPTION MISSING ) - queue id' do
  subject { ActionEnqueue.new port: 1 }
  it 'should raise ArgumentError' do
    expect { subject }.to raise_error(ArgumentError, /Queue id is a mandatory option/)
  end
end

describe ActionEnqueue, '.new( MANDATORY OPTION MISSING ) - port' do
  subject { ActionEnqueue.new queue_id: 123 }
  it 'should raise ArgumentError' do
    expect { subject }.to raise_error(ArgumentError, /Port is a mandatory option/)
  end
end

describe ActionEnqueue, '.new( MANDATORY OPTIONS MISSING ) - port, queue id' do
  it 'should raise ArgumentError' do
    expect { subject }.to raise_error(ArgumentError, /Port, queue id are mandatory options/)
  end
end

describe ActionEnqueue, '.new( VALID OPTIONS )' do
  context 'when sending #flow_mod(add) with action set to enqueue' do
    it 'should respond to #append' do
      class FlowModAddController < Controller; end
      network do
        vswitch { datapath_id 0xabc }
      end.run(FlowModAddController) do
        action = ActionEnqueue.new(port: 1, queue_id: 123)
        expect(action).to receive(:append)
        controller('FlowModAddController').send_flow_mod_add(0xabc, actions: action)
      end
    end

    it 'should have a flow with action set to enqueue' do
      class FlowModAddController < Controller; end
      network do
        vswitch { datapath_id 0xabc }
      end.run(FlowModAddController) do
        controller('FlowModAddController').send_flow_mod_add(0xabc, actions: ActionEnqueue.new(port: 1, queue_id: 123))
        sleep 2 # FIXME: wait to send_flow_mod
        expect(vswitch('0xabc').size).to eq(1)
        expect(vswitch('0xabc').flows[0].actions).to match(/enqueue:1q123/)
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

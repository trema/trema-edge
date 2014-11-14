#
# Author: Yasuhito Takamiya <yasuhito@gmail.com>
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

module Trema
  describe Controller do
    context 'when using OpenFlow constants' do
      subject { Controller.constants }

      it { is_expected.to include 'OFPP_MAX' }
      it { is_expected.to include 'OFPP_IN_PORT' }
      it { is_expected.to include 'OFPP_TABLE' }
      it { is_expected.to include 'OFPP_NORMAL' }
      it { is_expected.to include 'OFPP_FLOOD' }
      it { is_expected.to include 'OFPP_ALL' }
      it { is_expected.to include 'OFPP_CONTROLLER' }
      it { is_expected.to include 'OFPP_LOCAL' }
      it { is_expected.to include 'OFPP_NONE' }
    end

    context 'when logging' do
      subject { Controller.new }

      it { is_expected.to respond_to :critical }
      it { is_expected.to respond_to :error }
      it { is_expected.to respond_to :warn }
      it { is_expected.to respond_to :notice }
      it { is_expected.to respond_to :info }
      it { is_expected.to respond_to :debug }
    end

    context 'when sending flow_mod messages' do
      it 'should send a flow_mod_add message' do
        class FlowModAddController < Controller; end

        network do
          vswitch { datapath_id 0xabc }
        end.run(FlowModAddController) do
          controller('FlowModAddController').send_flow_mod_add(0xabc)
          expect(vswitch('0xabc').size).to eq(1)
        end
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

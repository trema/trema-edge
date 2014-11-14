#
# A test example program to send a OFPT_FEATURES_REQUEST message and print
# the reply.
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

class FeaturesRequestController < Controller
  def switch_ready(datapath_id)
    send_message datapath_id, FeaturesRequest.new
  end

  def features_reply(datapath_id, message)
    info "datapath_id: #{ datapath_id.to_hex }"
    info "transaction_id: #{ message.transaction_id.to_hex }"
    info "n_buffers: #{ message.n_buffers }"
    info "n_tables: #{ message.n_tables }"
    info "auxiliary_id: #{ message.auxiliary_id }"
    print_capabilities message.capabilities
  end

  ##############################################################################

  private

  ##############################################################################

  def print_capabilities(capabilities)
    info 'capabilities:'
    info '  OFPC_FLOW_STATS' if capabilities & OFPC_FLOW_STATS != 0
    info '  OFPC_TABLE_STATS' if capabilities & OFPC_TABLE_STATS != 0
    info '  OFPC_PORT_STATS' if capabilities & OFPC_PORT_STATS != 0
    info '  OFPC_IP_REASM' if capabilities & OFPC_IP_REASM != 0
    info '  OFPC_QUEUE_STATS' if capabilities & OFPC_QUEUE_STATS != 0
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

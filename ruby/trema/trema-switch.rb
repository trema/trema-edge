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

require_relative 'network-component'

module Trema
  class TremaSwitch < NetworkComponent
    include Trema::Daemon

    attr_accessor :datapath_id
    alias_method :dpid, :datapath_id

    def initialize(stanza)
      @stanza = stanza
      TremaSwitch.add self
    end

    #
    # Define host attribute accessors
    #
    # @example
    #   host.name  # delegated to @stanza[ :name ]
    #
    # @return an attribute value
    #
    # @api public
    #
    def method_missing(message, *_args)
      @stanza.__send__ :[], message
    end

    def command
      ports = @stanza[:ports]
      if @stanza[:ports].nil?
        ports = []
        Trema::Link.instances.values.each_with_index do | each, i |
          ports << "#{ each.name }/#{ i + 1 }" if each.peers.any? { | peer | peer.match(/\b#{ @stanza[:name] }\b/) }
        end
        ports = ports.join(',')
      end
      "sudo -E #{ Executables.switch } -i #{ dpid_short } #{ option_ports(ports) } --daemonize"
    end

    private

    def option_ports(ports)
      option = ''
      option << "-e #{ ports }" if ports.length > 0
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

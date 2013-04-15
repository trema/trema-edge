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


require "trema/network-component"


module Trema
  class TremaSwitch < NetworkComponent
    include Trema::Daemon

    attr_accessor :datapath_id
    alias :dpid :datapath_id


    log_file { | switch | "switch.#{ switch.dpid }.log" }

    
    def initialize stanza
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
    def method_missing message, *args
      @stanza.__send__ :[], message
    end


    def command
      ports = @stanza[ :ports ]
      if @stanza[ :ports ].nil?
        ports = []
        Trema::Link.instances.values.each_with_index do | each, i |
          ports << "#{ each.name }/#{ i + 1 }" if match_switch( each.peers, @stanza[ :name ] ) != []
        end
        ports = ports.join( ',' )
      end
      "export TREMA_HOME=`pwd`; sudo -E #{ Executables.switch } -i #{ dpid_short } -e #{ ports } > #{ log_file } &"
    end


    private


    def match_switch peers, name
      peers.each.select { | peer | peer.match( /\b#{ name }\b/ ) }
    end
  end
end


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:

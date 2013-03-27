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


module Trema
  #
  # IPv6 Address
  #
  class IPv6Address
    require "ipaddr"


    #
    # @return [IPAddr] value object instance of proxied IPAddr.
    #
    attr_reader :value


    #
    # Creates a {IPv6Address} instance object as a proxy to IPAddr class.
    #
    # @overload initialize(addr)
    #
    # @param [String] addr
    #   an IPv6 address specified either as a String or Number.
    #
    # @raise [ArgumentError] invalid address if supplied argument is invalid
    #   IPv6 address.
    #
    # @return [IP] self
    #   a proxy to IPAddr.
    #
    def initialize addr
      if !addr.kind_of? String
        @value = IPAddr.new( addr, Socket::AF_INET6 )
      else
        @value = IPAddr.new( addr )
      end
    end


    #
    # @return [String] the IPv6 address in its text representation.
    #
    def to_s
      @value.to_s
    end


    #
    # @return [Number] the IPv6 address in its numeric representation.
    #
    def to_i
      @value.to_i
    end


    #
    # @return [Array]
    #    an array of decimal numbers converted from IPv6 address.
    #
    def to_a
      @value.hton.unpack( "C*" )
    end
    alias :to_array :to_a


    #
    # @return [IPv6Address]
    #   Returns the IPv6 address masked with masklen.
    #
    def mask! masklen
      @value = @value.mask( masklen )
      return self
    end
    alias :prefix! :mask!

    
    #
    # @return [IPv6Address]
    #   Returns the IPv6 address masked with masklen.
    #
    def mask masklen
      self.clone.mask!( masklen )
    end
    alias :prefix :mask

    #
    # @return [bool]
    #   Returns true if the address is unspecified address (See rfc4291).
    #
    def unspecified?
      to_s == "::"
    end


    #
    # @return [bool]
    #   Returns true if the address is loopback address (See rfc 4291).
    #
    def loopback?
      to_s == "::1"
    end

    
    #
    # @return [bool]
    #   Returns true if the address is multicast address (See rfc4291).
    #
    def multicast?
      mask( 8 ).to_s == "ff00::"
    end
      

    #
    # @return [bool]
    #   Returns true if the address is link-local unicast address (See rfc4291).
    #
    def link_local_unicast?
      mask( 10 ).to_s == "fe80::"
    end

    
    #
    # @return [bool]
    #   Returns true if the address is global unicast address (See rfc4291).
    # 
    def global_unicast?
      not ( unspecified? or loopback? or multicast? or link_local_unicast? )
    end

    
    #
    # @return [bool]
    #   Returns true if the address is unicast address.
    #
    def unicast?
      link_local_unicast? or global_unicast?
    end
  end
end


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
